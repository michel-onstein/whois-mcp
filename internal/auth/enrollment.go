package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Enrollment secret sizing and hashing parameters.
//
// The token is 256 bits because it is the only real security boundary in a
// single-tenant deployment (design §5.8): anyone holding it can mint a session
// with any scope. The Argon2id parameters are the interactive-use profile from
// the RFC 9106 recommendations — deliberately not the minimum, because this hash
// is computed at most once per enrollment attempt and the attacker's cost is the
// entire point.
const (
	// EnrollmentTokenBytes is the entropy an operator-generated token should
	// carry. Shorter tokens are accepted (an operator may have inherited one)
	// but warned about, because refusing to start on a short secret would be a
	// worse failure than running with one.
	EnrollmentTokenBytes = 32

	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
)

// Lockout policy for the authorize endpoint (design §5.7).
const (
	// LockoutThreshold is how many consecutive failures from one source trip
	// the lockout.
	LockoutThreshold = 5
	// LockoutBase is the first lockout duration; it doubles per subsequent
	// failure, so a determined guesser is quickly spending hours per attempt
	// while a human who fat-fingered a paste waits seconds.
	LockoutBase = 2 * time.Second
	// LockoutMax caps the backoff. Unbounded doubling would eventually lock a
	// legitimate operator out for years after a bad week.
	LockoutMax = 15 * time.Minute
	// AttemptWindow is how long failures are remembered. A slow guesser must
	// not be able to reset their budget merely by being patient, but a
	// legitimate operator's mistake from yesterday should not count today.
	AttemptWindow = time.Hour
)

var (
	// ErrWrongSecret means the presented token did not match.
	ErrWrongSecret = errors.New("enrollment token is not correct")
	// ErrLockedOut means this source must wait before trying again.
	ErrLockedOut = errors.New("too many failed enrollment attempts")
)

// Enrollment verifies the operator's fixed enrollment secret.
//
// The plaintext secret is never retained: only its Argon2id hash and salt live
// in memory, so a heap dump or a core file does not hand over the one credential
// that matters. Comparison is constant time.
type Enrollment struct {
	salt []byte
	hash []byte
	log  *slog.Logger

	mu      sync.Mutex
	sources map[string]*attemptState
	now     func() time.Time
}

type attemptState struct {
	failures   int
	lastFail   time.Time
	lockedThru time.Time
}

// NewEnrollment hashes the secret and returns a verifier.
//
// It returns an error on an empty secret rather than accepting one, because an
// empty enrollment token means every caller is authorized, and a server that
// starts in that state is worse than a server that refuses to start.
func NewEnrollment(secret string, log *slog.Logger) (*Enrollment, error) {
	s := strings.TrimSpace(secret)
	if s == "" {
		return nil, errors.New("enrollment token is empty; set WHOIS_MCP_ENROLLMENT_TOKEN")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating enrollment salt: %w", err)
	}
	e := &Enrollment{
		salt:    salt,
		hash:    argon2.IDKey([]byte(s), salt, argonTime, argonMemory, argonThreads, argonKeyLen),
		log:     log,
		sources: make(map[string]*attemptState),
		now:     time.Now,
	}
	if len(s) < 32 {
		// Warned rather than refused: an operator with a short inherited token
		// should be told, not blocked from starting.
		log.Warn("enrollment token is shorter than recommended",
			"length", len(s), "recommended_bytes", EnrollmentTokenBytes)
	}
	return e, nil
}

// GenerateEnrollmentToken returns a fresh operator token, for `--generate-token`
// and for documentation that should not invite people to invent their own.
func GenerateEnrollmentToken() (string, error) {
	return randomID(EnrollmentTokenBytes)
}

// Verify checks a presented token from a source, applying the lockout policy.
//
// source is an opaque per-client key — the caller passes a client IP. It is
// hashed before use as a map key so the in-memory state does not hold a list of
// addresses that tried to enroll.
func (e *Enrollment) Verify(source, presented string) error {
	key := hashSource(source)

	e.mu.Lock()
	now := e.now()
	st := e.sources[key]
	if st == nil {
		st = &attemptState{}
		e.sources[key] = st
	}
	// Forget stale failures so yesterday's typo does not count today.
	if !st.lastFail.IsZero() && now.Sub(st.lastFail) > AttemptWindow {
		st.failures = 0
		st.lockedThru = time.Time{}
	}
	if now.Before(st.lockedThru) {
		wait := st.lockedThru.Sub(now)
		e.mu.Unlock()
		// Audit every attempt, successful or not, and never the token itself.
		e.log.Warn("enrollment attempt while locked out",
			"source", redactSource(source), "retry_after", wait.String())
		return fmt.Errorf("%w: retry in %s", ErrLockedOut, wait.Round(time.Second))
	}
	e.mu.Unlock()

	// Argon2id over the presented value, then a constant-time comparison of the
	// digests. Comparing digests rather than plaintexts is what keeps the
	// timing independent of how many leading characters an attacker guessed.
	got := argon2.IDKey([]byte(strings.TrimSpace(presented)), e.salt,
		argonTime, argonMemory, argonThreads, argonKeyLen)
	ok := subtle.ConstantTimeCompare(got, e.hash) == 1

	e.mu.Lock()
	defer e.mu.Unlock()
	if ok {
		st.failures = 0
		st.lockedThru = time.Time{}
		e.log.Info("enrollment succeeded", "source", redactSource(source))
		return nil
	}

	st.failures++
	st.lastFail = now
	if st.failures >= LockoutThreshold {
		backoff := LockoutBase << min(st.failures-LockoutThreshold, 20)
		if backoff > LockoutMax || backoff <= 0 {
			backoff = LockoutMax
		}
		st.lockedThru = now.Add(backoff)
		e.log.Warn("enrollment locked out after repeated failures",
			"source", redactSource(source), "failures", st.failures, "locked_for", backoff.String())
	} else {
		e.log.Warn("enrollment attempt failed",
			"source", redactSource(source), "failures", st.failures)
	}
	return ErrWrongSecret
}

// hashSource keys lockout state without retaining the address itself.
func hashSource(source string) string {
	sum := sha256.Sum256([]byte(source))
	return b64(sum[:8])
}

// redactSource renders an address for the audit log with the host truncated.
//
// The full client address is not what the audit trail needs — "someone on this
// /24 failed five times" answers the operational question — and logging exact
// addresses of failed attempts turns the log into a record of who probed us.
func redactSource(source string) string {
	host := source
	if h, _, err := net.SplitHostPort(source); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// SourceFromRequest picks the client address for lockout purposes.
//
// It uses the transport peer address and deliberately ignores X-Forwarded-For:
// that header is client-supplied, so trusting it would let an attacker reset
// their own lockout budget on every request by varying it. A deployment behind
// a proxy should terminate at an ingress that sets the peer address correctly,
// which is what the M4 chart does.
func SourceFromRequest(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	return r.RemoteAddr
}
