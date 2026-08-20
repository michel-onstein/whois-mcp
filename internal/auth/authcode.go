package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuthCodeTTL is how long an authorization code is valid.
//
// One minute, because a code is exchanged immediately by a client that is
// already waiting for it. A longer window buys nothing and widens the period in
// which a code intercepted from a redirect URL is still usable.
const AuthCodeTTL = time.Minute

var (
	// ErrCodeUnknown covers a code that was never issued, already spent, or
	// expired. The three are deliberately one error at the protocol boundary:
	// telling a client which of them applies helps an attacker probing codes.
	ErrCodeUnknown = errors.New("authorization code is not valid")
	// ErrPKCEFailed means the verifier did not match the challenge.
	ErrPKCEFailed = errors.New("PKCE verifier does not match the challenge")
	// ErrRedirectMismatch means the exchange named a different redirect_uri
	// than the authorization did.
	ErrRedirectMismatch = errors.New("redirect_uri does not match the authorization request")
)

// Code is one issued authorization code.
type Code struct {
	Code        string
	SessionID   string
	Label       string
	Scopes      []string
	ClientID    string
	RedirectURI string
	// Challenge is the PKCE S256 challenge captured at authorization time.
	Challenge string
	// Resource is the RFC 8707 resource indicator the client asked for. It is
	// recorded so the token endpoint can refuse to mint for a resource the
	// client did not request.
	Resource  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// CodeStore holds authorization codes between the authorize redirect and the
// token exchange.
//
// Codes are single-use: Consume deletes before returning, so two concurrent
// exchanges of one code produce one success. An attacker who intercepts a code
// from a redirect URL therefore races the legitimate client rather than being
// able to use it at leisure — and loses, because the legitimate client is
// already waiting.
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]*Code
	now   func() time.Time
}

// NewCodeStore returns an empty store.
func NewCodeStore() *CodeStore {
	return &CodeStore{codes: make(map[string]*Code), now: time.Now}
}

// Issue records a code and returns it.
func (s *CodeStore) Issue(c *Code) (string, error) {
	code, err := randomID(32)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	c.Code = code
	c.IssuedAt = now
	c.ExpiresAt = now.Add(AuthCodeTTL)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = c
	s.sweepLocked(now)
	return code, nil
}

// Consume validates and spends a code.
//
// Every binding established at authorization time is re-checked here: the PKCE
// challenge, the redirect URI, and the client. Skipping any of them turns the
// code into a bearer credential that anyone who observes it can redeem.
func (s *CodeStore) Consume(code, verifier, redirectURI, clientID string) (*Code, error) {
	s.mu.Lock()
	c, ok := s.codes[code]
	if ok {
		delete(s.codes, code) // single use, whatever happens next
	}
	now := s.now().UTC()
	s.mu.Unlock()

	if !ok {
		return nil, ErrCodeUnknown
	}
	if now.After(c.ExpiresAt) {
		return nil, fmt.Errorf("%w: expired", ErrCodeUnknown)
	}
	if c.ClientID != "" && clientID != "" && c.ClientID != clientID {
		return nil, fmt.Errorf("%w: issued to a different client", ErrCodeUnknown)
	}
	// RFC 6749 §4.1.3: if a redirect_uri was used in the authorization request,
	// the token request must present the identical value.
	if c.RedirectURI != "" && c.RedirectURI != redirectURI {
		return nil, ErrRedirectMismatch
	}
	if !VerifyPKCE(c.Challenge, verifier) {
		return nil, ErrPKCEFailed
	}
	return c, nil
}

// sweepLocked drops expired codes so the map cannot grow without bound from
// authorizations nobody completed.
func (s *CodeStore) sweepLocked(now time.Time) {
	for k, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, k)
		}
	}
}

// VerifyPKCE checks an S256 code verifier against its challenge.
//
// Only S256 is accepted. OAuth 2.1 removed the "plain" method, and accepting it
// would defeat the point: a plain challenge is the verifier, so anyone who sees
// the authorization request can complete the exchange.
func VerifyPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	// RFC 7636 §4.1: 43-128 characters from the unreserved set.
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// ValidateRedirectURI decides whether a client-supplied redirect target is
// acceptable.
//
// This is the open-redirect boundary. Without registered clients there is no
// allowlist to check against, so the rule is structural, following RFC 8252 for
// native apps: loopback HTTP (what MCP clients on a desktop use), HTTPS, and
// private-use schemes containing a dot (the reverse-DNS form). Everything else
// — plain http to a non-loopback host, javascript:, data:, scheme-relative — is
// refused, because the authorization code travels in that URL.
func ValidateRedirectURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("redirect_uri is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri is not a URI: %w", err)
	}
	if u.Fragment != "" {
		// RFC 6749 §3.1.2: the endpoint URI must not include a fragment.
		return errors.New("redirect_uri must not contain a fragment")
	}
	switch scheme := strings.ToLower(u.Scheme); scheme {
	case "https":
		if u.Host == "" {
			return errors.New("https redirect_uri has no host")
		}
		return nil
	case "http":
		host := u.Hostname()
		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			return nil
		}
		return errors.New("http redirect_uri is only allowed for loopback")
	case "":
		return errors.New("redirect_uri must be absolute")
	case "javascript", "data", "vbscript", "file":
		return fmt.Errorf("redirect_uri scheme %q is not allowed", scheme)
	default:
		// Private-use URI scheme (RFC 8252 §7.1): must be reverse-DNS-ish, so
		// a bare custom word cannot be claimed by any app on the machine.
		if strings.Contains(scheme, ".") {
			return nil
		}
		return fmt.Errorf("redirect_uri scheme %q is not a private-use scheme", scheme)
	}
}
