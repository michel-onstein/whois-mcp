// Package ratelimit is the per-upstream politeness policy: token buckets,
// Retry-After handling, backoff, and a circuit breaker.
//
// The reason this package is careful rather than merely functional is in design
// §9: there is no agreement with any registry. We query them as an anonymous
// client with no negotiated quota and no contractual protection, so every limit
// here is set to be defensibly polite. A registry that blocks us produces what
// looks to users like a total outage for that TLD, and the block outlasts
// whatever burst caused it.
//
// Everything is keyed by upstream host rather than by TLD, because the host is
// what enforces a quota: several TLDs share whois.verisign-grs.com, and treating
// them separately would let three "polite" streams add up to one impolite one.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Defaults chosen to be unremarkable to a registry watching its logs.
const (
	// DefaultRate is sustained requests per second per upstream host.
	DefaultRate = 2.0
	// DefaultBurst allows a small clump — an agent checking a handful of names
	// should not be serialised to a metronome — without looking like a scrape.
	DefaultBurst = 5
	// MaxWait bounds how long a caller will block for a token before being told
	// to give up. Beyond this the honest answer is "unknown, try later" rather
	// than a request that outlives the client's patience.
	MaxWait = 5 * time.Second
)

// ErrWouldExceedDeadline means a token will not arrive in time.
var ErrWouldExceedDeadline = errors.New("rate limit: token would not arrive before the deadline")

// ErrThrottled means the upstream told us to back off and the pause is not over.
type ErrThrottled struct {
	Host  string
	Until time.Time
}

func (e *ErrThrottled) Error() string {
	return fmt.Sprintf("rate limit: %s asked us to back off until %s",
		e.Host, e.Until.UTC().Format(time.RFC3339))
}

// RetryAfter is how long the caller should wait.
func (e *ErrThrottled) RetryAfter(now time.Time) time.Duration {
	d := e.Until.Sub(now)
	if d < 0 {
		return 0
	}
	return d
}

// Limiter holds one token bucket per upstream host, plus any explicit pause a
// host has asked for.
type Limiter struct {
	rate  float64
	burst int
	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	pauses  map[string]time.Time
	// failures counts consecutive failures per host, for Backoff.
	failures map[string]int
}

// Options tunes a Limiter.
type Options struct {
	// Rate is sustained requests per second per host. Zero uses DefaultRate.
	Rate float64
	// Burst is the bucket size. Zero uses DefaultBurst.
	Burst int
}

// New returns a Limiter.
func New(opt Options) *Limiter {
	r := opt.Rate
	if r <= 0 {
		r = DefaultRate
	}
	b := opt.Burst
	if b <= 0 {
		b = DefaultBurst
	}
	return &Limiter{
		rate: r, burst: b,
		now:      time.Now,
		sleep:    sleepCtx,
		buckets:  make(map[string]*rate.Limiter),
		pauses:   make(map[string]time.Time),
		failures: make(map[string]int),
	}
}

// Acquire waits for permission to call host.
//
// It returns ErrThrottled while an explicit Retry-After pause is in effect,
// because a pause the upstream asked for is not something to wait out silently:
// the caller should report "try later" rather than hold a request open.
func (l *Limiter) Acquire(ctx context.Context, host string) error {
	key := HostKey(host)

	l.mu.Lock()
	if until, ok := l.pauses[key]; ok {
		if l.now().Before(until) {
			l.mu.Unlock()
			return &ErrThrottled{Host: key, Until: until}
		}
		delete(l.pauses, key)
	}
	bucket, ok := l.buckets[key]
	if !ok {
		bucket = rate.NewLimiter(rate.Limit(l.rate), l.burst)
		l.buckets[key] = bucket
	}
	l.mu.Unlock()

	res := bucket.Reserve()
	if !res.OK() {
		return fmt.Errorf("rate limit: %s cannot admit any request", key)
	}
	delay := res.Delay()
	if delay == 0 {
		return nil
	}
	if delay > MaxWait {
		res.Cancel()
		return fmt.Errorf("%w: %s needs %s", ErrWouldExceedDeadline, key, delay.Round(time.Millisecond))
	}
	if dl, ok := ctx.Deadline(); ok && l.now().Add(delay).After(dl) {
		res.Cancel()
		return fmt.Errorf("%w: %s needs %s", ErrWouldExceedDeadline, key, delay.Round(time.Millisecond))
	}
	if err := l.sleep(ctx, delay); err != nil {
		res.Cancel()
		return err
	}
	return nil
}

// Observe records the outcome of a call so backoff and pauses stay current.
//
// status is the HTTP status where there is one, or 0 for a transport-level
// failure or a port-43 exchange. retryAfter is the header value if present.
//
// Only 429 and 5xx set a pause, which is design §9's wording and also the right
// division of labour: those are the upstream *telling us* it is overloaded, and
// backing off is the response. A pure transport failure — connection refused,
// no route — is the circuit breaker's domain, and pausing on it too would mean
// the breaker never accumulates its threshold, because every call after the
// first would be refused by the limiter before it reached the upstream. Two
// mechanisms that mask each other are worse than either alone.
func (l *Limiter) Observe(host string, status int, retryAfter string) {
	key := HostKey(host)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	failed := status == http.StatusTooManyRequests || status >= 500 || status == 0
	if !failed {
		l.failures[key] = 0
		delete(l.pauses, key)
		return
	}

	l.failures[key]++
	if status == 0 {
		// Transport failure: count it so a later 5xx backs off from a realistic
		// base, but leave the fast-fail decision to the breaker.
		return
	}
	// Honour Retry-After exactly when the upstream gave one. Guessing shorter is
	// how a polite client becomes an impolite one.
	if d, ok := ParseRetryAfter(retryAfter, now); ok {
		l.pauses[key] = now.Add(d)
		return
	}
	// No hint: back off on our own schedule.
	l.pauses[key] = now.Add(Backoff(l.failures[key]))
}

// Failures reports the consecutive failure count for a host.
func (l *Limiter) Failures(host string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failures[HostKey(host)]
}

// PausedUntil reports any active pause for a host.
func (l *Limiter) PausedUntil(host string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.pauses[HostKey(host)]
	if !ok || !l.now().Before(until) {
		return time.Time{}, false
	}
	return until, true
}

// Backoff base and ceiling for our own retry schedule.
const (
	backoffBase = 500 * time.Millisecond
	backoffMax  = 60 * time.Second
)

// Backoff returns an exponentially increasing delay with full jitter.
//
// Full jitter — a uniform draw from [0, computed) rather than the computed value
// — matters more than the exponential part. Without it, every replica that saw
// the same registry fail retries at the same instant, which is a synchronised
// burst aimed at a service that just told us it was struggling.
func Backoff(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := min(failures-1, 20)
	d := backoffBase << shift
	if d > backoffMax || d <= 0 {
		d = backoffMax
	}
	return time.Duration(rand.Int64N(int64(d)) + 1)
}

// ParseRetryAfter reads an HTTP Retry-After value in either permitted form:
// delta-seconds, or an HTTP-date.
//
// A past or unparseable date yields false rather than zero, so a caller can
// tell "no instruction" from "wait no time at all".
func ParseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(s); err == nil {
		if secs < 0 {
			return 0, false
		}
		return capPause(time.Duration(secs) * time.Second), true
	}
	if t, err := http.ParseTime(s); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			// The instant has passed; treat it as "no pause needed" rather than
			// as no instruction, since the upstream did answer.
			return 0, true
		}
		return capPause(d), true
	}
	return 0, false
}

// maxPause bounds how long we will honour. A registry asking for a day is
// asking us to stop serving that TLD entirely; the cap keeps a
// misconfigured header from doing that, while still being far longer than any
// legitimate throttle.
const maxPause = 15 * time.Minute

func capPause(d time.Duration) time.Duration {
	if d > maxPause {
		return maxPause
	}
	if d < 0 {
		return 0
	}
	return d
}

// defaultPorts are the ports that carry no information: an upstream reached on
// one of these is the same service as the same host named without a port.
var defaultPorts = map[string]bool{"43": true, "443": true, "80": true}

// HostKey normalizes an upstream identifier to the thing that enforces the
// quota: lowercase, no scheme, no path, and no *default* port.
//
// Several TLDs share one WHOIS or RDAP host, and keying by anything narrower
// would let three separately-polite streams add up to one impolite one. That is
// why the default port is dropped — the WHOIS transport always appends :43 while
// IANA discovery returns a bare hostname, and treating those as two upstreams
// would split one registry's budget in half.
//
// A non-default port is kept, because then it is load-bearing: two services on
// one host reached on different ports are two services, and merging them would
// make one of them responsible for the other's failures. In production this
// almost never fires; it matters for anything reached on an unusual port, and it
// is what keeps separate fakes separate under test.
func HostKey(hostOrURL string) string {
	s := strings.TrimSpace(strings.ToLower(hostOrURL))
	if s == "" {
		return "unknown"
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}

	host, port := s, ""
	if strings.HasPrefix(s, "[") {
		// Bracketed IPv6 literal, optionally with a port after the bracket.
		if i := strings.Index(s, "]"); i >= 0 {
			host = s[:i+1]
			if len(s) > i+1 && s[i+1] == ':' {
				port = s[i+2:]
			}
		}
	} else if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], ":") {
		host, port = s[:i], s[i+1:]
	}
	host = strings.TrimSuffix(host, ".")

	if port == "" || defaultPorts[port] {
		return host
	}
	return host + ":" + port
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
