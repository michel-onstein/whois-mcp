package ratelimit

import (
	"context"
	"net/http"
)

// Outcome is what a guarded call reports back.
type Outcome struct {
	// Status is the HTTP status, or 0 for a port-43 exchange or a transport
	// failure. It drives both the pause and the breaker.
	Status int
	// RetryAfter is the header value, if the upstream sent one.
	RetryAfter string
	// Err is the call's error, if any.
	Err error
}

// Guard is the whole upstream policy behind one call: rate limit, circuit
// breaker, and outcome recording.
//
// It exists so the transports have exactly one thing to remember. Rate limiting
// and breaking are separate concerns with separate reasons — politeness and
// concurrency budget — but a transport that had to interleave both by hand would
// eventually get the ordering or the release wrong, and both failures are
// invisible until a registry blocks us.
type Guard struct {
	lim *Limiter
	br  *Breaker
}

// NewGuard combines a limiter and a breaker. Either may be nil, in which case
// that policy is simply not applied — useful in tests, and honest about the
// fact that a nil breaker means no breaking rather than no calls.
func NewGuard(lim *Limiter, br *Breaker) *Guard {
	return &Guard{lim: lim, br: br}
}

// Do runs fn under the policy for host.
//
// The breaker is consulted before the rate limiter deliberately: if a host is
// already known to be failing, waiting for a token to call it anyway wastes both
// the token and the caller's deadline.
func (g *Guard) Do(ctx context.Context, host string, fn func(context.Context) Outcome) error {
	if g == nil {
		out := fn(ctx)
		return out.Err
	}

	release := func(bool) {}
	if g.br != nil {
		rel, err := g.br.Allow(host)
		if err != nil {
			return err
		}
		release = rel
	}

	if g.lim != nil {
		if err := g.lim.Acquire(ctx, host); err != nil {
			// Not the upstream's fault: a throttle or a deadline is our own
			// policy talking, so it must not count against the breaker.
			release(true)
			return err
		}
	}

	out := fn(ctx)

	if g.lim != nil {
		g.lim.Observe(host, out.Status, out.RetryAfter)
	}
	release(healthy(out))
	return out.Err
}

// healthy decides whether an outcome counts as the upstream working.
//
// A 404 is a successful conversation with a working registry — the domain does
// not exist — so counting it as a failure would open the breaker on a host that
// is answering perfectly. Only transport failures and 5xx/429 count against it.
func healthy(out Outcome) bool {
	switch {
	case out.Status == 0 && out.Err != nil:
		return false
	case out.Status == http.StatusTooManyRequests:
		return false
	case out.Status >= 500:
		return false
	default:
		return true
	}
}

// State reports a host's breaker position, for metrics.
func (g *Guard) State(host string) State {
	if g == nil || g.br == nil {
		return Closed
	}
	return g.br.State(host)
}

// OpenHosts lists hosts currently refusing traffic.
func (g *Guard) OpenHosts() []string {
	if g == nil || g.br == nil {
		return nil
	}
	return g.br.OpenHosts()
}

// Limiter exposes the limiter for metrics.
func (g *Guard) Limiter() *Limiter {
	if g == nil {
		return nil
	}
	return g.lim
}
