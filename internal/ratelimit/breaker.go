package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Circuit breaker tuning.
const (
	// BreakerThreshold is consecutive failures before the circuit opens.
	BreakerThreshold = 5
	// BreakerCooldown is how long it stays open before allowing a probe.
	BreakerCooldown = 30 * time.Second
	// BreakerHalfOpenProbes is how many successes in half-open close it again.
	// More than one because a single lucky response from a flapping registry is
	// not evidence of recovery.
	BreakerHalfOpenProbes = 2
)

// ErrCircuitOpen means the upstream is being given a rest.
type ErrCircuitOpen struct {
	Host  string
	Until time.Time
}

func (e *ErrCircuitOpen) Error() string {
	return fmt.Sprintf("circuit breaker: %s is failing; not retrying until %s",
		e.Host, e.Until.UTC().Format(time.RFC3339))
}

// IsOpen reports whether an error is a breaker rejection.
func IsOpen(err error) bool {
	var e *ErrCircuitOpen
	return errors.As(err, &e)
}

// State is a breaker's position.
type State string

const (
	// Closed is normal operation.
	Closed State = "closed"
	// Open means requests are refused without being attempted.
	Open State = "open"
	// HalfOpen means one probe at a time is allowed through.
	HalfOpen State = "half-open"
)

// Breaker stops us hammering an upstream that is already failing.
//
// The reason this exists alongside the rate limiter is concurrency budget, not
// politeness: a registry that has stopped answering will hold every request
// against it open until the deadline, and with a shared upstream concurrency
// limit that means one dead registry starves every other TLD. Failing fast for
// a dead host is what keeps .com working while .example is down.
type Breaker struct {
	threshold int
	cooldown  time.Duration
	probes    int
	now       func() time.Time

	mu    sync.Mutex
	hosts map[string]*breakerState
}

type breakerState struct {
	state     State
	failures  int
	successes int
	openUntil time.Time
	// inFlightProbe ensures half-open admits one request at a time; without it
	// a burst of waiting callers all probe at once and the "one probe" rule is
	// no rule at all.
	inFlightProbe bool
}

// BreakerOptions tunes a Breaker.
type BreakerOptions struct {
	Threshold int
	Cooldown  time.Duration
	Probes    int
}

// NewBreaker returns a Breaker.
func NewBreaker(opt BreakerOptions) *Breaker {
	b := &Breaker{
		threshold: opt.Threshold,
		cooldown:  opt.Cooldown,
		probes:    opt.Probes,
		now:       time.Now,
		hosts:     make(map[string]*breakerState),
	}
	if b.threshold <= 0 {
		b.threshold = BreakerThreshold
	}
	if b.cooldown <= 0 {
		b.cooldown = BreakerCooldown
	}
	if b.probes <= 0 {
		b.probes = BreakerHalfOpenProbes
	}
	return b
}

// Allow reports whether a call to host may proceed.
//
// The returned release function must be called with the outcome. A caller that
// forgets it leaves a half-open breaker holding its probe slot, so the signature
// is deliberately awkward to ignore.
func (b *Breaker) Allow(host string) (release func(success bool), err error) {
	key := HostKey(host)
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.hosts[key]
	if !ok {
		st = &breakerState{state: Closed}
		b.hosts[key] = st
	}

	switch st.state {
	case Open:
		if now.Before(st.openUntil) {
			return nil, &ErrCircuitOpen{Host: key, Until: st.openUntil}
		}
		// Cooldown elapsed: try one probe.
		st.state = HalfOpen
		st.successes = 0
		st.inFlightProbe = true
		return b.releaser(key), nil

	case HalfOpen:
		if st.inFlightProbe {
			return nil, &ErrCircuitOpen{Host: key, Until: now.Add(b.cooldown)}
		}
		st.inFlightProbe = true
		return b.releaser(key), nil

	default: // Closed
		return b.releaser(key), nil
	}
}

func (b *Breaker) releaser(key string) func(bool) {
	var once sync.Once
	return func(success bool) {
		once.Do(func() { b.record(key, success) })
	}
}

func (b *Breaker) record(key string, success bool) {
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.hosts[key]
	if !ok {
		return
	}
	st.inFlightProbe = false

	if success {
		st.failures = 0
		switch st.state {
		case HalfOpen:
			st.successes++
			if st.successes >= b.probes {
				st.state = Closed
				st.successes = 0
			}
		default:
			st.state = Closed
		}
		return
	}

	st.failures++
	st.successes = 0
	// A failed probe re-opens immediately rather than needing another
	// threshold's worth of failures: half-open already established doubt.
	if st.state == HalfOpen || st.failures >= b.threshold {
		st.state = Open
		st.openUntil = now.Add(b.cooldown)
	}
}

// State reports a host's current position, for metrics and tld_info.
func (b *Breaker) State(host string) State {
	key := HostKey(host)
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.hosts[key]
	if !ok {
		return Closed
	}
	// Report half-open once the cooldown has elapsed, so a reader is not told
	// "open" about a host the next call would actually try.
	if st.state == Open && !b.now().Before(st.openUntil) {
		return HalfOpen
	}
	return st.state
}

// OpenHosts lists every host currently refusing traffic, for the metrics
// endpoint and for an operator asking "what is broken right now".
func (b *Breaker) OpenHosts() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	now := b.now()
	for host, st := range b.hosts {
		if st.state == Open && now.Before(st.openUntil) {
			out = append(out, host)
		}
	}
	return out
}
