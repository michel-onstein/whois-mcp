package resolve

import (
	"time"

	"github.com/qjam/whois-mcp/internal/normalize"
)

// TTLPolicy is the cache lifetime table from design §9, as data.
//
// It is a table rather than a switch because the numbers encode a judgement
// that has to be reviewable at a glance: how long each *kind* of answer stays
// true. Registration data changes slowly; availability is the volatile case;
// an ambiguous answer must not be cemented, or one throttled minute turns into
// an hour of confidently wrong "unknown".
//
// Cache hit rate is a primary operational metric rather than a nicety (§9): it
// is the main lever keeping our query volume off registry radar, so these
// numbers are the difference between being a well-behaved client and being
// blocked.
type TTLPolicy struct {
	Registered   time.Duration
	Unregistered time.Duration
	Unknown      time.Duration
	Raw          time.Duration
	// Bootstrap covers the IANA RDAP map and the WHOIS host map, which IANA
	// publishes daily — so a day-old answer is the freshest that exists.
	Bootstrap time.Duration
}

// DefaultTTLPolicy is design §9's table.
var DefaultTTLPolicy = TTLPolicy{
	Registered:   time.Hour,
	Unregistered: 5 * time.Minute,
	Unknown:      time.Minute,
	Raw:          15 * time.Minute,
	Bootstrap:    24 * time.Hour,
}

// For returns the TTL appropriate to an answer's certainty.
func (p TTLPolicy) For(state normalize.Tristate) time.Duration {
	switch state {
	case normalize.Yes:
		return p.Registered
	case normalize.No:
		return p.Unregistered
	default:
		return p.Unknown
	}
}

// Valid reports whether a policy is usable.
//
// A zero or negative TTL is refused rather than silently treated as "do not
// cache": with the cache disabled, every lookup reaches a registry, which is
// exactly the behaviour that gets an anonymous client blocked.
func (p TTLPolicy) Valid() bool {
	return p.Registered > 0 && p.Unregistered > 0 && p.Unknown > 0 &&
		p.Raw > 0 && p.Bootstrap > 0
}

// Ordered reports whether the policy keeps the relationship the design
// requires: a certain answer may be cached longer than a volatile one, and an
// ambiguous one shortest of all.
//
// This is worth asserting because the failure is silent. A policy that cached
// "unknown" for an hour would pin a transient rate-limit as the answer for that
// domain, and nothing in the system would complain.
func (p TTLPolicy) Ordered() bool {
	return p.Registered >= p.Unregistered && p.Unregistered >= p.Unknown
}
