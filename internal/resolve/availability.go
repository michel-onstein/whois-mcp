package resolve

import (
	"context"
	"sync"
	"time"

	"github.com/qjam/whois-mcp/internal/normalize"
)

// MaxBatch caps a single availability request. The limit exists to protect the
// registries, not us: fifty names is already fifty queries to someone we have
// no agreement with, and an uncapped batch is how a well-meaning agent gets our
// egress IP blocked for a TLD.
const MaxBatch = 50

// AvailabilityTimeout is the per-domain ceiling on the cheap path. Tighter than
// a full lookup (design §6.1) because this answer is worth having quickly or
// not at all — an agent screening candidate names would rather hear "unknown"
// than wait.
const AvailabilityTimeout = 4 * time.Second

// availabilityConcurrency bounds parallel upstream queries within one batch.
//
// Deliberately modest. M3 adds real per-upstream token buckets; until then this
// is the only thing standing between a fifty-name batch and fifty simultaneous
// connections to the same registry, which is exactly the behaviour that earns
// a rate-limit block.
const availabilityConcurrency = 4

// Availability is the cheap per-domain answer: no contacts, no referral, no
// full report.
type Availability struct {
	Domain     string             `json:"domain" jsonschema:"the domain as queried, normalized to the registrable domain"`
	Registered normalize.Tristate `json:"registered" jsonschema:"yes, no, or unknown - unknown means could not determine, never treat it as available"`
	Source     normalize.Protocol `json:"source" jsonschema:"rdap or whois"`
	CheckedAt  time.Time          `json:"checked_at"`
	Cache      string             `json:"cache" jsonschema:"hit or miss"`
	// Warning explains an unknown. Present only when it would otherwise be
	// mysterious, because a caller screening fifty names cannot chase silence.
	Warning string `json:"warning,omitempty"`
	// Error is set when the input was not a usable domain. The entry is still
	// returned so a batch keeps its shape and the caller can align results
	// with inputs positionally.
	Error string `json:"error,omitempty"`
}

// CheckAvailability answers "is this registered" for up to MaxBatch domains.
//
// It never returns an error for a single bad or unresolvable name: each entry
// carries its own outcome, because failing the whole batch for one typo would
// force the caller to bisect their own request.
func (r *Resolver) CheckAvailability(ctx context.Context, domains []string, maxAge time.Duration) []Availability {
	if len(domains) > MaxBatch {
		domains = domains[:MaxBatch]
	}
	out := make([]Availability, len(domains))

	sem := make(chan struct{}, availabilityConcurrency)
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Add(1)
		go func(i int, input string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[i] = Availability{Domain: input, Registered: normalize.Unknown,
					CheckedAt: r.now().UTC(), Error: "cancelled"}
				return
			}
			out[i] = r.checkOne(ctx, input, maxAge)
		}(i, d)
	}
	wg.Wait()
	return out
}

func (r *Resolver) checkOne(ctx context.Context, input string, maxAge time.Duration) Availability {
	a := Availability{Domain: input, Registered: normalize.Unknown, CheckedAt: r.now().UTC()}

	ctx, cancel := context.WithTimeout(ctx, AvailabilityTimeout)
	defer cancel()

	rep, err := r.Lookup(ctx, input, Options{
		MaxAge:                maxAge,
		IncludeContacts:       false,
		SkipRegistrarReferral: true,
	})
	if err != nil {
		a.Error = err.Error()
		return a
	}

	a.Domain = rep.Query.ASCII
	a.Registered = rep.Registered
	a.Source = rep.Source.Protocol
	a.Cache = rep.Source.Cache
	a.CheckedAt = rep.Source.FetchedAt
	if rep.Registered == normalize.Unknown && len(rep.Warnings) > 0 {
		a.Warning = rep.Warnings[0]
	}
	return a
}
