package resolve

import (
	"context"
	"strings"
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
// Now that M3's per-upstream token buckets exist, this is no longer the only
// thing protecting a registry — but it is still what protects the *batch*. The
// limiter paces each host; this bounds how many goroutines sit waiting for a
// token at once, which is what keeps a fifty-name batch from holding fifty
// blocked goroutines and its own deadline hostage.
//
// Raised from 4 to 8 at M5 because the limiter now does the pacing: the
// concurrency here only has to be small enough that queueing is bounded, not
// small enough to be polite on its own.
const availabilityConcurrency = 8

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

	// Deduplicate before dispatching. A batch of candidate names routinely
	// repeats entries, and while singleflight collapses concurrent duplicates
	// anyway, doing it here also stops duplicates consuming batch concurrency
	// slots — so fifty names with twenty duplicates checks thirty things rather
	// than queueing fifty.
	first := make(map[string]int, len(domains))
	var order []int
	for i, d := range domains {
		key := strings.ToLower(strings.TrimSpace(d))
		if key == "" {
			order = append(order, i)
			continue
		}
		if j, seen := first[key]; seen {
			// Point the duplicate at the canonical result once it is known.
			out[i].Domain = d
			_ = j
			continue
		}
		first[key] = i
		order = append(order, i)
	}

	sem := make(chan struct{}, availabilityConcurrency)
	var wg sync.WaitGroup
	for _, i := range order {
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
		}(i, domains[i])
	}
	wg.Wait()

	// Fill the duplicates in from their canonical entry, so the caller still
	// gets one result per input in the order requested.
	for i, d := range domains {
		key := strings.ToLower(strings.TrimSpace(d))
		if j, ok := first[key]; ok && j != i {
			dup := out[j]
			// The echoed domain stays as the caller wrote it; everything else is
			// the shared answer.
			dup.Domain = out[j].Domain
			out[i] = dup
		}
	}
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
