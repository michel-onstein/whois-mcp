package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
)

// TTLs for cached results. Registration data changes slowly; availability is
// the volatile case; an ambiguous answer is retried soon rather than cemented.
// See docs/MCP_DESIGN.md §9.
const (
	TTLRegistered   = time.Hour
	TTLUnregistered = 5 * time.Minute
	TTLUnknown      = time.Minute
)

// Options tune a single lookup.
type Options struct {
	// MaxAge is the caller's cache tolerance. Zero forces a fresh fetch; the
	// result is still written back to the cache.
	MaxAge time.Duration
	// IncludeContacts controls whether entity records are returned. They are
	// usually redacted, but their presence and redaction state is itself
	// information.
	IncludeContacts bool
}

// Resolver executes lookups. It is safe for concurrent use.
type Resolver struct {
	rdap  *rdapx.Client
	cache cache.Cache
	log   *slog.Logger
	now   func() time.Time
}

// New returns a Resolver.
func New(rc *rdapx.Client, c cache.Cache, log *slog.Logger) *Resolver {
	return &Resolver{rdap: rc, cache: c, log: log, now: time.Now}
}

// Lookup normalizes the input, consults the cache, and queries RDAP.
//
// The WHOIS fallback lands at M1; until then a TLD with no RDAP service yields
// a report with Registered=unknown and an explanatory warning rather than an
// error, because "I cannot determine this" is a useful answer to an agent and
// a failed tool call is not.
func (r *Resolver) Lookup(ctx context.Context, input string, opt Options) (*normalize.DomainReport, error) {
	q, err := NormalizeQuery(input)
	if err != nil {
		return nil, err
	}

	key := cacheKey(q.ASCII)
	if opt.MaxAge > 0 {
		if raw, ok := r.cache.Get(ctx, key); ok {
			var rep normalize.DomainReport
			if err := json.Unmarshal(raw, &rep); err == nil {
				if age := r.now().Sub(rep.Source.FetchedAt); age <= opt.MaxAge {
					rep.Source.Cache = "hit"
					r.applyOptions(&rep, opt)
					return &rep, nil
				}
			}
		}
	}

	fetchedAt := r.now().UTC()
	res, err := r.rdap.Query(ctx, q)
	switch {
	case errors.Is(err, rdapx.ErrNoRDAPService):
		rep := &normalize.DomainReport{
			Query:      q,
			Registered: normalize.Unknown,
			Source: normalize.Source{
				Protocol:        normalize.ProtoRDAP,
				FetchedAt:       fetchedAt,
				Cache:           "miss",
				ParseConfidence: 0,
			},
			Warnings: []string{
				"TLD ." + q.TLD + " publishes no RDAP service; the WHOIS fallback that covers it is not implemented yet (M1)",
			},
		}
		r.store(ctx, key, rep)
		return rep, nil
	case err != nil:
		// Context cancellation and hard transport failures reach here.
		return nil, err
	}

	var rep *normalize.DomainReport
	if res.Registered == normalize.Yes {
		rep = normalize.FromRDAP(q, res.Domain, res.Servers, fetchedAt, "miss")
	} else {
		rep = &normalize.DomainReport{
			Query:      q,
			Registered: res.Registered,
			Source: normalize.Source{
				Protocol:        normalize.ProtoRDAP,
				Servers:         res.Servers,
				FetchedAt:       fetchedAt,
				Cache:           "miss",
				ParseConfidence: 1.0,
				RawAvailable:    len(res.Raw) > 0,
			},
		}
	}
	rep.Warnings = append(rep.Warnings, res.Warnings...)

	r.store(ctx, key, rep)
	r.applyOptions(rep, opt)
	return rep, nil
}

func (r *Resolver) applyOptions(rep *normalize.DomainReport, opt Options) {
	if !opt.IncludeContacts {
		rep.Entities = nil
	}
}

// store caches a report under the TTL appropriate to its certainty.
func (r *Resolver) store(ctx context.Context, key string, rep *normalize.DomainReport) {
	var ttl time.Duration
	switch rep.Registered {
	case normalize.Yes:
		ttl = TTLRegistered
	case normalize.No:
		ttl = TTLUnregistered
	default:
		ttl = TTLUnknown
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		r.log.Warn("caching report failed", "error", err)
		return
	}
	r.cache.Set(ctx, key, raw, ttl)
}

func cacheKey(ascii string) string { return "v1:report:" + ascii }
