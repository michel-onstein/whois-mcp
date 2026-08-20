package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/whois"
	"github.com/qjam/whois-mcp/internal/whois/parsers"
)

// TTLs for cached results, kept as names because they read better at call
// sites. The authoritative table is DefaultTTLPolicy in ttl.go.
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
	// SkipRegistrarReferral suppresses the registry-to-registrar hop. The
	// availability path sets it: the registry alone answers "is this taken".
	SkipRegistrarReferral bool
}

// Resolver executes lookups. It is safe for concurrent use.
type Resolver struct {
	rdap  *rdapx.Client
	whois *whois.Client
	cache cache.Cache
	log   *slog.Logger
	now   func() time.Time

	// flight collapses concurrent identical lookups into one upstream call.
	//
	// This matters more than it sounds: an agent screening a list of candidate
	// names routinely repeats entries, and domain_availability fans out fifty
	// at once. Without collapsing, duplicates in one batch become duplicate
	// queries to the same registry within the same second — which is precisely
	// the pattern that reads as a scrape.
	flight singleflight.Group

	// policy is the cache TTL table (design §9).
	policy TTLPolicy
}

// New returns a Resolver. A nil WHOIS client disables the fallback, which
// leaves RDAP-less TLDs answering Unknown — the M0 behaviour, retained only so
// a caller that genuinely wants RDAP-only can have it.
func New(rc *rdapx.Client, wc *whois.Client, c cache.Cache, log *slog.Logger) *Resolver {
	return &Resolver{
		rdap: rc, whois: wc, cache: c, log: log,
		now:    time.Now,
		policy: DefaultTTLPolicy,
	}
}

// WithTTLPolicy overrides the cache TTL table.
//
// An invalid or out-of-order policy is refused rather than applied: a policy
// that cached "unknown" longer than "registered" would pin transient failures
// as answers, and nothing downstream would notice.
func (r *Resolver) WithTTLPolicy(p TTLPolicy) error {
	if !p.Valid() {
		return errors.New("TTL policy has a non-positive entry; that would disable caching, which is what gets an anonymous client blocked")
	}
	if !p.Ordered() {
		return errors.New("TTL policy caches an ambiguous answer for longer than a certain one")
	}
	r.policy = p
	return nil
}

// Lookup normalizes the input, consults the cache, and queries RDAP, falling
// back to WHOIS.
//
// Two paths reach WHOIS: a TLD with no RDAP service at all (most ccTLDs), and
// an RDAP answer too ambiguous to report (design §8, the "ambiguous" branch).
// The second matters as much as the first — an RDAP endpoint that is dead or
// misconfigured should not turn into "I cannot determine this" while a
// perfectly good port-43 service sits next to it.
//
// When both protocols fail to produce a definite answer the report says
// Unknown with an explanatory warning rather than erroring, because "I cannot
// determine this" is a useful answer to an agent and a failed tool call is not.
func (r *Resolver) Lookup(ctx context.Context, input string, opt Options) (*normalize.DomainReport, error) {
	q, err := NormalizeQuery(input)
	if err != nil {
		return nil, err
	}

	// Collapse concurrent identical lookups. The key includes the options that
	// change the answer, so a caller asking for a fresh fetch is not handed a
	// cached one that another caller was content with.
	key := flightKey(q.ASCII, opt)
	v, err, _ := r.flight.Do(key, func() (any, error) {
		return r.lookupOnce(ctx, input, opt)
	})
	if err != nil {
		return nil, err
	}
	rep, ok := v.(*normalize.DomainReport)
	if !ok || rep == nil {
		return nil, fmt.Errorf("internal: lookup produced %T", v)
	}
	// Each caller gets its own copy, and per-caller filtering happens here and
	// nowhere else. Filtering inside lookupOnce would apply the *winning*
	// caller's options to the shared report, so a caller that asked for
	// include_contacts=false would silently strip the entities every other
	// collapsed caller had asked for.
	clone := *rep
	r.applyOptions(&clone, opt)
	return &clone, nil
}

// flightKey identifies lookups that may share one upstream call.
func flightKey(ascii string, opt Options) string {
	// MaxAge participates because a zero MaxAge forces a fresh fetch; folding
	// it in with a cached-result caller would defeat that.
	fresh := "c"
	if opt.MaxAge <= 0 {
		fresh = "f"
	}
	skip := "r"
	if opt.SkipRegistrarReferral {
		skip = "n"
	}
	return ascii + "|" + fresh + "|" + skip
}

func (r *Resolver) lookupOnce(ctx context.Context, input string, opt Options) (*normalize.DomainReport, error) {
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
					return &rep, nil
				}
			}
		}
	}

	fetchedAt := r.now().UTC()
	res, err := r.rdap.QueryWithOptions(ctx, q, rdapx.QueryOptions{
		SkipRegistrarReferral: opt.SkipRegistrarReferral,
	})
	switch {
	case errors.Is(err, rdapx.ErrNoRDAPService):
		rep := r.viaWHOIS(ctx, q, fetchedAt,
			"TLD ."+q.TLD+" publishes no RDAP service")
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

	// An ambiguous RDAP answer is exactly the case WHOIS exists to resolve.
	// Only Unknown falls through: a definite yes or no from RDAP is structured
	// data and beats anything parsed out of free text.
	if rep.Registered == normalize.Unknown && r.whois != nil {
		if alt := r.viaWHOIS(ctx, q, fetchedAt, "RDAP returned no definite answer"); alt.Registered != normalize.Unknown {
			alt.Warnings = append(alt.Warnings, rep.Warnings...)
			r.store(ctx, key, alt)
			return alt, nil
		}
	}

	r.store(ctx, key, rep)
	return rep, nil
}

// viaWHOIS runs the port-43 path and maps the result onto a report.
//
// It never returns nil and never returns an error: a WHOIS failure becomes an
// Unknown report carrying both the reason RDAP was insufficient and the reason
// WHOIS could not finish the job, which is what an agent needs to decide
// whether to retry or to tell its user the truth.
func (r *Resolver) viaWHOIS(ctx context.Context, q normalize.Query, fetchedAt time.Time, because string) *normalize.DomainReport {
	unknown := func(warnings ...string) *normalize.DomainReport {
		return &normalize.DomainReport{
			Query:      q,
			Registered: normalize.Unknown,
			Source: normalize.Source{
				Protocol:  normalize.ProtoWHOIS,
				FetchedAt: fetchedAt,
				Cache:     "miss",
			},
			Warnings: warnings,
		}
	}

	if r.whois == nil {
		return unknown(because + "; the WHOIS fallback is not configured")
	}

	res, err := r.whois.Query(ctx, q)
	if err != nil {
		r.log.Debug("whois lookup failed", "domain", q.ASCII, "error", err)
		return unknown(because, "WHOIS lookup failed: "+err.Error())
	}

	host := ""
	if len(res.Servers) > 0 {
		host = res.Servers[len(res.Servers)-1]
	}
	parsed := parsers.Parse(host, res.Raw)
	registered := tristate(parsers.Classify(host, res.Raw))

	rep := normalize.FromWHOIS(q, parsed, registered, res.Servers, fetchedAt, "miss", len(res.Raw) > 0)
	rep.Warnings = append(rep.Warnings, res.Warnings...)
	if res.Truncated {
		rep.Warnings = append(rep.Warnings,
			"WHOIS response was truncated at the size cap; fields near the end may be missing")
	}
	return rep
}

// tristate converts the parser's availability into the report's.
func tristate(a parsers.Availability) normalize.Tristate {
	switch a {
	case parsers.Registered:
		return normalize.Yes
	case parsers.Unregistered:
		return normalize.No
	default:
		return normalize.Unknown
	}
}

// applyOptions trims a report to what this caller asked for.
//
// It is called only on a per-caller copy, never on the report that goes into the
// cache: caching a filtered report would serve the next caller data that was
// removed for someone else's benefit.
func (r *Resolver) applyOptions(rep *normalize.DomainReport, opt Options) {
	if !opt.IncludeContacts {
		rep.Entities = nil
	}
}

// store caches a report under the TTL appropriate to its certainty.
func (r *Resolver) store(ctx context.Context, key string, rep *normalize.DomainReport) {
	ttl := r.policy.For(rep.Registered)
	raw, err := json.Marshal(rep)
	if err != nil {
		r.log.Warn("caching report failed", "error", err)
		return
	}
	r.cache.Set(ctx, key, raw, ttl)
}

func cacheKey(ascii string) string { return "v1:report:" + ascii }
