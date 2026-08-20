package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openrdap/rdap"

	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
)

// TTLNet is how long an IP or ASN registration is cached.
//
// Longer than a domain's hour: RIR allocations change far less often than
// domain registrations — a /16 does not expire — so the volatility that justifies
// a short TTL for domains does not apply.
const TTLNet = 6 * time.Hour

// ErrNoNetRegistry means the resolver was built without IP/ASN support.
var ErrNoNetRegistry = errors.New("IP and ASN lookups are not configured")

// WithNetRegistry enables IP and ASN lookups.
func (r *Resolver) WithNetRegistry(reg *rdapx.NetRegistry) *Resolver {
	r.netReg = reg
	return r
}

// LookupResource resolves an IP address, CIDR prefix, or ASN.
//
// It shares the cache, the singleflight group and the upstream guard with domain
// lookups, because the RIRs are upstreams like any other: an agent enumerating a
// prefix list deserves the same collapsing and the same politeness as one
// enumerating domains.
func (r *Resolver) LookupResource(ctx context.Context, input string, maxAge time.Duration) (*normalize.NetReport, error) {
	if r.netReg == nil {
		return nil, ErrNoNetRegistry
	}
	res, err := rdapx.ParseResource(input)
	if err != nil {
		return nil, err
	}

	key := "v1:net:" + res.String()
	if maxAge > 0 {
		if raw, ok := r.cache.Get(ctx, key); ok {
			var rep normalize.NetReport
			if json.Unmarshal(raw, &rep) == nil &&
				r.now().Sub(rep.Source.FetchedAt) <= maxAge {
				rep.Source.Cache = "hit"
				return &rep, nil
			}
		}
	}

	// Collapse concurrent identical lookups, keyed on the normalized resource so
	// "8.8.8.8" and " 8.8.8.8 " share one upstream call.
	v, err, _ := r.flight.Do("net:"+key, func() (any, error) {
		return r.lookupResourceOnce(ctx, res, key)
	})
	if err != nil {
		return nil, err
	}
	rep, ok := v.(*normalize.NetReport)
	if !ok || rep == nil {
		return nil, fmt.Errorf("internal: resource lookup produced %T", v)
	}
	clone := *rep
	return &clone, nil
}

func (r *Resolver) lookupResourceOnce(ctx context.Context, res rdapx.Resource, key string) (*normalize.NetReport, error) {
	fetchedAt := r.now().UTC()
	out, err := r.rdap.QueryResource(ctx, r.netReg, res)
	if err != nil {
		return nil, err
	}

	q := normalize.NetQuery{Input: res.Input, Normalized: res.String()}
	var rep *normalize.NetReport
	switch obj := out.Object.(type) {
	case *rdap.IPNetwork:
		rep = normalize.FromRDAPIPNetwork(q, string(res.Kind), obj, out.Servers, fetchedAt, "miss")
	case *rdap.Autnum:
		rep = normalize.FromRDAPAutnum(q, obj, out.Servers, fetchedAt, "miss")
	default:
		// The RIR answered with something we did not ask for. Reporting it as an
		// error is right: unlike a domain lookup there is no tri-state to fall
		// back to, and inventing an empty report would look like a real answer.
		return nil, fmt.Errorf("%s returned an unexpected RDAP object type %T", res, out.Object)
	}
	rep.Warnings = append(rep.Warnings, out.Warnings...)

	if body, err := json.Marshal(rep); err == nil {
		r.cache.Set(ctx, key, body, TTLNet)
	} else {
		r.log.Warn("caching resource report failed", "error", err)
	}
	return rep, nil
}

// RawResource returns the verbatim RDAP JSON for an IP or ASN, for rdap_raw.
func (r *Resolver) RawResource(ctx context.Context, input string, maxAge time.Duration) (*RawResponse, error) {
	if r.netReg == nil {
		return nil, ErrNoNetRegistry
	}
	res, err := rdapx.ParseResource(input)
	if err != nil {
		return nil, err
	}
	key := "v1:raw:net:" + res.String()
	if cached, ok := r.cachedRaw(ctx, key, maxAge); ok {
		return cached, nil
	}

	out, err := r.rdap.QueryResource(ctx, r.netReg, res)
	if err != nil {
		return nil, err
	}
	if len(out.Raw) == 0 {
		return nil, fmt.Errorf("%w: no RDAP body for %s", ErrNoRaw, res)
	}
	raw := &RawResponse{
		Query:     normalize.Query{Input: res.Input, ASCII: res.String()},
		Protocol:  normalize.ProtoRDAP,
		Servers:   out.Servers,
		FetchedAt: r.now().UTC(),
		Cache:     "miss",
		Body:      string(out.Raw),
		Warnings:  out.Warnings,
	}
	r.storeRaw(ctx, key, raw)
	return raw, nil
}
