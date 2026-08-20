package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
)

// TTLRaw is how long a raw upstream payload is cached (design §9).
//
// Fifteen minutes rather than the report's hour: raw payloads are larger and
// reused far less, so caching them as long would spend memory on data almost
// nobody asks for twice.
const TTLRaw = 15 * time.Minute

// ErrNoRaw means no raw payload could be obtained.
var ErrNoRaw = errors.New("no raw response available")

// RawResponse is a verbatim upstream payload.
type RawResponse struct {
	Query    normalize.Query    `json:"query"`
	Protocol normalize.Protocol `json:"protocol"`
	// Servers is every endpoint consulted, in order. For WHOIS this is the
	// referral chain, which is the thing whois_raw exists to expose.
	Servers   []string  `json:"servers"`
	FetchedAt time.Time `json:"fetched_at"`
	Cache     string    `json:"cache"`
	Truncated bool      `json:"truncated,omitempty"`
	// Body is the payload: RDAP JSON, or port-43 text.
	Body string `json:"body"`
	// Warnings carries anything non-fatal, such as a referral that failed.
	Warnings []string `json:"warnings,omitempty"`
}

// RawRDAP returns the verbatim RDAP JSON for a domain.
func (r *Resolver) RawRDAP(ctx context.Context, input string, maxAge time.Duration) (*RawResponse, error) {
	q, err := NormalizeQuery(input)
	if err != nil {
		return nil, err
	}
	key := "v1:raw:rdap:" + q.ASCII
	if cached, ok := r.cachedRaw(ctx, key, maxAge); ok {
		return cached, nil
	}

	res, err := r.rdap.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(res.Raw) == 0 {
		return nil, fmt.Errorf("%w: the registry returned no RDAP body for %s", ErrNoRaw, q.ASCII)
	}
	out := &RawResponse{
		Query: q, Protocol: normalize.ProtoRDAP, Servers: res.Servers,
		FetchedAt: r.now().UTC(), Cache: "miss", Body: string(res.Raw),
		Warnings: res.Warnings,
	}
	r.storeRaw(ctx, key, out)
	return out, nil
}

// RawWHOIS returns the verbatim port-43 text for a domain, plus the referral
// chain that produced it.
func (r *Resolver) RawWHOIS(ctx context.Context, input string, maxAge time.Duration) (*RawResponse, error) {
	q, err := NormalizeQuery(input)
	if err != nil {
		return nil, err
	}
	if r.whois == nil {
		return nil, fmt.Errorf("%w: the WHOIS path is not configured", ErrNoRaw)
	}
	key := "v1:raw:whois:" + q.ASCII
	if cached, ok := r.cachedRaw(ctx, key, maxAge); ok {
		return cached, nil
	}

	res, err := r.whois.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(res.Raw) == 0 {
		// An empty WHOIS response is a real outcome elsewhere, but there is
		// nothing raw to return, and an empty body would read as "the registry
		// says this domain has no data" rather than "we got nothing".
		return nil, fmt.Errorf("%w: %s returned no text for %s", ErrNoRaw, lastServer(res.Servers), q.ASCII)
	}
	out := &RawResponse{
		Query: q, Protocol: normalize.ProtoWHOIS, Servers: res.Servers,
		FetchedAt: r.now().UTC(), Cache: "miss", Body: string(res.Raw),
		Truncated: res.Truncated, Warnings: res.Warnings,
	}
	r.storeRaw(ctx, key, out)
	return out, nil
}

// RawAuto returns whichever raw payload the resolver would actually have used:
// RDAP when the TLD publishes it, WHOIS otherwise.
func (r *Resolver) RawAuto(ctx context.Context, input string, maxAge time.Duration) (*RawResponse, error) {
	out, err := r.RawRDAP(ctx, input, maxAge)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, rdapx.ErrNoRDAPService) || errors.Is(err, ErrNoRaw) {
		return r.RawWHOIS(ctx, input, maxAge)
	}
	return nil, err
}

func (r *Resolver) cachedRaw(ctx context.Context, key string, maxAge time.Duration) (*RawResponse, bool) {
	if maxAge <= 0 {
		return nil, false
	}
	raw, ok := r.cache.Get(ctx, key)
	if !ok {
		return nil, false
	}
	var out RawResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	if r.now().Sub(out.FetchedAt) > maxAge {
		return nil, false
	}
	out.Cache = "hit"
	return &out, true
}

func (r *Resolver) storeRaw(ctx context.Context, key string, v *RawResponse) {
	body, err := json.Marshal(v)
	if err != nil {
		r.log.Warn("caching raw payload failed", "error", err)
		return
	}
	r.cache.Set(ctx, key, body, TTLRaw)
}

func lastServer(servers []string) string {
	if len(servers) == 0 {
		return "the registry"
	}
	return servers[len(servers)-1]
}
