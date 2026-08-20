package resolve

import (
	"context"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/ratelimit"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/whois"
	"github.com/qjam/whois-mcp/internal/whois/whoistest"
)

// guardedResolver builds a WHOIS-only resolver sharing one guard, the way
// cmd/whois-mcp does.
func guardedResolver(t *testing.T, ianaHost string, guard *ratelimit.Guard) *Resolver {
	t.Helper()
	reg, err := rdapx.NewRegistryForTest(map[string][]string{"unrelated": {"https://rdap.invalid/"}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	hc := rdapx.NewHTTPClientWithOptions(time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	tr := whois.NewTransportWithOptions(2*time.Second, whois.TransportOptions{AllowPrivateAddresses: true}).
		WithGuard(guard)
	store := cache.NewMemory()
	wc := whois.NewClientWithOptions(tr, store, quietLog(), whois.ClientOptions{IANAHost: ianaHost})
	return New(rdapx.NewClient(reg, hc, "test").WithGuard(guard), wc, store, quietLog())
}

// TestOneDeadUpstreamDoesNotAffectOthers is M3's headline exit criterion:
// killing one upstream trips its breaker without affecting other TLDs.
//
// The failure this guards against is the reason the breaker exists. A registry
// that stops answering holds every request against it open until the deadline,
// and with a shared upstream concurrency budget that means one dead ccTLD makes
// .com slow for everybody.
func TestOneDeadUpstreamDoesNotAffectOthers(t *testing.T) {
	// A registry that answers, and one that is not listening at all.
	healthy := whoistest.New(t, whoistest.ModeNormal,
		"Domain Name: good.alive\r\nRegistrar: R\r\nCreation Date: 2020-01-01T00:00:00Z\r\n"+
			"Domain Status: ok\r\nName Server: ns1.example-dns.test\r\n")
	dead := whoistest.New(t, whoistest.ModeNormal, "")
	deadAddr := dead.Addr
	dead.Close()

	// One IANA fake that routes each TLD to its own registry.
	iana := whoistest.NewHandler(t, func(query string) (string, whoistest.Mode) {
		switch query {
		case "alive":
			return "domain: ALIVE\nwhois: " + healthy.Addr + "\n", whoistest.ModeNormal
		default:
			return "domain: DEADTLD\nwhois: " + deadAddr + "\n", whoistest.ModeNormal
		}
	})

	guard := ratelimit.NewGuard(
		ratelimit.New(ratelimit.Options{Rate: 1000, Burst: 1000}),
		ratelimit.NewBreaker(ratelimit.BreakerOptions{Threshold: 2, Cooldown: time.Hour}),
	)
	r := guardedResolver(t, iana.Addr, guard)
	ctx := context.Background()

	// Hammer the dead TLD until its circuit opens.
	for i := range 3 {
		rep, err := r.Lookup(ctx, "x.deadtld", Options{MaxAge: 0})
		if err != nil {
			t.Fatalf("dead lookup %d errored instead of reporting unknown: %v", i, err)
		}
		if rep.Registered != normalize.Unknown {
			t.Errorf("dead lookup %d: Registered = %q; want unknown", i, rep.Registered)
		}
	}
	if got := guard.State(deadAddr); got != ratelimit.Open {
		t.Fatalf("breaker for the dead host = %q; want open", got)
	}

	// The healthy TLD is unaffected, and fast.
	start := time.Now()
	rep, err := r.Lookup(ctx, "good.alive", Options{MaxAge: 0, IncludeContacts: true})
	if err != nil {
		t.Fatalf("healthy lookup failed while another upstream was down: %v", err)
	}
	if rep.Registered != normalize.Yes {
		t.Errorf("healthy lookup: Registered = %q; want yes", rep.Registered)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("healthy lookup took %v while another upstream was down", elapsed)
	}
	if got := guard.State(healthy.Addr); got != ratelimit.Closed {
		t.Errorf("healthy host's breaker = %q; want closed", got)
	}

	// And the dead TLD now fails fast rather than burning a dial timeout, which
	// is what frees the concurrency budget.
	start = time.Now()
	if _, err := r.Lookup(ctx, "y.deadtld", Options{MaxAge: 0}); err != nil {
		t.Fatalf("dead lookup errored: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("dead lookup took %v with the circuit open; the point is to fail fast", elapsed)
	}
}

// TestRetryAfterIsHonouredExactly is the other half of M3's exit criterion: a
// fake registry returning a Retry-After must be obeyed to the second, not
// approximated.
func TestRetryAfterIsHonouredExactly(t *testing.T) {
	lim := ratelimit.New(ratelimit.Options{Rate: 1000, Burst: 1000})
	registry := whoistest.New(t, whoistest.ModeRateLimited, "")
	iana := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "domain: T\nwhois: " + registry.Addr + "\n", whoistest.ModeNormal
	})
	guard := ratelimit.NewGuard(lim, nil)
	r := guardedResolver(t, iana.Addr, guard)

	// The registry answers with a rate-limit notice, which the parser must not
	// read as "this domain is free".
	rep, err := r.Lookup(context.Background(), "throttled.test", Options{MaxAge: 0})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.Unknown {
		t.Errorf("Registered = %q for a rate-limited response; want unknown", rep.Registered)
	}

	// Now record an explicit pause the way an HTTP upstream would, and confirm
	// the limiter honours the exact interval.
	base := time.Now()
	lim.Observe(registry.Addr, 429, "90")
	until, paused := lim.PausedUntil(registry.Addr)
	if !paused {
		t.Fatal("no pause recorded")
	}
	if d := until.Sub(base); d < 89*time.Second || d > 91*time.Second {
		t.Errorf("pause = %v; want the 90s the upstream asked for", d)
	}
}
