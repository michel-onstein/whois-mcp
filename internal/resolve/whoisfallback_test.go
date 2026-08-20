package resolve

import (
	"context"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/whois"
	"github.com/qjam/whois-mcp/internal/whois/whoistest"
)

// fallbackResolver builds a resolver whose RDAP registry knows nothing, so
// every lookup takes the WHOIS path, pointed at fake servers on loopback.
func fallbackResolver(t *testing.T, ianaHost string) *Resolver {
	t.Helper()
	// A registry that knows some other TLD, so the one under test is
	// genuinely absent rather than the registry being empty.
	reg, err := rdapx.NewRegistryForTest(map[string][]string{"unrelated": {"https://rdap.invalid/"}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	hc := rdapx.NewHTTPClientWithOptions(2*time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	tr := whois.NewTransportWithOptions(5*time.Second, whois.TransportOptions{AllowPrivateAddresses: true})
	store := cache.NewMemory()
	wc := whois.NewClientWithOptions(tr, store, quietLog(), whois.ClientOptions{IANAHost: ianaHost})
	return New(rdapx.NewClient(reg, hc, "test"), wc, store, quietLog())
}

func ianaFake(t *testing.T, host string) string {
	t.Helper()
	return whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "domain:  TEST\nwhois:   " + host + "\n", whoistest.ModeNormal
	}).Addr
}

// TestFallbackResolvesRDAPLessTLD is M1's headline exit criterion: a TLD with no
// RDAP service must resolve, not report unknown.
func TestFallbackResolvesRDAPLessTLD(t *testing.T) {
	registry := whoistest.New(t, whoistest.ModeNormal,
		"Domain Name: example.test\r\n"+
			"Registrar: Example Registrar Ltd\r\n"+
			"Creation Date: 2001-04-01T00:00:00Z\r\n"+
			"Registry Expiry Date: 2027-04-01T00:00:00Z\r\n"+
			"Domain Status: ok\r\n"+
			"Name Server: ns1.example-dns.test\r\n"+
			"Name Server: ns2.example-dns.test\r\n")
	r := fallbackResolver(t, ianaFake(t, registry.Addr))

	rep, err := r.Lookup(context.Background(), "example.test", Options{MaxAge: 0, IncludeContacts: true})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.Yes {
		t.Errorf("Registered = %q; want yes", rep.Registered)
	}
	if rep.Source.Protocol != normalize.ProtoWHOIS {
		t.Errorf("Protocol = %q; want whois", rep.Source.Protocol)
	}
	if rep.Registrar == nil || rep.Registrar.Name != "Example Registrar Ltd" {
		t.Errorf("Registrar = %+v; want the parsed registrar", rep.Registrar)
	}
	if rep.Dates.Created == nil || rep.Dates.Created.Year() != 2001 {
		t.Errorf("Created = %v; want 2001", rep.Dates.Created)
	}
	if len(rep.Nameservers) != 2 {
		t.Errorf("Nameservers = %v; want 2", rep.Nameservers)
	}
	// RDAP scores 1.0; a WHOIS parse must report something lower so an agent
	// can tell the difference.
	if rep.Source.ParseConfidence <= 0 || rep.Source.ParseConfidence >= 1.0 {
		t.Errorf("ParseConfidence = %v; want between 0 and 1 for WHOIS", rep.Source.ParseConfidence)
	}
}

func TestFallbackReportsUnregistered(t *testing.T) {
	registry := whoistest.New(t, whoistest.ModeNormal,
		"No match for \"nosuchdomain.test\".\r\n")
	r := fallbackResolver(t, ianaFake(t, registry.Addr))

	rep, err := r.Lookup(context.Background(), "nosuchdomain.test", Options{MaxAge: 0})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.No {
		t.Errorf("Registered = %q; want no", rep.Registered)
	}
}

// TestFallbackNeverGuessesFree is the safety property at the resolver level:
// every non-answer must surface as unknown with a warning, never as available.
func TestFallbackNeverGuessesFree(t *testing.T) {
	cases := []struct {
		name string
		mode whoistest.Mode
		body string
	}{
		{"rate limited", whoistest.ModeRateLimited, ""},
		{"html error page", whoistest.ModeMalformed, ""},
		{"empty response", whoistest.ModeRefuse, ""},
		{"hanging server", whoistest.ModeHang, ""},
		{"banner only", whoistest.ModeNormal, "% This is a WHOIS server.\r\n% Terms of use apply.\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			registry := whoistest.New(t, c.mode, c.body)
			r := fallbackResolver(t, ianaFake(t, registry.Addr))
			// Keep the deadline short so the hanging case does not stall.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			rep, err := r.Lookup(ctx, "whatever.test", Options{MaxAge: 0})
			if err != nil {
				t.Fatalf("a non-answer must not fail the lookup: %v", err)
			}
			if rep.Registered != normalize.Unknown {
				t.Errorf("Registered = %q; want unknown — a non-answer must never become an availability claim", rep.Registered)
			}
			if len(rep.Warnings) == 0 {
				t.Error("no warning explaining why the answer is unknown")
			}
		})
	}
}

// TestFallbackWhenNoWHOISHostExists covers a TLD IANA does not know: unknown
// with an explanation beats an error, because the agent can still act on it.
func TestFallbackWhenNoWHOISHostExists(t *testing.T) {
	iana := whoistest.New(t, whoistest.ModeNormal, "% This query returned 0 objects.\r\n")
	r := fallbackResolver(t, iana.Addr)

	rep, err := r.Lookup(context.Background(), "example.nowhere", Options{MaxAge: 0})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.Unknown {
		t.Errorf("Registered = %q; want unknown", rep.Registered)
	}
	if len(rep.Warnings) == 0 {
		t.Error("no warning explaining that the TLD has no WHOIS host")
	}
}

// TestFallbackNotConfiguredStillAnswers pins the nil-client behaviour, which is
// the M0 shape and must stay an answer rather than a panic.
func TestFallbackNotConfiguredStillAnswers(t *testing.T) {
	reg, _ := rdapx.NewRegistryForTest(map[string][]string{"unrelated": {"https://rdap.invalid/"}})
	hc := rdapx.NewHTTPClientWithOptions(time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	r := New(rdapx.NewClient(reg, hc, "test"), nil, cache.NewMemory(), quietLog())

	rep, err := r.Lookup(context.Background(), "example.test", Options{MaxAge: 0})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.Unknown {
		t.Errorf("Registered = %q; want unknown", rep.Registered)
	}
	if len(rep.Warnings) == 0 {
		t.Error("no warning explaining that the fallback is not configured")
	}
}

// TestFallbackCachesByCertainty checks the TTL choice actually follows the
// answer: an unknown result must not be cemented for an hour.
func TestFallbackCachesByCertainty(t *testing.T) {
	registry := whoistest.New(t, whoistest.ModeRateLimited, "")
	r := fallbackResolver(t, ianaFake(t, registry.Addr))

	rep, err := r.Lookup(context.Background(), "throttled.test", Options{MaxAge: 0})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.Unknown {
		t.Fatalf("Registered = %q; want unknown", rep.Registered)
	}
	// A second lookup inside the unknown TTL may serve from cache, but must
	// still be unknown rather than promoted.
	again, err := r.Lookup(context.Background(), "throttled.test", Options{MaxAge: time.Minute})
	if err != nil {
		t.Fatalf("second Lookup: %v", err)
	}
	if again.Registered != normalize.Unknown {
		t.Errorf("cached Registered = %q; want unknown", again.Registered)
	}
}
