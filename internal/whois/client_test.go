package whois

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/whois/whoistest"
)

func testQuery(domain, tld string) normalize.Query {
	return normalize.Query{
		Input:             domain,
		RegistrableDomain: domain,
		ASCII:             domain,
		TLD:               tld,
		PublicSuffix:      tld,
	}
}

// newTestClient wires a Client whose TLD discovery answers with the given host,
// bypassing the real whois.iana.org. The discoverer's ianaHost is unexported,
// which is deliberate: only this package may redirect it.
func newTestClient(t *testing.T, ianaHost string) *Client {
	t.Helper()
	tr := testTransport(t, 5*time.Second)
	c := NewClient(tr, cache.NewMemory(), nil)
	c.dis.ianaHost = ianaHost
	return c
}

// ianaServer fakes whois.iana.org: it answers a TLD query with a record naming
// the registry's WHOIS host.
func ianaServer(t *testing.T, host string) *whoistest.Server {
	t.Helper()
	return whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "domain:       TEST\nwhois:        " + host + "\nstatus:       ACTIVE\n", whoistest.ModeNormal
	})
}

func TestClientQuerySingleHop(t *testing.T) {
	const body = "Domain Name: example.test\nRegistrar: Someone Ltd\n"
	registry := whoistest.New(t, whoistest.ModeNormal, body)
	c := newTestClient(t, ianaServer(t, registry.Addr).Addr)

	res, err := c.Query(context.Background(), testQuery("example.test", "test"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if string(res.Raw) != body {
		t.Errorf("Raw = %q; want %q", res.Raw, body)
	}
	if len(res.Chain) != 1 {
		t.Fatalf("Chain has %d hops; want 1", len(res.Chain))
	}
	if len(res.Servers) != 1 || res.Servers[0] != registry.Addr {
		t.Errorf("Servers = %v; want [%s]", res.Servers, registry.Addr)
	}
}

// TestClientFollowsReferral is the registry-to-registrar hop: the answer must
// come from the registrar, which is where the thick data lives.
func TestClientFollowsReferral(t *testing.T) {
	const registrarBody = "Domain Name: example.test\nRegistrant Organization: Real Owner\n"
	registrar := whoistest.New(t, whoistest.ModeNormal, registrarBody)
	registry := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "Domain Name: example.test\n" + whoistest.Referral(registrar.Addr), whoistest.ModeNormal
	})
	c := newTestClient(t, ianaServer(t, registry.Addr).Addr)

	res, err := c.Query(context.Background(), testQuery("example.test", "test"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if string(res.Raw) != registrarBody {
		t.Errorf("Raw = %q; want the registrar body %q", res.Raw, registrarBody)
	}
	if len(res.Chain) != 2 {
		t.Fatalf("Chain has %d hops; want 2", len(res.Chain))
	}
	if registrar.Conns() != 1 {
		t.Errorf("registrar saw %d connections; want 1", registrar.Conns())
	}
}

// TestClientStopsAtMaxHops proves the chain is bounded. An unbounded chain is
// an amplification vector, since every hop target is third-party input.
func TestClientStopsAtMaxHops(t *testing.T) {
	// Each server refers to the next; the fourth is never reached.
	last := whoistest.New(t, whoistest.ModeNormal, "Domain Name: deep.test\n")
	third := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "Domain Name: deep.test\n" + whoistest.Referral(last.Addr), whoistest.ModeNormal
	})
	second := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "Domain Name: deep.test\n" + whoistest.Referral(third.Addr), whoistest.ModeNormal
	})
	c := newTestClient(t, ianaServer(t, second.Addr).Addr)

	res, err := c.Query(context.Background(), testQuery("deep.test", "test"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Chain) != MaxReferralHops {
		t.Errorf("Chain has %d hops; want the %d-hop cap", len(res.Chain), MaxReferralHops)
	}
	if last.Conns() != 0 {
		t.Errorf("the fourth server was reached; the hop cap is not enforced")
	}
	if !hasWarning(res.Warnings, "stopped after") {
		t.Errorf("warnings = %v; want one about the hop cap", res.Warnings)
	}
}

// TestClientDetectsReferralLoop covers a registry that points at itself via a
// second host, which without cycle detection burns every remaining hop.
func TestClientDetectsReferralLoop(t *testing.T) {
	var addrA string
	a := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "Domain Name: loop.test\n" + whoistest.Referral(addrA), whoistest.ModeNormal
	})
	addrA = a.Addr
	c := newTestClient(t, ianaServer(t, a.Addr).Addr)

	res, err := c.Query(context.Background(), testQuery("loop.test", "test"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// The self-referral is recognised as the same host and not followed.
	if a.Conns() != 1 {
		t.Errorf("server was queried %d times; want 1", a.Conns())
	}
	if len(res.Raw) == 0 {
		t.Error("Raw is empty; the first answer was discarded")
	}
}

// TestClientDegradesWhenReferralFails is design §8.3's rule: a failed second
// hop must yield the registry answer plus a warning, never an error.
func TestClientDegradesWhenReferralFails(t *testing.T) {
	dead := whoistest.New(t, whoistest.ModeNormal, "")
	deadAddr := dead.Addr
	dead.Close() // nothing is listening there now

	const registryBody = "Domain Name: example.test\n"
	want := registryBody + whoistest.Referral(deadAddr)
	registry := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return want, whoistest.ModeNormal
	})
	c := newTestClient(t, ianaServer(t, registry.Addr).Addr)

	res, err := c.Query(context.Background(), testQuery("example.test", "test"))
	if err != nil {
		t.Fatalf("a failed referral must not fail the lookup: %v", err)
	}
	if string(res.Raw) != want {
		t.Errorf("Raw = %q; want the registry response %q", res.Raw, want)
	}
	if !hasWarning(res.Warnings, "referral") {
		t.Errorf("warnings = %v; want one naming the failed referral", res.Warnings)
	}
}

// TestClientKeepsRegistryAnswerWhenReferralIsEmpty guards a subtle data-loss
// bug: a registrar that answers with nothing must not blank out the registry's
// useful response.
func TestClientKeepsRegistryAnswerWhenReferralIsEmpty(t *testing.T) {
	silent := whoistest.New(t, whoistest.ModeRefuse, "")
	const registryBody = "Domain Name: example.test\nRegistrar: Someone\n"
	want := registryBody + whoistest.Referral(silent.Addr)
	registry := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return want, whoistest.ModeNormal
	})
	c := newTestClient(t, ianaServer(t, registry.Addr).Addr)

	res, err := c.Query(context.Background(), testQuery("example.test", "test"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if string(res.Raw) != want {
		t.Errorf("Raw = %q; want the registry response preserved, not the empty referral", res.Raw)
	}
}

func TestClientAppliesQuirkQuery(t *testing.T) {
	registry := whoistest.New(t, whoistest.ModeNormal, "Domain: example.de\n")
	c := newTestClient(t, ianaServer(t, registry.Addr).Addr)

	if _, err := c.Query(context.Background(), testQuery("example.de", "de")); err != nil {
		t.Fatalf("Query: %v", err)
	}
	got := registry.Queries()
	if len(got) != 1 || got[0] != "-T dn,ace example.de" {
		t.Errorf("registry received %q; want the .de quirk query", got)
	}
}

func TestClientHonoursNoReferralQuirk(t *testing.T) {
	registrar := whoistest.New(t, whoistest.ModeNormal, "should not be reached\n")
	registry := whoistest.NewHandler(t, func(string) (string, whoistest.Mode) {
		return "Domain name: example.nl\n" + whoistest.Referral(registrar.Addr), whoistest.ModeNormal
	})
	c := newTestClient(t, ianaServer(t, registry.Addr).Addr)

	if _, err := c.Query(context.Background(), testQuery("example.nl", "nl")); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if registrar.Conns() != 0 {
		t.Error("referral was followed despite the NoReferral quirk")
	}
}

func TestClientErrorsWhenTLDHasNoHost(t *testing.T) {
	iana := whoistest.New(t, whoistest.ModeNormal,
		"% This query returned 0 objects.\n")
	c := newTestClient(t, iana.Addr)

	_, err := c.Query(context.Background(), testQuery("example.nowhere", "nowhere"))
	if err == nil {
		t.Fatal("Query succeeded for a TLD with no WHOIS host")
	}
}

func TestDiscovererCachesAndReusesHost(t *testing.T) {
	registry := whoistest.New(t, whoistest.ModeNormal, "Domain Name: x.test\n")
	iana := ianaServer(t, registry.Addr)
	c := newTestClient(t, iana.Addr)

	for i := 0; i < 3; i++ {
		if _, err := c.Query(context.Background(), testQuery("x.test", "test")); err != nil {
			t.Fatalf("Query %d: %v", i, err)
		}
	}
	if iana.Conns() != 1 {
		t.Errorf("IANA was asked %d times for the same TLD; want 1 (the answer is cached %v)",
			iana.Conns(), HostTTL)
	}
}

func TestDiscovererFallsBackToSeedOnFailure(t *testing.T) {
	// An IANA host that is not listening forces the cold-start path.
	dead := whoistest.New(t, whoistest.ModeNormal, "")
	addr := dead.Addr
	dead.Close()

	d := NewDiscoverer(testTransport(t, time.Second), cache.NewMemory())
	d.ianaHost = addr

	got, err := d.Host(context.Background(), "com")
	if err != nil {
		t.Fatalf("Host(com) with IANA unreachable: %v", err)
	}
	if got != seedHosts["com"] {
		t.Errorf("Host(com) = %q; want the embedded seed %q", got, seedHosts["com"])
	}

	if _, err := d.Host(context.Background(), "unseeded"); err == nil {
		t.Error("Host succeeded for an unseeded TLD with IANA unreachable")
	}
}

func TestDiscovererRejectsEmptyTLD(t *testing.T) {
	d := NewDiscoverer(testTransport(t, time.Second), nil)
	if _, err := d.Host(context.Background(), "  "); !errors.Is(err, ErrNoWHOISHost) {
		t.Errorf("error = %v; want ErrNoWHOISHost", err)
	}
}

func TestWhoisFieldFromIANA(t *testing.T) {
	cases := []struct{ in, want string }{
		{"domain: UK\nwhois: whois.nic.uk\n", "whois.nic.uk"},
		{"domain: XX\nrefer: whois.example.org\n", "whois.example.org"},
		// "whois:" wins over "refer:" when both appear.
		{"refer: old.example.org\nwhois: new.example.org\n", "new.example.org"},
		// Trailing dot and case are normalised.
		{"whois: WHOIS.NIC.UK.\n", "whois.nic.uk"},
		// A value that is not a hostname is rejected rather than dialled.
		{"whois: none\n", ""},
		{"whois: http://example.org/form\n", ""},
		{"whois:\n", ""},
		{"% comment: whois.evil.example\n", ""},
	}
	for _, c := range cases {
		if got := whoisFieldFromIANA(c.in); got != c.want {
			t.Errorf("whoisFieldFromIANA(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestReferralHostPrefersMostSpecific(t *testing.T) {
	body := "Whois Server: generic.example\n" +
		"Registrar WHOIS Server: registrar.example\n"
	if got := referralHost(body); got != "registrar.example" {
		t.Errorf("referralHost = %q; want the registrar server", got)
	}
	if got := referralHost("Domain Name: x.test\n"); got != "" {
		t.Errorf("referralHost = %q; want empty when there is no referral", got)
	}
}

func TestQueryForAppliesQuirks(t *testing.T) {
	cases := []struct{ tld, domain, want string }{
		{"de", "example.de", "-T dn,ace example.de"},
		{"jp", "example.jp", "example.jp/e"},
		{"com", "example.com", "domain example.com"},
		{"net", "example.net", "domain example.net"},
		{"dk", "example.dk", "--show-handles example.dk"},
		{"org", "example.org", "example.org"}, // no quirk
		{"DE", "example.de", "-T dn,ace example.de"},
		{".de", "example.de", "-T dn,ace example.de"},
	}
	for _, c := range cases {
		if got := QueryFor(c.tld, c.domain); got != c.want {
			t.Errorf("QueryFor(%q, %q) = %q; want %q", c.tld, c.domain, got, c.want)
		}
	}
}

// TestQuirkTableIsWellFormed keeps the table honest: an entry with a format
// string that drops the domain would query the wrong thing, and one with no
// explanation cannot be maintained.
func TestQuirkTableIsWellFormed(t *testing.T) {
	for _, tld := range QuirkTLDs() {
		q, _ := QuirkFor(tld)
		if q.QueryFormat != "" && !strings.Contains(q.QueryFormat, "%s") {
			t.Errorf("quirk %q: QueryFormat %q has no %%s, so the domain would be dropped", tld, q.QueryFormat)
		}
		if strings.Count(q.QueryFormat, "%s") > 1 {
			t.Errorf("quirk %q: QueryFormat %q has more than one %%s", tld, q.QueryFormat)
		}
		if strings.TrimSpace(q.Why) == "" {
			t.Errorf("quirk %q has no Why; an unexplained workaround cannot be retired safely", tld)
		}
		if tld != normalizeTLD(tld) {
			t.Errorf("quirk key %q is not normalised", tld)
		}
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(strings.ToLower(w), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}
