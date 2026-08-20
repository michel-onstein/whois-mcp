package rdapx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/normalize"
)

// thinRegistryResponse is a registry record with one entity and a rel=related
// link at the registrar, which is the shape gTLD registries actually serve.
func thinRegistryResponse(registrarHref string) []byte {
	doc := map[string]any{
		"objectClassName": "domain",
		"handle":          "REG-1",
		"ldhName":         "example.com",
		"status":          []string{"active"},
		"events": []map[string]any{
			{"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
		},
		"entities": []map[string]any{
			{"objectClassName": "entity", "handle": "REGISTRAR-1", "roles": []string{"registrar"}},
		},
		"links": []map[string]any{
			{"rel": "self", "href": "https://registry.invalid/domain/example.com", "type": "application/rdap+json"},
			{"rel": "related", "href": "https://terms.invalid/tos.html", "type": "text/html"},
			{"rel": "related", "href": registrarHref, "type": "application/rdap+json"},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

// thickRegistrarResponse carries the contacts the registry withheld.
func thickRegistrarResponse() []byte {
	doc := map[string]any{
		"objectClassName": "domain",
		"handle":          "REG-1",
		"ldhName":         "example.com",
		"entities": []map[string]any{
			{"objectClassName": "entity", "handle": "REGISTRAR-1", "roles": []string{"registrar"}},
			{"objectClassName": "entity", "handle": "REGISTRANT-1", "roles": []string{"registrant"}},
			{"objectClassName": "entity", "handle": "TECH-1", "roles": []string{"technical"}},
		},
		"nameservers": []map[string]any{
			{"objectClassName": "nameserver", "ldhName": "ns1.example-dns.test"},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

func rdapHandler(body []byte, hits *int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}
}

// TestFollowsRegistrarReferral is the M1.8 happy path: the thick contacts held
// at the registrar must reach the report.
func TestFollowsRegistrarReferral(t *testing.T) {
	var registrarHits int
	registrar := httptest.NewTLSServer(rdapHandler(thickRegistrarResponse(), &registrarHits))
	defer registrar.Close()

	registry := httptest.NewServer(rdapHandler(thinRegistryResponse(registrar.URL+"/domain/example.com"), nil))
	defer registry.Close()

	c := registrarTestClient(t, testRegistry("com", registry.URL), registrar.Client())
	res, err := c.Query(context.Background(), query("example.com", "com"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Registered != normalize.Yes {
		t.Fatalf("Registered = %q; want yes", res.Registered)
	}
	if registrarHits != 1 {
		t.Errorf("registrar was hit %d times; want exactly 1 (design caps the chain at one hop)", registrarHits)
	}
	if len(res.Domain.Entities) != 3 {
		t.Errorf("Entities = %d; want the registrar's 3, not the registry's 1", len(res.Domain.Entities))
	}
	if len(res.Servers) != 2 {
		t.Errorf("Servers = %v; want both the registry and the registrar", res.Servers)
	}
	// The registry had an event; the registrar's absence of one must not erase it.
	if len(res.Domain.Events) == 0 {
		t.Error("registry events were lost in the merge")
	}
}

// TestRegistrarReferralFailureDegrades is design 8.3's rule: a dead registrar
// yields registry data plus a warning, never a failed lookup.
func TestRegistrarReferralFailureDegrades(t *testing.T) {
	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	deadURL := dead.URL
	dead.Close() // nothing listening now

	registry := httptest.NewServer(rdapHandler(thinRegistryResponse(deadURL+"/domain/example.com"), nil))
	defer registry.Close()

	c := testClient(t, testRegistry("com", registry.URL))
	res, err := c.Query(context.Background(), query("example.com", "com"))
	if err != nil {
		t.Fatalf("a failed registrar referral must not fail the lookup: %v", err)
	}
	if res.Registered != normalize.Yes {
		t.Errorf("Registered = %q; want yes from the registry data", res.Registered)
	}
	if len(res.Domain.Entities) != 1 {
		t.Errorf("Entities = %d; want the registry's 1 preserved", len(res.Domain.Entities))
	}
	if !hasWarning(res.Warnings, "registrar referral") {
		t.Errorf("warnings = %v; want one naming the failed referral", res.Warnings)
	}
}

// TestRefusesCleartextRegistrarReferral covers a hostile or misconfigured
// referral: the href is third-party input and http would expose the query.
func TestRefusesCleartextRegistrarReferral(t *testing.T) {
	registry := httptest.NewServer(rdapHandler(thinRegistryResponse("http://insecure.invalid/domain/example.com"), nil))
	defer registry.Close()

	c := testClient(t, testRegistry("com", registry.URL))
	res, err := c.Query(context.Background(), query("example.com", "com"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !hasWarning(res.Warnings, "non-https") {
		t.Errorf("warnings = %v; want a refusal of the cleartext referral", res.Warnings)
	}
	if len(res.Servers) != 1 {
		t.Errorf("Servers = %v; the cleartext referral must not be recorded as consulted", res.Servers)
	}
}

func TestRegistrarFollowCanBeDisabled(t *testing.T) {
	var registrarHits int
	registrar := httptest.NewTLSServer(rdapHandler(thickRegistrarResponse(), &registrarHits))
	defer registrar.Close()
	registry := httptest.NewServer(rdapHandler(thinRegistryResponse(registrar.URL+"/domain/example.com"), nil))
	defer registry.Close()

	hc := NewHTTPClientWithOptions(5*time.Second, HTTPClientOptions{AllowPrivateAddresses: true})
	c := NewClientWithOptions(testRegistry("com", registry.URL), hc, "test", ClientOptions{FollowRegistrar: false})

	if _, err := c.Query(context.Background(), query("example.com", "com")); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if registrarHits != 0 {
		t.Errorf("registrar was hit %d times with following disabled", registrarHits)
	}
}

func TestRegistrarLinkSelection(t *testing.T) {
	// Only the rel=related link with the RDAP media type may be followed: a
	// rel=related terms-of-service page would waste the single hop.
	body := thinRegistryResponse("https://registrar.invalid/domain/example.com")
	if !strings.Contains(string(body), "tos.html") {
		t.Fatal("fixture should contain a decoy html related link")
	}
	registry := httptest.NewServer(rdapHandler(body, nil))
	defer registry.Close()

	c := testClient(t, testRegistry("com", registry.URL))
	res, err := c.Query(context.Background(), query("example.com", "com"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// registrar.invalid does not resolve, so the hop fails — but the warning
	// must name the RDAP host, proving the html decoy was not chosen.
	if !hasWarning(res.Warnings, "registrar.invalid") {
		t.Errorf("warnings = %v; want the RDAP-typed link to have been selected", res.Warnings)
	}
	if hasWarning(res.Warnings, "terms.invalid") {
		t.Errorf("the text/html related link was followed: %v", res.Warnings)
	}
}

// registrarTestClient builds a client whose HTTP transport trusts the test TLS
// server's certificate, which is the only way to exercise the https-only rule
// against a local server.
func registrarTestClient(t *testing.T, reg *Registry, tlsClient *http.Client) *Client {
	t.Helper()
	hc := NewHTTPClientWithOptions(5*time.Second, HTTPClientOptions{AllowPrivateAddresses: true})
	if tr, ok := tlsClient.Transport.(*http.Transport); ok {
		if lt, ok := hc.Transport.(*limitTransport); ok {
			if base, ok := lt.base.(*http.Transport); ok {
				base.TLSClientConfig = tr.TLSClientConfig
			}
		}
	}
	return NewClient(reg, hc, "whois-mcp-test")
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(strings.ToLower(w), strings.ToLower(substr)) {
			return true
		}
	}
	return false
}
