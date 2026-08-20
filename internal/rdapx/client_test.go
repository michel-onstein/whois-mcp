package rdapx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/normalize"
)

// testRegistry points a TLD at a fake server. It writes byTLD directly rather
// than going through load(), because load() enforces the https-only policy
// that is tested separately in bootstrap_test.go.
func testRegistry(tld, baseURL string) *Registry {
	return &Registry{
		byTLD: map[string][]string{tld: {strings.TrimSuffix(baseURL, "/") + "/"}},
		now:   time.Now,
	}
}

func testClient(t *testing.T, reg *Registry) *Client {
	t.Helper()
	hc := NewHTTPClientWithOptions(5*time.Second, HTTPClientOptions{AllowPrivateAddresses: true})
	return NewClient(reg, hc, "whois-mcp-test")
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rdap", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

func query(ascii, tld string) normalize.Query {
	return normalize.Query{Input: ascii, RegistrableDomain: ascii, ASCII: ascii, TLD: tld, PublicSuffix: tld}
}

func TestQueryRegistered(t *testing.T) {
	body := fixture(t, "com-registered.json")
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := testClient(t, testRegistry("com", srv.URL))
	res, err := c.Query(context.Background(), query("example.com", "com"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Registered != normalize.Yes {
		t.Errorf("Registered = %q, want yes", res.Registered)
	}
	if res.Domain == nil {
		t.Fatal("Domain is nil for a registered domain")
	}
	if !strings.Contains(gotPath, "domain/example.com") {
		t.Errorf("requested path %q; want it to contain domain/example.com", gotPath)
	}
	if len(res.Raw) == 0 {
		t.Error("raw body not captured")
	}
	if len(res.Servers) != 1 {
		t.Errorf("Servers = %v; want exactly the one endpoint consulted", res.Servers)
	}
}

// A 404 carrying a proper RDAP error body is the one case allowed to become a
// confident "no".
func TestQueryNotFoundIsNo(t *testing.T) {
	body := fixture(t, "org-notfound.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c := testClient(t, testRegistry("org", srv.URL))
	res, err := c.Query(context.Background(), query("nx.org", "org"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Registered != normalize.No {
		t.Errorf("Registered = %q, want no", res.Registered)
	}
}

// Anything ambiguous must be unknown. Reporting "no" here would tell a user a
// taken domain is available — the worst failure this server has.
func TestQueryAmbiguousIsUnknown(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"500": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		},
		"403": func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "blocked", http.StatusForbidden)
		},
		"429": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "slow down", http.StatusTooManyRequests)
		},
		"html error page": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>nope</body></html>"))
		},
		"empty 200": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/rdap+json")
		},
		"garbage json": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{"objectClassName":`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()

			c := testClient(t, testRegistry("com", srv.URL))
			res, err := c.Query(context.Background(), query("example.com", "com"))
			if err != nil {
				t.Fatalf("Query returned a hard error: %v", err)
			}
			if res.Registered != normalize.Unknown {
				t.Errorf("Registered = %q, want unknown for %s", res.Registered, name)
			}
			if len(res.Warnings) == 0 {
				t.Error("no warning recorded for an ambiguous result")
			}
		})
	}
}

func TestQueryNoServiceForTLD(t *testing.T) {
	c := testClient(t, testRegistry("com", "https://example.invalid"))
	_, err := c.Query(context.Background(), query("example.de", "de"))
	if !errors.Is(err, ErrNoRDAPService) {
		t.Fatalf("err = %v, want ErrNoRDAPService", err)
	}
}

func TestQueryRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	c := testClient(t, testRegistry("com", srv.URL))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.Query(ctx, query("example.com", "com"))
	if err == nil {
		t.Fatal("expected a context error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("query took %v; context deadline was not honoured", elapsed)
	}
}

// A registry publishing several endpoints should survive one being dead.
func TestQueryFallsBackToSecondEndpoint(t *testing.T) {
	body := fixture(t, "com-registered.json")
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer dead.Close()
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer live.Close()

	reg := &Registry{
		byTLD: map[string][]string{"com": {dead.URL + "/", live.URL + "/"}},
		now:   time.Now,
	}
	c := testClient(t, reg)
	res, err := c.Query(context.Background(), query("example.com", "com"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Registered != normalize.Yes {
		t.Errorf("Registered = %q; want yes via the second endpoint", res.Registered)
	}
	if len(res.Servers) != 2 {
		t.Errorf("Servers = %v; want both endpoints recorded", res.Servers)
	}
}
