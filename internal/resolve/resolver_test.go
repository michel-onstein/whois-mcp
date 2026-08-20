package resolve

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rdap", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

// newResolver wires a Resolver to a fake registry serving the given handler
// for the .com TLD.
func newResolver(t *testing.T, h http.HandlerFunc) (*Resolver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	reg, err := rdapx.NewRegistryForTest(map[string][]string{"com": {srv.URL + "/"}})
	if err != nil {
		t.Fatalf("test registry: %v", err)
	}
	hc := rdapx.NewHTTPClientWithOptions(5*time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	return New(rdapx.NewClient(reg, hc, "test"), cache.NewMemory(), quietLog()), srv
}

func TestLookupRegistered(t *testing.T) {
	body := fixture(t, "com-registered.json")
	r, _ := newResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	})

	rep, err := r.Lookup(context.Background(), "  HTTPS://WWW.Example.COM/path  ", Options{IncludeContacts: true})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.Yes {
		t.Errorf("Registered = %q, want yes", rep.Registered)
	}
	if rep.Query.ASCII != "example.com" {
		t.Errorf("ASCII = %q; messy input was not normalized", rep.Query.ASCII)
	}
	if rep.Source.Cache != "miss" {
		t.Errorf("Cache = %q, want miss on first lookup", rep.Source.Cache)
	}
	if rep.Dates.Created == nil {
		t.Error("Created not populated")
	}
}

func TestLookupInvalidDomain(t *testing.T) {
	r, _ := newResolver(t, func(w http.ResponseWriter, _ *http.Request) {})
	if _, err := r.Lookup(context.Background(), "not a domain", Options{}); err == nil {
		t.Fatal("expected an error for invalid input")
	}
}

// A second lookup within MaxAge must not touch the upstream.
func TestLookupUsesCache(t *testing.T) {
	body := fixture(t, "com-registered.json")
	var hits int64
	r, _ := newResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	})

	opt := Options{MaxAge: time.Hour, IncludeContacts: true}
	if _, err := r.Lookup(context.Background(), "example.com", opt); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	rep, err := r.Lookup(context.Background(), "example.com", opt)
	if err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (cache not used)", got)
	}
	if rep.Source.Cache != "hit" {
		t.Errorf("Cache = %q, want hit", rep.Source.Cache)
	}
}

// MaxAge of zero must bypass the cache, so an agent can re-check immediately
// after a registration.
func TestLookupMaxAgeZeroBypassesCache(t *testing.T) {
	body := fixture(t, "com-registered.json")
	var hits int64
	r, _ := newResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	})

	for i := 0; i < 2; i++ {
		if _, err := r.Lookup(context.Background(), "example.com", Options{MaxAge: 0}); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Errorf("upstream hits = %d, want 2 (cache was not bypassed)", got)
	}
}

func TestLookupNotFound(t *testing.T) {
	body := fixture(t, "org-notfound.json")
	r, _ := newResolver(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(body)
	})

	rep, err := r.Lookup(context.Background(), "definitely-not-registered-qjam.com", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rep.Registered != normalize.No {
		t.Errorf("Registered = %q, want no", rep.Registered)
	}
}

// A TLD with no RDAP service is an answer ("I cannot determine this"), not a
// tool failure — an agent can act on the former.
func TestLookupTLDWithoutRDAPIsUnknownNotError(t *testing.T) {
	r, _ := newResolver(t, func(w http.ResponseWriter, _ *http.Request) {})

	rep, err := r.Lookup(context.Background(), "example.de", Options{})
	if err != nil {
		t.Fatalf("Lookup returned an error instead of an unknown report: %v", err)
	}
	if rep.Registered != normalize.Unknown {
		t.Errorf("Registered = %q, want unknown", rep.Registered)
	}
	if len(rep.Warnings) == 0 || !strings.Contains(strings.Join(rep.Warnings, " "), "WHOIS") {
		t.Errorf("warnings = %v; want one explaining the missing WHOIS fallback", rep.Warnings)
	}
}

func TestLookupContactsSuppressed(t *testing.T) {
	body := fixture(t, "uk-registered.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	reg, _ := rdapx.NewRegistryForTest(map[string][]string{"uk": {srv.URL + "/"}})
	hc := rdapx.NewHTTPClientWithOptions(5*time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	r := New(rdapx.NewClient(reg, hc, "test"), cache.NewMemory(), quietLog())

	with, err := r.Lookup(context.Background(), "nominet.uk", Options{IncludeContacts: true, MaxAge: 0})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(with.Entities) == 0 {
		t.Fatal("expected entities when IncludeContacts is true")
	}
	without, err := r.Lookup(context.Background(), "nominet.uk", Options{IncludeContacts: false, MaxAge: 0})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(without.Entities) != 0 {
		t.Errorf("entities returned despite IncludeContacts=false: %+v", without.Entities)
	}
}
