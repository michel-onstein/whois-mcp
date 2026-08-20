package rdapx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEmbeddedBootstrapLoads(t *testing.T) {
	r, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if r.Count() < 1000 {
		t.Errorf("only %d TLDs loaded; the embedded snapshot looks wrong", r.Count())
	}
	if r.FromNetwork() {
		t.Error("FromNetwork = true before any refresh")
	}
	if r.Publication().IsZero() {
		t.Error("publication timestamp not parsed")
	}

	for _, tld := range []string{"com", "org", "net", "dev", "uk"} {
		urls, ok := r.Lookup(tld)
		if !ok || len(urls) == 0 {
			t.Errorf("no RDAP base URL for .%s", tld)
			continue
		}
		for _, u := range urls {
			if len(u) < 9 || u[:8] != "https://" {
				t.Errorf(".%s base URL %q is not https", tld, u)
			}
			if u[len(u)-1] != '/' {
				t.Errorf(".%s base URL %q does not end in /", tld, u)
			}
		}
	}

	// ccTLDs without RDAP must report absence, not a wrong answer. These are
	// exactly the TLDs the WHOIS fallback exists for.
	for _, tld := range []string{"de", "jp", "io"} {
		if _, ok := r.Lookup(tld); ok {
			t.Logf("note: .%s now has RDAP coverage; fixture may be outdated", tld)
		}
	}

	if _, ok := r.Lookup("definitelynotatld"); ok {
		t.Error("unknown TLD resolved to a service")
	}
}

func TestLookupIsCaseInsensitive(t *testing.T) {
	r, _ := NewRegistry()
	a, okA := r.Lookup("COM")
	b, okB := r.Lookup("com")
	if !okA || !okB || len(a) != len(b) {
		t.Errorf("case-insensitive lookup failed: %v/%v vs %v/%v", a, okA, b, okB)
	}
}

func TestHTTPOnlyServicesAreExcluded(t *testing.T) {
	r := &Registry{now: time.Now}
	doc := `{"version":"1.0","publication":"2026-07-23T02:00:03Z","services":[
	  [["good"],["https://rdap.example/"]],
	  [["cleartext"],["http://rdap.example/"]]
	]}`
	if err := r.load([]byte(doc), ""); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := r.Lookup("good"); !ok {
		t.Error("https service was dropped")
	}
	if _, ok := r.Lookup("cleartext"); ok {
		t.Error("http-only service was accepted; RDAP must not be queried in cleartext")
	}
}

func TestLoadRejectsUnusableDocuments(t *testing.T) {
	r := &Registry{now: time.Now}
	for name, doc := range map[string]string{
		"not json":      `{`,
		"no services":   `{"version":"1.0","services":[]}`,
		"all cleartext": `{"version":"1.0","services":[[["x"],["http://a/"]]]}`,
	} {
		if err := r.load([]byte(doc), ""); err == nil {
			t.Errorf("%s: load succeeded; want error", name)
		}
	}
}

func TestRefreshReplacesDataAndHonoursETag(t *testing.T) {
	const etag = `"v1"`
	var hits, conditional int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits++
		if req.Header.Get("If-None-Match") == etag {
			conditional++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.0","publication":"2026-08-01T00:00:00Z","services":[[["zzz"],["https://rdap.example/"]]]}`))
	}))
	defer srv.Close()

	r, _ := NewRegistry()
	hc := NewHTTPClientWithOptions(5*time.Second, HTTPClientOptions{AllowPrivateAddresses: true})

	if err := r.Refresh(context.Background(), hc, srv.URL); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if _, ok := r.Lookup("zzz"); !ok {
		t.Error("refreshed data not applied")
	}
	if !r.FromNetwork() {
		t.Error("FromNetwork = false after a successful refresh")
	}

	if err := r.Refresh(context.Background(), hc, srv.URL); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if conditional != 1 {
		t.Errorf("conditional requests = %d; want 1 (If-None-Match not sent)", conditional)
	}
}

// A failed refresh must leave the previous data intact: stale bootstrap data
// is far more useful than none.
func TestRefreshFailureKeepsExistingData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	r, _ := NewRegistry()
	before := r.Count()
	hc := NewHTTPClientWithOptions(5*time.Second, HTTPClientOptions{AllowPrivateAddresses: true})

	if err := r.Refresh(context.Background(), hc, srv.URL); err == nil {
		t.Fatal("refresh against a 500 returned nil error")
	}
	if r.Count() != before {
		t.Errorf("count changed after failed refresh: %d -> %d", before, r.Count())
	}
	if _, ok := r.Lookup("com"); !ok {
		t.Error(".com lookup broken after a failed refresh")
	}
}
