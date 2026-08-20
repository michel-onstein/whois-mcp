// Package rdapx wraps RDAP: the IANA bootstrap registry, an SSRF-guarded HTTP
// client, and query execution with tri-state availability classification.
// See docs/MCP_DESIGN.md §8.2 and §8.3.
package rdapx

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// embeddedBootstrap is a snapshot of https://data.iana.org/rdap/dns.json baked
// into the binary so that a cold start with no egress to data.iana.org still
// resolves every major TLD. Refresh it periodically; staleness is reported by
// Registry.Age, never treated as fatal.
//
//go:embed data/dns.json
var embeddedBootstrap []byte

// BootstrapURL is the IANA-published RDAP bootstrap file for domain names
// (RFC 9224).
const BootstrapURL = "https://data.iana.org/rdap/dns.json"

// bootstrapDoc is the on-the-wire shape of dns.json. Each service is a
// two-element array: a list of TLDs, then a list of RDAP base URLs.
type bootstrapDoc struct {
	Version     string       `json:"version"`
	Publication time.Time    `json:"publication"`
	Services    [][][]string `json:"services"`
}

// Registry maps a TLD to the RDAP base URLs that serve it.
//
// It is safe for concurrent use. Reads never block on a refresh, and a failed
// refresh leaves the previous (or embedded) data in place — stale bootstrap
// data is far better than no bootstrap data.
type Registry struct {
	mu          sync.RWMutex
	byTLD       map[string][]string
	publication time.Time
	loadedAt    time.Time
	etag        string
	fromNetwork bool

	now func() time.Time
}

// NewRegistry returns a Registry preloaded from the embedded snapshot.
// Call Refresh to fetch current data from IANA.
func NewRegistry() (*Registry, error) {
	r := &Registry{now: time.Now}
	if err := r.load(embeddedBootstrap, ""); err != nil {
		return nil, fmt.Errorf("loading embedded bootstrap: %w", err)
	}
	r.fromNetwork = false
	return r, nil
}

func (r *Registry) load(raw []byte, etag string) error {
	var doc bootstrapDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing bootstrap document: %w", err)
	}
	if len(doc.Services) == 0 {
		return fmt.Errorf("bootstrap document contains no services")
	}

	byTLD := make(map[string][]string, 1500)
	for _, svc := range doc.Services {
		if len(svc) != 2 {
			continue // malformed entry; skip rather than fail the whole document
		}
		tlds, urls := svc[0], svc[1]
		secure := preferHTTPS(urls)
		if len(secure) == 0 {
			// Every URL was cleartext. We do not query RDAP over plain HTTP;
			// such TLDs fall through to the WHOIS path instead.
			continue
		}
		for _, tld := range tlds {
			t := strings.ToLower(strings.TrimSpace(tld))
			if t == "" {
				continue
			}
			byTLD[t] = secure
		}
	}
	if len(byTLD) == 0 {
		return fmt.Errorf("bootstrap document yielded no usable TLDs")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.byTLD = byTLD
	r.publication = doc.Publication
	r.loadedAt = r.now()
	r.etag = etag
	return nil
}

// preferHTTPS keeps only https base URLs, normalising each to end with "/" as
// RFC 9224 requires for concatenation.
func preferHTTPS(urls []string) []string {
	var out []string
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if !strings.HasPrefix(strings.ToLower(u), "https://") {
			continue
		}
		if !strings.HasSuffix(u, "/") {
			u += "/"
		}
		out = append(out, u)
	}
	return out
}

// Lookup returns the RDAP base URLs serving a TLD. The TLD must be the last
// label, lowercase and in A-label form (for example "com" or "xn--p1ai"),
// which is how IANA keys the bootstrap file.
func (r *Registry) Lookup(tld string) ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	urls, ok := r.byTLD[strings.ToLower(tld)]
	return urls, ok && len(urls) > 0
}

// Publication reports the bootstrap file's own publication timestamp.
func (r *Registry) Publication() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.publication
}

// FromNetwork reports whether the current data came from IANA (true) or from
// the embedded snapshot (false).
func (r *Registry) FromNetwork() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fromNetwork
}

// Age reports how long ago the current data was loaded.
func (r *Registry) Age() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.now().Sub(r.loadedAt)
}

// Count reports how many TLDs have a usable RDAP service.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byTLD)
}

// TLDs returns every TLD with RDAP coverage, sorted.
func (r *Registry) TLDs() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.byTLD))
	for t := range r.byTLD {
		out = append(out, t)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Refresh fetches the bootstrap file from IANA and replaces the in-memory data
// on success. It uses If-None-Match, so an unchanged document costs a 304 and
// leaves the registry untouched.
//
// A refresh failure is returned for logging but is not fatal to the caller:
// the previous data remains in place.
func (r *Registry) Refresh(ctx context.Context, hc *http.Client, url string) error {
	if url == "" {
		url = BootstrapURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	r.mu.RLock()
	etag := r.etag
	r.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		r.mu.Lock()
		r.loadedAt = r.now()
		r.mu.Unlock()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching %s: unexpected status %s", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("reading %s: %w", url, err)
	}
	if err := r.load(body, resp.Header.Get("ETag")); err != nil {
		return err
	}
	r.mu.Lock()
	r.fromNetwork = true
	r.mu.Unlock()
	return nil
}

// NewRegistryForTest builds a Registry directly from a TLD-to-URL map,
// bypassing both the embedded snapshot and the https-only policy that load()
// enforces. It exists so tests can point at an httptest server; production
// code must use NewRegistry.
func NewRegistryForTest(byTLD map[string][]string) (*Registry, error) {
	if len(byTLD) == 0 {
		return nil, fmt.Errorf("no TLDs supplied")
	}
	m := make(map[string][]string, len(byTLD))
	for k, v := range byTLD {
		m[strings.ToLower(k)] = v
	}
	return &Registry{byTLD: m, now: time.Now, loadedAt: time.Now()}, nil
}
