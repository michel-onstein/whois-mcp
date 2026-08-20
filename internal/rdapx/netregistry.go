package rdapx

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Embedded RFC 9224 bootstrap snapshots for IPs and ASNs, baked in for the same
// reason the domain one is: a cold start with no egress to data.iana.org still
// answers, and the container has no runtime file dependencies.
//
//go:embed data/ipv4.json
var embeddedIPv4 []byte

//go:embed data/ipv6.json
var embeddedIPv6 []byte

//go:embed data/asn.json
var embeddedASN []byte

// Bootstrap URLs for the IP and ASN registries.
const (
	BootstrapIPv4URL = "https://data.iana.org/rdap/ipv4.json"
	BootstrapIPv6URL = "https://data.iana.org/rdap/ipv6.json"
	BootstrapASNURL  = "https://data.iana.org/rdap/asn.json"
)

// ErrNoRDAPForResource means no RIR claims this address or ASN.
var ErrNoRDAPForResource = errors.New("no RDAP service for this resource")

// netService is one bootstrap entry: a set of prefixes and the RDAP bases that
// serve them.
type netService struct {
	prefixes []*net.IPNet
	bases    []string
}

// asnRange is an inclusive ASN range and its RDAP bases.
type asnRange struct {
	lo, hi uint32
	bases  []string
}

// NetRegistry maps IP prefixes and ASNs to the RIR RDAP service that serves
// them.
//
// It is a separate type from Registry rather than a method on it because the
// lookup is genuinely different: a domain is an exact key, while an address
// needs the *most specific* covering prefix. Folding both into one type would
// mean one of the two lookups reading as a special case of the other, which it
// is not.
type NetRegistry struct {
	mu sync.RWMutex

	v4, v6      []netService
	asns        []asnRange
	publication time.Time
	loadedAt    time.Time
	fromNetwork bool

	now func() time.Time
}

// NewNetRegistry returns a registry preloaded from the embedded snapshots.
func NewNetRegistry() (*NetRegistry, error) {
	r := &NetRegistry{now: time.Now}
	if err := r.loadIP(embeddedIPv4, false); err != nil {
		return nil, fmt.Errorf("loading embedded ipv4 bootstrap: %w", err)
	}
	if err := r.loadIP(embeddedIPv6, true); err != nil {
		return nil, fmt.Errorf("loading embedded ipv6 bootstrap: %w", err)
	}
	if err := r.loadASN(embeddedASN); err != nil {
		return nil, fmt.Errorf("loading embedded asn bootstrap: %w", err)
	}
	r.fromNetwork = false
	return r, nil
}

// NewNetRegistryForTest points every family at one base URL, so a test can
// exercise the query path against a local fake without a network.
func NewNetRegistryForTest(base string) (*NetRegistry, error) {
	if base == "" {
		return nil, errors.New("base URL is required")
	}
	_, all4, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return nil, err
	}
	_, all6, err := net.ParseCIDR("::/0")
	if err != nil {
		return nil, err
	}
	now := time.Now
	return &NetRegistry{
		now:         now,
		loadedAt:    now(),
		publication: now(),
		v4:          []netService{{prefixes: []*net.IPNet{all4}, bases: []string{base}}},
		v6:          []netService{{prefixes: []*net.IPNet{all6}, bases: []string{base}}},
		asns:        []asnRange{{lo: 0, hi: ^uint32(0), bases: []string{base}}},
	}, nil
}

func (r *NetRegistry) loadIP(raw []byte, v6 bool) error {
	var doc bootstrapDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing bootstrap document: %w", err)
	}
	out := make([]netService, 0, len(doc.Services))
	for _, svc := range doc.Services {
		if len(svc) != 2 {
			continue // malformed entry; skip rather than fail the document
		}
		bases := preferHTTPS(svc[1])
		if len(bases) == 0 {
			continue // cleartext only; we do not query RDAP over plain HTTP
		}
		var nets []*net.IPNet
		for _, cidr := range svc[0] {
			_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				continue
			}
			nets = append(nets, n)
		}
		if len(nets) > 0 {
			out = append(out, netService{prefixes: nets, bases: bases})
		}
	}
	if len(out) == 0 {
		return errors.New("bootstrap document yielded no usable prefixes")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if v6 {
		r.v6 = out
	} else {
		r.v4 = out
	}
	if doc.Publication.After(r.publication) {
		r.publication = doc.Publication
	}
	r.loadedAt = r.now()
	return nil
}

func (r *NetRegistry) loadASN(raw []byte) error {
	var doc bootstrapDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parsing bootstrap document: %w", err)
	}
	var out []asnRange
	for _, svc := range doc.Services {
		if len(svc) != 2 {
			continue
		}
		bases := preferHTTPS(svc[1])
		if len(bases) == 0 {
			continue
		}
		for _, spec := range svc[0] {
			lo, hi, ok := parseASNRange(spec)
			if !ok {
				continue
			}
			out = append(out, asnRange{lo: lo, hi: hi, bases: bases})
		}
	}
	if len(out) == 0 {
		return errors.New("bootstrap document yielded no usable ASN ranges")
	}
	// Sorted so the lookup can binary-search rather than scan ~1,000 ranges per
	// query.
	sort.Slice(out, func(i, j int) bool { return out[i].lo < out[j].lo })

	r.mu.Lock()
	defer r.mu.Unlock()
	r.asns = out
	if doc.Publication.After(r.publication) {
		r.publication = doc.Publication
	}
	r.loadedAt = r.now()
	return nil
}

// parseASNRange reads "64496" or "64496-64511".
func parseASNRange(spec string) (lo, hi uint32, ok bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return 0, 0, false
	}
	before, after, found := strings.Cut(s, "-")
	l, err := strconv.ParseUint(strings.TrimSpace(before), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if !found {
		return uint32(l), uint32(l), true
	}
	h, err := strconv.ParseUint(strings.TrimSpace(after), 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if h < l {
		return 0, 0, false
	}
	return uint32(l), uint32(h), true
}

// LookupIP returns the RDAP base URLs for an address, most specific first.
//
// "Most specific" is the whole point. IANA publishes overlapping entries — a
// /8 held by one RIR can contain a /16 transferred to another — and answering
// from the broader one returns the wrong registry's data, which looks like a
// correct answer.
func (r *NetRegistry) LookupIP(ip net.IP) ([]string, bool) {
	if ip == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	services := r.v4
	if ip.To4() == nil {
		services = r.v6
	}

	bestOnes := -1
	var best []string
	for _, svc := range services {
		for _, n := range svc.prefixes {
			if !n.Contains(ip) {
				continue
			}
			ones, _ := n.Mask.Size()
			if ones > bestOnes {
				bestOnes, best = ones, svc.bases
			}
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// LookupASN returns the RDAP base URLs for an autonomous system number.
func (r *NetRegistry) LookupASN(asn uint32) ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Binary search for the first range whose low bound exceeds asn, then step
	// back: ranges are disjoint in practice, but scanning backwards a little
	// costs nothing and tolerates an overlap if IANA ever publishes one.
	i := sort.Search(len(r.asns), func(i int) bool { return r.asns[i].lo > asn })
	for j := i - 1; j >= 0 && j >= i-4; j-- {
		if asn >= r.asns[j].lo && asn <= r.asns[j].hi {
			return r.asns[j].bases, true
		}
	}
	return nil, false
}

// Publication reports the newest publication timestamp across the three files.
func (r *NetRegistry) Publication() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.publication
}

// Age reports how long since the data was loaded.
func (r *NetRegistry) Age() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.now().Sub(r.loadedAt)
}

// FromNetwork reports whether the current data came from IANA rather than the
// embedded snapshot.
func (r *NetRegistry) FromNetwork() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fromNetwork
}

// Counts reports how many entries each family holds, for tld_info and metrics.
func (r *NetRegistry) Counts() (v4, v6, asn int) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.v4 {
		v4 += len(s.prefixes)
	}
	for _, s := range r.v6 {
		v6 += len(s.prefixes)
	}
	return v4, v6, len(r.asns)
}

// Refresh fetches all three files. A failure on any one leaves that family's
// previous data in place, because stale bootstrap data is far better than none.
func (r *NetRegistry) Refresh(ctx context.Context, hc *http.Client, ipv4URL, ipv6URL, asnURL string) error {
	var errs []error

	if raw, err := fetchBootstrap(ctx, hc, ipv4URL); err != nil {
		errs = append(errs, fmt.Errorf("ipv4: %w", err))
	} else if err := r.loadIP(raw, false); err != nil {
		errs = append(errs, fmt.Errorf("ipv4: %w", err))
	}
	if raw, err := fetchBootstrap(ctx, hc, ipv6URL); err != nil {
		errs = append(errs, fmt.Errorf("ipv6: %w", err))
	} else if err := r.loadIP(raw, true); err != nil {
		errs = append(errs, fmt.Errorf("ipv6: %w", err))
	}
	if raw, err := fetchBootstrap(ctx, hc, asnURL); err != nil {
		errs = append(errs, fmt.Errorf("asn: %w", err))
	} else if err := r.loadASN(raw); err != nil {
		errs = append(errs, fmt.Errorf("asn: %w", err))
	}

	if len(errs) == 3 {
		return fmt.Errorf("refreshing IP/ASN bootstrap: %w", errors.Join(errs...))
	}
	r.mu.Lock()
	r.fromNetwork = true
	r.mu.Unlock()
	if len(errs) > 0 {
		return fmt.Errorf("partially refreshed IP/ASN bootstrap: %w", errors.Join(errs...))
	}
	return nil
}

// fetchBootstrap retrieves one bootstrap document.
func fetchBootstrap(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	// Capped for the same reason every other upstream read is: a bootstrap file
	// is a few kilobytes, and a server streaming indefinitely must not exhaust us.
	return io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
}
