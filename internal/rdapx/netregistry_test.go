package rdapx

import (
	"net"
	"strings"
	"testing"
)

func testNetRegistry(t *testing.T) *NetRegistry {
	t.Helper()
	r, err := NewNetRegistry()
	if err != nil {
		t.Fatalf("NewNetRegistry: %v", err)
	}
	return r
}

// TestEmbeddedBootstrapIsUsable runs against the real IANA snapshots in
// data/, so a corrupted or truncated file fails here rather than at the first
// lookup in production.
func TestEmbeddedBootstrapIsUsable(t *testing.T) {
	r := testNetRegistry(t)
	v4, v6, asn := r.Counts()

	// Sanity floors rather than exact counts: the files are refreshed, so
	// pinning exact numbers would make every refresh a test failure.
	if v4 < 50 {
		t.Errorf("ipv4 prefixes = %d; the snapshot looks truncated", v4)
	}
	if v6 < 10 {
		t.Errorf("ipv6 prefixes = %d; the snapshot looks truncated", v6)
	}
	if asn < 100 {
		t.Errorf("asn ranges = %d; the snapshot looks truncated", asn)
	}
	if r.Publication().IsZero() {
		t.Error("no publication timestamp")
	}
	if r.FromNetwork() {
		t.Error("FromNetwork is true for the embedded snapshot")
	}
}

// TestLookupIPFindsARealRIR checks addresses whose RIR is stable and public
// knowledge. Deliberately not asserting *which* RIR beyond the fact that one
// answered with an https base: allocations do transfer between registries, and a
// test that pinned ARIN for a given /8 would eventually fail for a correct
// reason.
func TestLookupIPFindsARealRIR(t *testing.T) {
	r := testNetRegistry(t)
	cases := []string{
		"8.8.8.8",              // Google DNS, v4
		"1.1.1.1",              // Cloudflare, v4
		"193.0.6.139",          // RIPE NCC, v4
		"2001:4860:4860::8888", // Google DNS, v6
		"2606:4700:4700::1111", // Cloudflare, v6
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			ip := net.ParseIP(s)
			if ip == nil {
				t.Fatalf("test data %q is not an IP", s)
			}
			bases, ok := r.LookupIP(ip)
			if !ok {
				t.Fatalf("no RDAP service found for %s", s)
			}
			if len(bases) == 0 {
				t.Fatal("lookup succeeded with no base URLs")
			}
			for _, b := range bases {
				if !strings.HasPrefix(b, "https://") {
					t.Errorf("base %q is not https; we do not query RDAP over cleartext", b)
				}
			}
		})
	}
}

// TestLookupIPPrefersMostSpecific is the property that matters. IANA publishes
// overlapping entries — a /8 held by one RIR can contain a smaller range
// transferred to another — and answering from the broader one returns the wrong
// registry's data while looking like a correct answer.
func TestLookupIPPrefersMostSpecific(t *testing.T) {
	r := &NetRegistry{now: testNetRegistry(t).now}
	_, broad, _ := net.ParseCIDR("10.0.0.0/8")
	_, narrow, _ := net.ParseCIDR("10.1.0.0/16")
	r.v4 = []netService{
		{prefixes: []*net.IPNet{broad}, bases: []string{"https://broad.example/"}},
		{prefixes: []*net.IPNet{narrow}, bases: []string{"https://narrow.example/"}},
	}

	bases, ok := r.LookupIP(net.ParseIP("10.1.2.3"))
	if !ok {
		t.Fatal("no match inside both prefixes")
	}
	if bases[0] != "https://narrow.example/" {
		t.Errorf("got %v; want the /16, not the enclosing /8", bases)
	}

	// An address only in the broader range still resolves to it.
	bases, ok = r.LookupIP(net.ParseIP("10.9.9.9"))
	if !ok || bases[0] != "https://broad.example/" {
		t.Errorf("got %v %v; want the /8", bases, ok)
	}
}

// TestLookupIPCoversPrivateSpace records something surprising about the real
// data, because it drove a design decision.
//
// IANA's bootstrap file does not carve private ranges out of the RIR
// allocations it lists: 192.168.1.1 falls inside a broader ARIN entry, so the
// registry cheerfully returns a service for it. The registry is not wrong — it
// answers "which RIR administers this range" — so the filtering belongs in the
// query path, which is where QueryResource refuses it before spending an
// upstream request.
func TestLookupIPCoversPrivateSpace(t *testing.T) {
	r := testNetRegistry(t)
	if _, ok := r.LookupIP(net.ParseIP("192.168.1.1")); !ok {
		t.Skip("IANA no longer covers private space in a broader entry; the query-path filter is now the only guard")
	}
}

func TestLookupIPUnknownSpace(t *testing.T) {
	r := testNetRegistry(t)
	if _, ok := r.LookupIP(nil); ok {
		t.Error("LookupIP(nil) reported success")
	}
	// 0.0.0.0/8 is "this network" and no RIR administers it.
	if _, ok := r.LookupIP(net.ParseIP("0.0.0.1")); ok {
		t.Error("LookupIP found a service for 0.0.0.0/8")
	}
}

func TestLookupASNFindsARealRIR(t *testing.T) {
	r := testNetRegistry(t)
	// Well-known, long-standing ASNs.
	for _, asn := range []uint32{15169 /* Google */, 13335 /* Cloudflare */, 3333 /* RIPE NCC */, 1 /* Level3 */} {
		bases, ok := r.LookupASN(asn)
		if !ok {
			t.Errorf("no RDAP service for AS%d", asn)
			continue
		}
		if len(bases) == 0 || !strings.HasPrefix(bases[0], "https://") {
			t.Errorf("AS%d: bases = %v", asn, bases)
		}
	}
}

func TestLookupASNBoundaries(t *testing.T) {
	r := &NetRegistry{now: testNetRegistry(t).now}
	r.asns = []asnRange{
		{lo: 100, hi: 200, bases: []string{"https://a.example/"}},
		{lo: 300, hi: 300, bases: []string{"https://b.example/"}},
	}

	cases := map[uint32]string{
		100: "https://a.example/", // inclusive low
		150: "https://a.example/",
		200: "https://a.example/", // inclusive high
		300: "https://b.example/", // single-value range
	}
	for asn, want := range cases {
		bases, ok := r.LookupASN(asn)
		if !ok || bases[0] != want {
			t.Errorf("AS%d = %v %v; want %s", asn, bases, ok, want)
		}
	}
	for _, asn := range []uint32{99, 201, 299, 301} {
		if _, ok := r.LookupASN(asn); ok {
			t.Errorf("AS%d matched a range it is outside", asn)
		}
	}
}

func TestParseASNRange(t *testing.T) {
	cases := []struct {
		in     string
		lo, hi uint32
		ok     bool
	}{
		{in: "64496", lo: 64496, hi: 64496, ok: true},
		{in: "64496-64511", lo: 64496, hi: 64511, ok: true},
		{in: " 64496 - 64511 ", lo: 64496, hi: 64511, ok: true},
		{in: "4200000000", lo: 4200000000, hi: 4200000000, ok: true},
		{in: "", ok: false},
		{in: "abc", ok: false},
		{in: "100-abc", ok: false},
		// An inverted range is malformed; accepting it would create a range
		// that matches nothing while looking valid.
		{in: "200-100", ok: false},
		{in: "99999999999", ok: false}, // beyond uint32
	}
	for _, c := range cases {
		lo, hi, ok := parseASNRange(c.in)
		if ok != c.ok {
			t.Errorf("parseASNRange(%q) ok = %v; want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (lo != c.lo || hi != c.hi) {
			t.Errorf("parseASNRange(%q) = %d-%d; want %d-%d", c.in, lo, hi, c.lo, c.hi)
		}
	}
}

func TestParseResource(t *testing.T) {
	cases := []struct {
		in         string
		kind       ResourceKind
		normalized string
	}{
		{in: "8.8.8.8", kind: KindIP, normalized: "8.8.8.8"},
		{in: " 8.8.8.8 ", kind: KindIP, normalized: "8.8.8.8"},
		{in: "2001:4860:4860::8888", kind: KindIP, normalized: "2001:4860:4860::8888"},
		{in: "8.8.8.0/24", kind: KindPrefix, normalized: "8.8.8.0/24"},
		{in: "2001:4860::/32", kind: KindPrefix, normalized: "2001:4860::/32"},
		{in: "AS15169", kind: KindASN, normalized: "AS15169"},
		{in: "as15169", kind: KindASN, normalized: "AS15169"},
		{in: "15169", kind: KindASN, normalized: "AS15169"},
		{in: " AS15169 ", kind: KindASN, normalized: "AS15169"},
	}
	for _, c := range cases {
		got, err := ParseResource(c.in)
		if err != nil {
			t.Errorf("ParseResource(%q): %v", c.in, err)
			continue
		}
		if got.Kind != c.kind {
			t.Errorf("ParseResource(%q).Kind = %q; want %q", c.in, got.Kind, c.kind)
		}
		if got.String() != c.normalized {
			t.Errorf("ParseResource(%q).String() = %q; want %q", c.in, got.String(), c.normalized)
		}
		if got.Input != c.in {
			t.Errorf("Input not echoed: %q", got.Input)
		}
	}
}

func TestParseResourceRejectsJunk(t *testing.T) {
	for _, s := range []string{
		"", "   ", "example.com", "not an address",
		"999.999.999.999", "8.8.8.8/99", "AS", "ASfoo", "-1",
		"8.8.8.8:80",
	} {
		if got, err := ParseResource(s); err == nil {
			t.Errorf("ParseResource(%q) accepted as %s", s, got.Kind)
		}
	}
}

// TestParseResourceASNvsAddressIsUnambiguous: a bare number can only be an ASN,
// and a dotted or colonned string can only be an address, so there is no
// heuristic to get wrong.
func TestParseResourceASNvsAddressIsUnambiguous(t *testing.T) {
	asn, err := ParseResource("13335")
	if err != nil || asn.Kind != KindASN || asn.ASN != 13335 {
		t.Errorf("bare number = %+v %v; want ASN 13335", asn, err)
	}
	ip, err := ParseResource("13.33.5.1")
	if err != nil || ip.Kind != KindIP {
		t.Errorf("dotted quad = %+v %v; want an IP", ip, err)
	}
}
