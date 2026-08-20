package resolve

import (
	"errors"
	"testing"
)

func TestNormalizeQuery(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantASCII  string
		wantUni    string
		wantTLD    string
		wantSuffix string
	}{
		{"plain", "example.com", "example.com", "example.com", "com", "com"},
		{"uppercase", "EXAMPLE.COM", "example.com", "example.com", "com", "com"},
		{"trailing dot", "example.com.", "example.com", "example.com", "com", "com"},
		{"url with path", "https://example.com/a/b?q=1#f", "example.com", "example.com", "com", "com"},
		{"url with port", "http://example.com:8443/x", "example.com", "example.com", "com", "com"},
		{"userinfo", "http://user:pw@example.com/", "example.com", "example.com", "com", "com"},
		{"subdomain reduced", "www.example.com", "example.com", "example.com", "com", "com"},
		{"deep subdomain", "a.b.c.example.com", "example.com", "example.com", "com", "com"},
		{"multi-label suffix", "foo.example.co.uk", "example.co.uk", "example.co.uk", "uk", "co.uk"},
		{"whitespace", "  example.com  ", "example.com", "example.com", "com", "com"},
		{"idn unicode", "bücher.de", "xn--bcher-kva.de", "bücher.de", "de", "de"},
		{"idn already punycode", "xn--bcher-kva.de", "xn--bcher-kva.de", "bücher.de", "de", "de"},
		{"idn tld", "пример.рф", "xn--e1afmkfd.xn--p1ai", "пример.рф", "xn--p1ai", "рф"},
		{"new gtld", "example.dev", "example.dev", "example.dev", "dev", "dev"},
		// The design's own §7 example: a subdomain under a multi-label ccTLD.
		// The registrable domain is the eTLD+1, so the "bücher" label is dropped.
		{"design example", "https://WWW.Bücher.example.co.uk/path",
			"example.co.uk", "example.co.uk", "uk", "co.uk"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeQuery(tc.in)
			if err != nil {
				t.Fatalf("NormalizeQuery(%q) error: %v", tc.in, err)
			}
			if got.ASCII != tc.wantASCII {
				t.Errorf("ASCII = %q, want %q", got.ASCII, tc.wantASCII)
			}
			if got.RegistrableDomain != tc.wantUni {
				t.Errorf("RegistrableDomain = %q, want %q", got.RegistrableDomain, tc.wantUni)
			}
			if got.TLD != tc.wantTLD {
				t.Errorf("TLD = %q, want %q", got.TLD, tc.wantTLD)
			}
			if got.PublicSuffix != tc.wantSuffix {
				t.Errorf("PublicSuffix = %q, want %q", got.PublicSuffix, tc.wantSuffix)
			}
			if got.Input != tc.in {
				t.Errorf("Input = %q, want the raw input %q", got.Input, tc.in)
			}
		})
	}
}

func TestNormalizeQueryRejects(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		"localhost",    // no public suffix
		"com",          // is a public suffix
		"co.uk",        // is a public suffix
		"exa mple.com", // whitespace inside
		"http:///path", // no host
		"..",           // degenerate
	} {
		t.Run(in, func(t *testing.T) {
			if _, err := NormalizeQuery(in); err == nil {
				t.Fatalf("NormalizeQuery(%q) = nil error; want ErrInvalidDomain", in)
			} else if !errors.Is(err, ErrInvalidDomain) {
				t.Fatalf("error = %v; want ErrInvalidDomain", err)
			}
		})
	}
}
