// Package resolve orchestrates a lookup: normalize the caller's input, consult
// the bootstrap registry, query RDAP, fall back to WHOIS, and normalize the
// answer. See docs/MCP_DESIGN.md §8.
package resolve

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/qjam/whois-mcp/internal/normalize"
)

// ErrInvalidDomain is returned when the input cannot be interpreted as a
// domain name. Callers surface this as the invalid_domain tool error.
var ErrInvalidDomain = errors.New("invalid domain")

// lookupProfile is IDNA2008, non-transitional, with lookup-time mapping
// (which lowercases and NFC-normalizes). Non-transitional matters: it is what
// keeps German ß and Greek final sigma resolving the way browsers resolve them.
var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
)

// NormalizeQuery turns messy caller input into the exact domain to query.
//
// It accepts URLs, mixed case, trailing dots, ports, userinfo, and Unicode
// IDNs, and reduces the result to the registrable domain (eTLD+1) using the
// Public Suffix List. Without that reduction "foo.example.co.uk" would be
// queried as "co.uk" and every multi-label ccTLD would return nonsense.
func NormalizeQuery(input string) (normalize.Query, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return normalize.Query{}, fmt.Errorf("%w: empty input", ErrInvalidDomain)
	}

	host := hostFromInput(raw)
	if host == "" {
		return normalize.Query{}, fmt.Errorf("%w: no host in %q", ErrInvalidDomain, input)
	}

	ascii, err := lookupProfile.ToASCII(host)
	if err != nil {
		return normalize.Query{}, fmt.Errorf("%w: %q: %v", ErrInvalidDomain, input, err)
	}
	if !strings.Contains(ascii, ".") {
		return normalize.Query{}, fmt.Errorf("%w: %q has no public suffix", ErrInvalidDomain, input)
	}

	suffix, _ := publicsuffix.PublicSuffix(ascii)
	registrableASCII, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		// Happens when the input *is* a public suffix ("co.uk", "com"): there is
		// no registrable domain to look up.
		return normalize.Query{}, fmt.Errorf("%w: %q is a public suffix, not a registrable domain", ErrInvalidDomain, input)
	}

	unicode, err := lookupProfile.ToUnicode(registrableASCII)
	if err != nil {
		unicode = registrableASCII // A-label is always a valid fallback
	}
	suffixUnicode, err := lookupProfile.ToUnicode(suffix)
	if err != nil {
		suffixUnicode = suffix
	}

	return normalize.Query{
		Input:             input,
		RegistrableDomain: unicode,
		ASCII:             registrableASCII,
		TLD:               lastLabel(suffix),
		PublicSuffix:      suffixUnicode,
	}, nil
}

// hostFromInput extracts a bare hostname from a URL, an authority, or a plain
// domain. It deliberately avoids net/url for the non-URL cases, because
// url.Parse accepts a great deal that is not a domain and silently treats a
// bare host as a path.
func hostFromInput(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Drop path, query and fragment.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Drop userinfo ("user:pass@host", and incidentally email local parts).
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	// Drop port. Domains never contain a colon otherwise.
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	// Drop the root label's trailing dot.
	s = strings.TrimSuffix(s, ".")
	if strings.ContainsAny(s, " \t\n") {
		return ""
	}
	return s
}

func lastLabel(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}
