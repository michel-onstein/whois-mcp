package whois

import "strings"

// Quirk records how one registry deviates from "send the bare domain".
//
// This is a table on purpose. Every entry here is a registry-specific special
// case, and special cases expressed as branches in the transport are how that
// code becomes unreadable and then wrong: the twentieth `if tld == "de"` hides
// the first. As data, the whole set is auditable at a glance, testable without
// a network, and extendable by someone who has never read the transport.
//
// See docs/MCP_DESIGN.md §8.4 and docs/IMPLEMENTATION_PLAN.md task 1.4.
type Quirk struct {
	// QueryFormat renders the line to send. It must contain exactly one %s,
	// which is replaced by the A-label domain. Empty means "send the domain".
	QueryFormat string
	// Host overrides the discovered WHOIS host. Rarely needed; present because
	// a few registries publish one host in IANA and answer usefully on another.
	Host string
	// NoReferral suppresses referral following for registries whose referral
	// line points somewhere useless or hostile.
	NoReferral bool
	// Why documents the deviation. Not decoration: without it the next reader
	// cannot tell a live workaround from a stale one.
	Why string
}

// quirks is keyed by TLD (last label, lowercase, A-label form).
var quirks = map[string]Quirk{
	"de": {
		QueryFormat: "-T dn,ace %s",
		Why: "DENIC defaults to a legacy format and rejects a bare domain with " +
			"an error; -T dn,ace selects the domain object in ACE encoding.",
	},
	"jp": {
		QueryFormat: "%s/e",
		Why:         "JPRS answers in Japanese unless the /e suffix requests English.",
	},
	"com": {
		QueryFormat: "domain %s",
		Why: "Some Verisign hosts treat a bare string as a broad search and " +
			"return a truncated match list; the domain keyword pins it to an exact lookup.",
	},
	"net": {
		QueryFormat: "domain %s",
		Why:         "Same Verisign behaviour as .com.",
	},
	"fr": {
		QueryFormat: "%s",
		Why: "AFNIC is standards-clean but rate-limits aggressively per IP; " +
			"listed so the rate-limit budget at M3 has an entry to attach to.",
	},
	"dk": {
		QueryFormat: "--show-handles %s",
		Why:         "DK Hostmaster omits handle detail unless asked.",
	},
	"nl": {
		NoReferral: true,
		Why: "SIDN's referral line points at a registrar web form rather than a " +
			"WHOIS service, so following it wastes a hop and a deadline.",
	},
}

// QueryFor renders the line to send for a domain in a TLD, applying any quirk.
func QueryFor(tld, domainASCII string) string {
	q, ok := quirks[normalizeTLD(tld)]
	if !ok || q.QueryFormat == "" {
		return domainASCII
	}
	return strings.Replace(q.QueryFormat, "%s", domainASCII, 1)
}

// HostFor returns the quirk host override for a TLD, or "" if there is none.
func HostFor(tld string) string {
	return quirks[normalizeTLD(tld)].Host
}

// ReferralsAllowed reports whether referrals should be followed for a TLD.
func ReferralsAllowed(tld string) bool {
	return !quirks[normalizeTLD(tld)].NoReferral
}

// QuirkFor exposes an entry for diagnostics and for the tld_info tool.
func QuirkFor(tld string) (Quirk, bool) {
	q, ok := quirks[normalizeTLD(tld)]
	return q, ok
}

// QuirkTLDs lists every TLD with a quirk, for tld_info and for tests that
// assert the table stays well-formed.
func QuirkTLDs() []string {
	out := make([]string, 0, len(quirks))
	for t := range quirks {
		out = append(out, t)
	}
	return out
}

func normalizeTLD(tld string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(tld, ".")))
}
