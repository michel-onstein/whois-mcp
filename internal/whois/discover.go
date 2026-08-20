package whois

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/qjam/whois-mcp/internal/cache"
)

// IANAHost is the WHOIS server that answers questions about TLDs themselves.
// Asking it for "uk" returns the record for the .uk delegation, including the
// registry's own WHOIS host — which is how the WHOIS path bootstraps, there
// being no bulk equivalent of RDAP's dns.json.
const IANAHost = "whois.iana.org"

// HostTTL matches the bootstrap refresh interval from design §9: IANA
// publishes daily, so a day-old answer is the freshest that exists.
const HostTTL = 24 * time.Hour

// ErrNoWHOISHost means the TLD exists but publishes no WHOIS server. Some
// ccTLDs genuinely have none — they are web-form only — and that is an answer,
// not a failure: the caller reports unknown rather than guessing.
var ErrNoWHOISHost = errors.New("TLD publishes no WHOIS host")

// seedHosts is a small embedded map of TLD to WHOIS host, mirroring the
// embedded RDAP bootstrap: a cold start with no egress to whois.iana.org still
// answers for the TLDs that carry most real traffic. It is a fallback, not the
// source of truth — a live IANA answer always wins, and this is only consulted
// when discovery fails.
//
// Kept deliberately short. A long hand-maintained copy of IANA's data is a
// second source of truth that silently goes stale; the network path is the
// real one.
var seedHosts = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.publicinterestregistry.org",
	"info": "whois.afilias.net",
	"biz":  "whois.nic.biz",
	"io":   "whois.nic.io",
	"dev":  "whois.nic.google",
	"app":  "whois.nic.google",
	"uk":   "whois.nic.uk",
	"de":   "whois.denic.de",
	"nl":   "whois.domain-registry.nl",
	"fr":   "whois.nic.fr",
	"jp":   "whois.jprs.jp",
	"ru":   "whois.tcinet.ru",
	"br":   "whois.registro.br",
	"au":   "whois.auda.org.au",
	"ca":   "whois.cira.ca",
	"ch":   "whois.nic.ch",
	"se":   "whois.iis.se",
	"eu":   "whois.eu",
}

// Discoverer resolves a TLD to its authoritative WHOIS host.
//
// Answers are cached for HostTTL through the shared Cache, so the Redis
// implementation arriving at M3 makes the map shared across replicas without
// any change here.
type Discoverer struct {
	tr    *Transport
	cache cache.Cache
	now   func() time.Time

	// ianaHost is the server asked about TLDs. Overridable for tests only.
	ianaHost string
}

// NewDiscoverer returns a Discoverer. A nil cache disables caching, which is
// useful in tests but wasteful in production.
func NewDiscoverer(tr *Transport, c cache.Cache) *Discoverer {
	return &Discoverer{tr: tr, cache: c, now: time.Now, ianaHost: IANAHost}
}

// Host returns the WHOIS host serving a TLD.
//
// The TLD must be the last label, lowercase, in A-label form ("uk", "xn--p1ai"),
// which is how IANA keys its records.
func (d *Discoverer) Host(ctx context.Context, tld string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(tld, ".")))
	if t == "" {
		return "", fmt.Errorf("%w: empty TLD", ErrNoWHOISHost)
	}

	key := "whois:host:" + t
	if d.cache != nil {
		if raw, ok := d.cache.Get(ctx, key); ok {
			// A negative answer is cached as an empty value: "this TLD has no
			// WHOIS host" is worth remembering, or every lookup for such a TLD
			// pays a round trip to IANA to learn nothing.
			if len(raw) == 0 {
				return "", fmt.Errorf("%w: %q", ErrNoWHOISHost, t)
			}
			return string(raw), nil
		}
	}

	host, err := d.query(ctx, t)
	if err != nil {
		// Fall back to the embedded seed. This is the cold-start path, and the
		// reason it is a fallback rather than a first choice is that IANA's
		// answer can change and ours cannot.
		if seed, ok := seedHosts[t]; ok {
			return seed, nil
		}
		return "", err
	}

	if d.cache != nil {
		d.cache.Set(ctx, key, []byte(host), HostTTL)
	}
	if host == "" {
		return "", fmt.Errorf("%w: %q", ErrNoWHOISHost, t)
	}
	return host, nil
}

// query asks IANA about one TLD. An empty host with a nil error means IANA
// answered and the TLD has no WHOIS server, which is different from a failure
// to ask — and the two must not be conflated, because the first is cacheable
// and the second is not.
func (d *Discoverer) query(ctx context.Context, tld string) (string, error) {
	resp, err := d.tr.Query(ctx, d.ianaHost, tld)
	if err != nil {
		return "", fmt.Errorf("asking %s about %q: %w", d.ianaHost, tld, err)
	}
	if len(resp.Raw) == 0 {
		return "", fmt.Errorf("%s returned nothing for %q", d.ianaHost, tld)
	}
	body := string(resp.Raw)
	if !ianaKnowsTLD(body) {
		return "", fmt.Errorf("%s does not know TLD %q", d.ianaHost, tld)
	}
	return whoisFieldFromIANA(body), nil
}

// ianaKnowsTLD distinguishes "IANA has no such TLD" from "IANA has it but it
// has no WHOIS host". Only the latter is a cacheable negative.
func ianaKnowsTLD(body string) bool {
	lower := strings.ToLower(body)
	for _, sig := range []string{"this query returned 0 objects", "not found", "no match"} {
		if strings.Contains(lower, sig) {
			return false
		}
	}
	return strings.Contains(lower, "domain:") || strings.Contains(lower, "whois:") ||
		strings.Contains(lower, "refer:")
}

// whoisFieldFromIANA extracts the WHOIS host from an IANA TLD record.
//
// IANA labels it "whois:", but a number of records carry only "refer:", which
// is the same information under the older name, so both are accepted with
// "whois:" winning when both appear.
func whoisFieldFromIANA(body string) string {
	var refer string
	for _, line := range strings.Split(body, "\n") {
		label, value, ok := splitField(line)
		if !ok {
			continue
		}
		switch strings.ToLower(label) {
		case "whois":
			if h := sanitizeHost(value); h != "" {
				return h
			}
		case "refer":
			if refer == "" {
				refer = sanitizeHost(value)
			}
		}
	}
	return refer
}

// splitField parses a "label: value" line, which is the entire structure both
// IANA records and most WHOIS responses have.
func splitField(line string) (label, value string, ok bool) {
	line = strings.TrimSpace(strings.TrimRight(line, "\r"))
	if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	i := strings.Index(line, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// sanitizeHost rejects anything that is not a bare hostname. The value comes
// from a third-party response, and it is about to become a dial target.
func sanitizeHost(v string) string {
	h := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "."))
	if h == "" || strings.ContainsAny(h, " \t/\\@") || !strings.Contains(h, ".") {
		return ""
	}
	return strings.ToLower(h)
}
