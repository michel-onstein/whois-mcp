package whois

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
)

// MaxReferralHops bounds the referral chain. Two is the design's number
// (§8.4): registry to registrar is one hop, and one more covers the registries
// that point at an intermediate host. Beyond that a chain is either a loop or
// an attempt to use us as an amplifier, and neither deserves another dial.
const MaxReferralHops = 2

// Exchange is one hop of a lookup, retained so a surprising answer can be
// traced to the server that gave it.
type Exchange struct {
	Host      string
	Query     string
	Bytes     int
	Truncated bool
	Referral  string
}

// Result is the outcome of the WHOIS path for one domain.
type Result struct {
	// Raw is the response from the last hop — the most specific answer, which
	// is the one worth parsing and the one whois_raw should return.
	Raw []byte
	// Chain lists every hop in order, including the one that produced Raw.
	Chain []Exchange
	// Servers is the hosts consulted, in order, for DomainReport.Source.
	Servers []string
	// Truncated is true if the final response hit the size cap.
	Truncated bool
	// Warnings records non-fatal problems: a referral that failed, a chain cut
	// short, a response that arrived empty.
	Warnings []string
}

// Client executes the WHOIS path: discover the TLD's host, apply that
// registry's quirks, query, and follow referrals to the most specific answer.
//
// It deliberately does not parse. Parsing decides what the bytes mean, and
// keeping that separate is what lets a parser change without touching the
// transport, and what lets whois_raw answer when parsing fails entirely.
type Client struct {
	tr  *Transport
	dis *Discoverer
	log *slog.Logger
}

// NewClient returns a Client. A nil logger discards.
func NewClient(tr *Transport, c cache.Cache, log *slog.Logger) *Client {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{tr: tr, dis: NewDiscoverer(tr, c), log: log}
}

// Query resolves a domain over WHOIS.
//
// A returned error means the lookup could not be performed at all — no host
// discoverable, or the first hop failed outright. Everything softer comes back
// as a Result with warnings, because a partial answer plus an honest caveat is
// more useful to an agent than a failed tool call.
func (c *Client) Query(ctx context.Context, q normalize.Query) (*Result, error) {
	host := HostFor(q.TLD)
	if host == "" {
		h, err := c.dis.Host(ctx, q.TLD)
		if err != nil {
			return nil, err
		}
		host = h
	}

	res := &Result{}
	seen := make(map[string]bool, MaxReferralHops+1)
	query := QueryFor(q.TLD, q.ASCII)

	for hop := 0; ; hop++ {
		key := strings.ToLower(host)
		if seen[key] {
			// A registry pointing back at a host already asked is a loop. Stop
			// and keep what we have rather than spending the remaining hops.
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("referral loop: %s was already queried", host))
			break
		}
		seen[key] = true

		resp, err := c.tr.Query(ctx, host, query)
		if err != nil {
			if hop == 0 {
				return nil, fmt.Errorf("querying %s: %w", host, err)
			}
			// A failed referral degrades to the answer we already have, which
			// is design §8.3's rule for RDAP and is no less true here.
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("referral to %s failed: %v; reporting the registry answer", host, err))
			break
		}

		ex := Exchange{
			Host:      resp.Host,
			Query:     resp.Query,
			Bytes:     len(resp.Raw),
			Truncated: resp.Truncated,
		}

		// Only replace the answer if this hop actually said something. A
		// referral target that answers with nothing must not erase the
		// registry's useful response.
		if len(resp.Raw) > 0 {
			res.Raw = resp.Raw
			res.Truncated = resp.Truncated
		} else if hop == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s returned an empty response", resp.Host))
		} else {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("referral %s returned an empty response; reporting the registry answer", resp.Host))
		}

		next := ""
		if ReferralsAllowed(q.TLD) && len(resp.Raw) > 0 {
			next = referralHost(string(resp.Raw))
			// A registry naming itself is not a referral.
			if next != "" && strings.EqualFold(next, hostOnly(resp.Host)) {
				next = ""
			}
		}
		ex.Referral = next
		res.Chain = append(res.Chain, ex)
		res.Servers = append(res.Servers, resp.Host)

		if next == "" {
			break
		}
		if hop+1 >= MaxReferralHops {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("stopped after %d referral hops; %s not followed", MaxReferralHops, next))
			break
		}
		host = next
	}

	if len(res.Raw) == 0 && len(res.Warnings) == 0 {
		res.Warnings = append(res.Warnings, "WHOIS returned no data")
	}
	return res, nil
}

// referralLabels are the field names registries use to point at a more
// specific WHOIS server. Ordered by how specific they are: a registrar server
// beats a generic "whois" line pointing at the registry itself.
var referralLabels = []string{
	"registrar whois server",
	"whois server",
	"refer",
	"whois",
}

// referralHost finds the most specific referral target in a response.
func referralHost(body string) string {
	found := make(map[string]string, len(referralLabels))
	for _, line := range strings.Split(body, "\n") {
		label, value, ok := splitField(line)
		if !ok {
			continue
		}
		l := strings.ToLower(label)
		for _, want := range referralLabels {
			if l == want {
				if _, exists := found[want]; !exists {
					if h := sanitizeHost(value); h != "" {
						found[want] = h
					}
				}
			}
		}
	}
	for _, want := range referralLabels {
		if h, ok := found[want]; ok {
			return h
		}
	}
	return ""
}

// hostOnly strips a port so a host can be compared with a referral value.
func hostOnly(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i > 0 && !strings.Contains(hostport[i+1:], "]") {
		return hostport[:i]
	}
	return hostport
}
