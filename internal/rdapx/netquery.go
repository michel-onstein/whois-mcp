package rdapx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/openrdap/rdap"

	"github.com/qjam/whois-mcp/internal/netguard"
	"github.com/qjam/whois-mcp/internal/ratelimit"
)

// ResourceKind is what an ip_lookup input turned out to be.
type ResourceKind string

// The three resource kinds an ip_lookup input can resolve to.
const (
	KindIP     ResourceKind = "ip"
	KindPrefix ResourceKind = "prefix"
	KindASN    ResourceKind = "asn"
)

// ErrInvalidResource means the input is neither an IP, a CIDR, nor an ASN.
var ErrInvalidResource = errors.New("not an IP address, CIDR prefix, or ASN")

// Resource is a parsed ip_lookup input.
type Resource struct {
	Kind ResourceKind
	// Input is what the caller supplied, echoed back so an agent can show what
	// was actually looked up.
	Input string
	IP    net.IP
	// Prefix is set for KindPrefix. The query still uses the network address,
	// because that is what RIR RDAP expects.
	Prefix *net.IPNet
	ASN    uint32
}

// String renders the resource as RDAP would name it.
func (r Resource) String() string {
	switch r.Kind {
	case KindASN:
		return "AS" + strconv.FormatUint(uint64(r.ASN), 10)
	case KindPrefix:
		if r.Prefix != nil {
			return r.Prefix.String()
		}
	}
	if r.IP != nil {
		return r.IP.String()
	}
	return r.Input
}

// ParseResource interprets an ip_lookup input.
//
// It accepts what a person would type: an address, a CIDR block, an ASN with or
// without the AS prefix, in either case. Being generous here is cheap and the
// alternative is an agent guessing at our format.
func ParseResource(input string) (Resource, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return Resource{}, fmt.Errorf("%w: empty input", ErrInvalidResource)
	}
	res := Resource{Input: input}

	// ASN forms first: "AS15169", "as15169", "15169". A bare number cannot be
	// an address, so there is no ambiguity to resolve.
	bare := strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
	if bare != s || !strings.ContainsAny(s, ".:/") {
		if n, err := strconv.ParseUint(strings.TrimSpace(bare), 10, 32); err == nil {
			res.Kind = KindASN
			res.ASN = uint32(n)
			return res, nil
		}
	}

	if strings.Contains(s, "/") {
		ip, prefix, err := net.ParseCIDR(s)
		if err != nil {
			return Resource{}, fmt.Errorf("%w: %q", ErrInvalidResource, input)
		}
		res.Kind = KindPrefix
		res.IP = ip
		res.Prefix = prefix
		return res, nil
	}

	if ip := net.ParseIP(s); ip != nil {
		res.Kind = KindIP
		res.IP = ip
		return res, nil
	}
	return Resource{}, fmt.Errorf("%w: %q", ErrInvalidResource, input)
}

// NetResult is the outcome of an IP or ASN lookup.
type NetResult struct {
	Resource Resource
	// Object is the decoded RDAP object: *rdap.IPNetwork or *rdap.Autnum.
	Object any
	Raw    []byte
	// Servers lists the endpoints consulted, in order.
	Servers  []string
	Warnings []string
}

// QueryResource looks up an IP, prefix or ASN at the responsible RIR.
//
// Unlike a domain lookup there is no tri-state to report: an address either has
// a registration or the RIR does not know it, and "not allocated" is a definite
// answer rather than an ambiguous one. So this returns an error when nothing
// answers, and the tool layer turns that into a structured tool error.
func (c *Client) QueryResource(ctx context.Context, netReg *NetRegistry, res Resource) (*NetResult, error) {
	if netReg == nil {
		return nil, errors.New("no IP/ASN bootstrap registry configured")
	}

	// Reject non-public addresses before touching an upstream.
	//
	// IANA's bootstrap file does not carve private space out of the RIR
	// allocations it lists — 192.168.0.0/16 falls inside a broader ARIN entry —
	// so the registry lookup happily returns a service for an address no RIR can
	// say anything useful about. Querying it anyway spends a request on a third
	// party to be told nothing, and the answer an agent needs ("this is private
	// space") is something we already know locally.
	if res.Kind != KindASN {
		if reason := netguard.BlockReason(res.IP); reason != "" {
			return nil, fmt.Errorf("%w: %s is %s", ErrNoRDAPForResource, res, reason)
		}
	}

	var bases []string
	var ok bool
	switch res.Kind {
	case KindASN:
		bases, ok = netReg.LookupASN(res.ASN)
	default:
		bases, ok = netReg.LookupIP(res.IP)
	}
	if !ok {
		// Unallocated space, or a private/reserved range no RIR publishes. Both
		// are answers, and neither is a failure of ours.
		return nil, fmt.Errorf("%w: %s", ErrNoRDAPForResource, res)
	}

	out := &NetResult{Resource: res, Servers: make([]string, 0, len(bases))}
	var lastErr error

	for _, base := range bases {
		u, err := url.Parse(base)
		if err != nil {
			lastErr = fmt.Errorf("bad bootstrap URL %q: %w", base, err)
			continue
		}
		out.Servers = append(out.Servers, base)

		req := requestFor(res).WithServer(u).WithContext(ctx)

		var resp *rdap.Response
		gerr := c.guard.Do(ctx, base, func(context.Context) ratelimit.Outcome {
			r, e := c.rc.Do(req)
			resp = r
			return ratelimit.Outcome{Status: statusOf(r), RetryAfter: retryAfterOf(r), Err: e}
		})
		if isPolicyRejection(gerr) {
			out.Warnings = append(out.Warnings, truncate(gerr.Error(), 200))
			lastErr = gerr
			continue
		}

		if resp != nil && len(resp.HTTP) > 0 {
			if last := resp.HTTP[len(resp.HTTP)-1]; last != nil {
				if last.Body != nil {
					out.Raw = last.Body
				}
				if last.URL != "" {
					out.Servers[len(out.Servers)-1] = last.URL
				}
			}
		}

		if gerr == nil {
			out.Object = resp.Object
			return out, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		lastErr = gerr
		out.Warnings = append(out.Warnings, truncate(gerr.Error(), 300))
	}

	if lastErr == nil {
		lastErr = errors.New("no endpoint answered")
	}
	return nil, fmt.Errorf("looking up %s: %w", res, lastErr)
}

// requestFor builds the right RDAP request for a resource kind.
func requestFor(res Resource) *rdap.Request {
	switch res.Kind {
	case KindASN:
		return rdap.NewAutnumRequest(res.ASN)
	case KindPrefix:
		return rdap.NewIPNetRequest(res.Prefix)
	default:
		return rdap.NewIPRequest(res.IP)
	}
}
