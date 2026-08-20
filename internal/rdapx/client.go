package rdapx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openrdap/rdap"

	"github.com/qjam/whois-mcp/internal/normalize"
)

// ErrNoRDAPService means the TLD has no RDAP service in the bootstrap
// registry. All gTLDs have one; many ccTLDs do not, and those are the WHOIS
// path's reason for existing (M1).
var ErrNoRDAPService = errors.New("no RDAP service for TLD")

// Result is the outcome of an RDAP query.
type Result struct {
	// Domain is the decoded response. It is nil when Registered is not Yes.
	Domain *rdap.Domain
	// Raw is the verbatim JSON body of the final response, for rdap_raw.
	Raw []byte
	// Servers lists the endpoints consulted, in order.
	Servers []string
	// Registered is the tri-state answer. Unknown is used whenever the signal
	// is ambiguous — never guessed into a yes or no.
	Registered normalize.Tristate
	// Warnings records non-fatal problems worth surfacing to the agent.
	Warnings []string
}

// Client queries registry RDAP services.
type Client struct {
	reg  *Registry
	http *http.Client
	rc   *rdap.Client
}

// NewClient returns a Client using the given bootstrap registry. The HTTP
// client should come from NewHTTPClient so that the SSRF guard is in place.
func NewClient(reg *Registry, hc *http.Client, userAgent string) *Client {
	return &Client{
		reg:  reg,
		http: hc,
		rc: &rdap.Client{
			HTTP:      hc,
			UserAgent: userAgent,
		},
	}
}

// Query looks up a domain via its registry's RDAP service.
//
// It returns ErrNoRDAPService if the TLD has no RDAP endpoint. Every other
// outcome — including "not registered" and "the server misbehaved" — comes
// back as a Result with the appropriate tri-state, because those are answers,
// not failures.
func (c *Client) Query(ctx context.Context, q normalize.Query) (*Result, error) {
	bases, ok := c.reg.Lookup(q.TLD)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoRDAPService, q.TLD)
	}

	res := &Result{Registered: normalize.Unknown}
	var lastErr error

	// Try each published base URL in turn; registries often publish more than
	// one, and a single dead endpoint should not fail the lookup.
	for _, base := range bases {
		u, err := url.Parse(base)
		if err != nil {
			lastErr = fmt.Errorf("bad bootstrap URL %q: %w", base, err)
			continue
		}
		res.Servers = append(res.Servers, base)

		req := rdap.NewDomainRequest(q.ASCII).WithServer(u).WithContext(ctx)
		resp, err := c.rc.Do(req)

		// Capture the raw body and the actual URL, whatever the outcome.
		if resp != nil && len(resp.HTTP) > 0 {
			last := resp.HTTP[len(resp.HTTP)-1]
			if last != nil {
				if last.Body != nil {
					res.Raw = last.Body
				}
				if last.URL != "" {
					res.Servers[len(res.Servers)-1] = last.URL
				}
			}
		}

		if err == nil {
			dom, ok := resp.Object.(*rdap.Domain)
			if !ok {
				lastErr = fmt.Errorf("unexpected RDAP object type %T from %s", resp.Object, base)
				res.Warnings = append(res.Warnings, lastErr.Error())
				continue
			}
			res.Domain = dom
			res.Registered = normalize.Yes
			return res, nil
		}

		// Classify the failure. Only an explicit, RDAP-shaped "does not exist"
		// is allowed to become a confident "no".
		if ct, ok := clientErrorType(err); ok {
			switch ct {
			case rdap.ObjectDoesNotExist:
				res.Registered = normalize.No
				return res, nil
			case rdap.BootstrapNoMatch, rdap.BootstrapNotSupported:
				lastErr = fmt.Errorf("%w: %v", ErrNoRDAPService, err)
				res.Warnings = append(res.Warnings, err.Error())
				continue
			}
		}
		if ctx.Err() != nil {
			res.Warnings = append(res.Warnings, "lookup cancelled or timed out")
			return res, ctx.Err()
		}
		lastErr = err
		res.Warnings = append(res.Warnings, truncate(err.Error(), 300))
	}

	// Every endpoint was tried and none gave a definitive answer.
	if lastErr != nil && errors.Is(lastErr, ErrNoRDAPService) {
		return nil, lastErr
	}
	res.Registered = normalize.Unknown
	if lastErr != nil {
		res.Warnings = append(res.Warnings,
			"registration status could not be determined from RDAP; treat as unknown")
	}
	return res, nil
}

// clientErrorType extracts openrdap's error classification.
//
// The library returns *rdap.ClientError, but ClientError's Error method has a
// value receiver, so both the pointer and the value satisfy error. Matching
// only one of them silently misclassifies every 404 as "unknown" — checking
// both is cheap insurance against that reappearing if the library changes.
func clientErrorType(err error) (rdap.ClientErrorType, bool) {
	var pe *rdap.ClientError
	if errors.As(err, &pe) && pe != nil {
		return pe.Type, true
	}
	var ve rdap.ClientError
	if errors.As(err, &ve) {
		return ve.Type, true
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// DefaultUserAgent identifies us honestly to registries, which is part of
// being a well-behaved client of services we have no agreement with.
func DefaultUserAgent(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		v = "dev"
	}
	return "whois-mcp/" + v + " (+https://github.com/qjam/whois-mcp)"
}

// DefaultTimeout is the per-upstream request ceiling from the design.
const DefaultTimeout = 5 * time.Second
