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
	"github.com/qjam/whois-mcp/internal/ratelimit"
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

// RegistrarTimeout bounds the registrar referral hop. It is deliberately
// shorter than the registry call (design 8.3): the registrar's data is a
// bonus, so a slow registrar must not consume the budget for the answer we
// already have.
const RegistrarTimeout = 3 * time.Second

// Client queries registry RDAP services.
type Client struct {
	reg             *Registry
	http            *http.Client
	rc              *rdap.Client
	followRegistrar bool
	// guard is the per-upstream rate limit and circuit breaker. Nil means no
	// policy, which is the right default for a unit test and the wrong one for
	// production — cmd/whois-mcp always supplies it.
	guard *ratelimit.Guard
}

// WithGuard attaches the upstream policy.
func (c *Client) WithGuard(g *ratelimit.Guard) *Client {
	c.guard = g
	return c
}

// ClientOptions tunes the client.
type ClientOptions struct {
	// FollowRegistrar enables the registry-to-registrar referral hop, which is
	// where thick data lives for gTLDs that keep contacts at the registrar.
	FollowRegistrar bool
}

// NewClient returns a Client using the given bootstrap registry. The HTTP
// client should come from NewHTTPClient so that the SSRF guard is in place.
//
// Registrar referral following is on by default: without it a gTLD lookup
// returns the thin registry record, and an agent cannot tell whether contacts
// are withheld or merely held elsewhere.
func NewClient(reg *Registry, hc *http.Client, userAgent string) *Client {
	return NewClientWithOptions(reg, hc, userAgent, ClientOptions{FollowRegistrar: true})
}

// NewClientWithOptions is NewClient with referral following configurable.
func NewClientWithOptions(reg *Registry, hc *http.Client, userAgent string, opt ClientOptions) *Client {
	return &Client{
		reg:  reg,
		http: hc,
		rc: &rdap.Client{
			HTTP:      hc,
			UserAgent: userAgent,
		},
		followRegistrar: opt.FollowRegistrar,
	}
}

// Query looks up a domain via its registry's RDAP service.
//
// It returns ErrNoRDAPService if the TLD has no RDAP endpoint. Every other
// outcome — including "not registered" and "the server misbehaved" — comes
// back as a Result with the appropriate tri-state, because those are answers,
// not failures.
func (c *Client) Query(ctx context.Context, q normalize.Query) (*Result, error) {
	return c.QueryWithOptions(ctx, q, QueryOptions{})
}

// QueryOptions tunes a single query.
type QueryOptions struct {
	// SkipRegistrarReferral suppresses the registrar hop for this call even
	// when the client has following enabled. The availability path uses it:
	// "is this domain free" is answered by the registry alone, and paying for
	// a referral to learn contact data nobody asked for is waste.
	SkipRegistrarReferral bool
}

// QueryWithOptions is Query with per-call behaviour.
func (c *Client) QueryWithOptions(ctx context.Context, q normalize.Query, opt QueryOptions) (*Result, error) {
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

		var resp *rdap.Response
		gerr := c.guard.Do(ctx, base, func(ctx context.Context) ratelimit.Outcome {
			r, e := c.rc.Do(req)
			resp = r
			return ratelimit.Outcome{
				Status:     statusOf(r),
				RetryAfter: retryAfterOf(r),
				Err:        e,
			}
		})
		// A policy rejection — throttled, or the circuit is open — is not an
		// answer about the domain. Record it and move to the next endpoint,
		// because another of this registry's base URLs may be healthy.
		if isPolicyRejection(gerr) {
			res.Warnings = append(res.Warnings, truncate(gerr.Error(), 200))
			lastErr = gerr
			continue
		}
		err = gerr

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
			if c.followRegistrar && !opt.SkipRegistrarReferral {
				c.followRegistrarHop(ctx, res)
			}
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

// followRegistrarHop fetches the registrar's RDAP record and merges it in.
//
// At most one hop, on a shorter deadline, and every failure degrades to the
// registry data plus a warning rather than failing the lookup (design 8.3).
// The registrar record is a supplement: it is where thick contact data lives,
// but the registry is authoritative for the registration itself, so registry
// fields are never overwritten, only filled where the registry said nothing.
func (c *Client) followRegistrarHop(ctx context.Context, res *Result) {
	href := registrarLink(res.Domain)
	if href == "" {
		return
	}
	u, err := url.Parse(href)
	if err != nil {
		res.Warnings = append(res.Warnings, "registrar referral URL is unparseable: "+truncate(href, 120))
		return
	}
	if !strings.EqualFold(u.Scheme, "https") {
		// The referral comes from a third party. Cleartext would expose the
		// query along the path, and we refuse it for the same reason the
		// bootstrap map drops http base URLs.
		res.Warnings = append(res.Warnings, "refusing non-https registrar referral to "+u.Redacted())
		return
	}

	hopCtx, cancel := context.WithTimeout(ctx, RegistrarTimeout)
	defer cancel()

	resp, err := c.rc.Do(rdap.NewRawRequest(u).WithContext(hopCtx))
	if err != nil {
		res.Warnings = append(res.Warnings,
			"registrar referral to "+u.Host+" failed ("+truncate(err.Error(), 160)+"); reporting registry data only")
		return
	}
	dom, ok := resp.Object.(*rdap.Domain)
	if !ok || dom == nil {
		res.Warnings = append(res.Warnings,
			"registrar referral to "+u.Host+" did not return a domain object; reporting registry data only")
		return
	}
	res.Servers = append(res.Servers, u.String())

	// Entities are the reason for the hop: prefer the registrar's when it has
	// more of them, since a thin registry record typically has one or none.
	if len(dom.Entities) > len(res.Domain.Entities) {
		res.Domain.Entities = dom.Entities
	}
	// Everything else fills gaps only.
	if len(res.Domain.Nameservers) == 0 {
		res.Domain.Nameservers = dom.Nameservers
	}
	if len(res.Domain.Events) == 0 {
		res.Domain.Events = dom.Events
	}
	if len(res.Domain.Status) == 0 {
		res.Domain.Status = dom.Status
	}
	if res.Domain.SecureDNS == nil {
		res.Domain.SecureDNS = dom.SecureDNS
	}
}

// registrarLink finds the registrar RDAP service link in a registry response.
//
// RFC 9083 marks it rel="related" with the RDAP media type. Matching the media
// type matters: registries also publish rel="related" links to their own
// terms-of-service HTML, and fetching one of those as RDAP wastes the hop.
func registrarLink(d *rdap.Domain) string {
	if d == nil {
		return ""
	}
	for _, l := range d.Links {
		if !strings.EqualFold(strings.TrimSpace(l.Rel), "related") {
			continue
		}
		if !strings.Contains(strings.ToLower(l.Type), "rdap+json") {
			continue
		}
		if h := strings.TrimSpace(l.Href); h != "" {
			return h
		}
	}
	return ""
}

// statusOf recovers the HTTP status from an RDAP response, or 0 if the exchange
// never got that far.
func statusOf(resp *rdap.Response) int {
	if resp == nil || len(resp.HTTP) == 0 {
		return 0
	}
	last := resp.HTTP[len(resp.HTTP)-1]
	if last == nil || last.Response == nil {
		return 0
	}
	return last.Response.StatusCode
}

// retryAfterOf recovers a Retry-After header, which is the only thing that lets
// us honour a registry's own pacing instruction rather than guessing.
func retryAfterOf(resp *rdap.Response) string {
	if resp == nil || len(resp.HTTP) == 0 {
		return ""
	}
	last := resp.HTTP[len(resp.HTTP)-1]
	if last == nil || last.Response == nil {
		return ""
	}
	return last.Response.Header.Get("Retry-After")
}

// isPolicyRejection reports whether an error came from our own upstream policy
// rather than from the registry.
//
// The distinction matters at the call site: a policy rejection says nothing
// about the domain, so it must not be classified as "does not exist", and it
// should not stop us trying this registry's other endpoints.
func isPolicyRejection(err error) bool {
	if err == nil {
		return false
	}
	var throttled *ratelimit.ErrThrottled
	return ratelimit.IsOpen(err) || errors.As(err, &throttled) ||
		errors.Is(err, ratelimit.ErrWouldExceedDeadline)
}
