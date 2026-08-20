package mcpsrv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/auth"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/resolve"
)

// IPLookupInput is the argument schema for ip_lookup.
type IPLookupInput struct {
	Resource      string `json:"resource" jsonschema:"an IP address (8.8.8.8, 2001:4860:4860::8888), a CIDR prefix (8.8.8.0/24), or an ASN (AS15169 or 15169)"`
	MaxAgeSeconds *int   `json:"max_age_seconds,omitempty" jsonschema:"the oldest acceptable cached result in seconds; 0 forces a fresh lookup (default 21600)"`
}

func registerM5(s *mcp.Server, opt Options) {
	if !opt.NetLookups {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "ip_lookup",
		Description: "Look up the registration of an IP address, CIDR prefix, or autonomous system " +
			"number at the responsible Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, " +
			"AFRINIC). Returns the allocation, its holder, dates and status. Note that 'country' is " +
			"the registered country of the allocation, which is administrative rather than " +
			"geographic — it is not geolocation and should not be presented as the location of a " +
			"host. Requires the whois:read scope.",
	}, ipLookupHandler(opt))
}

func ipLookupHandler(opt Options) mcp.ToolHandlerFor[IPLookupInput, *normalize.NetReport] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in IPLookupInput) (*mcp.CallToolResult, *normalize.NetReport, error) {
		if err := auth.RequireScope(ctx, auth.ScopeRead); err != nil && opt.EnforceScopes {
			return insufficientScope(auth.ScopeRead), nil, nil
		}
		if strings.TrimSpace(in.Resource) == "" {
			return errorResultCode("invalid_request", "", "resource is required"), nil, nil
		}
		maxAge := resolve.TTLNet
		if in.MaxAgeSeconds != nil {
			maxAge = time.Duration(*in.MaxAgeSeconds) * time.Second
		}

		rep, err := opt.Resolver.LookupResource(ctx, in.Resource, maxAge)
		if err != nil {
			return netErrorResult(in.Resource, err), nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summarizeNet(rep)}},
		}, rep, nil
	}
}

// netErrorResult classifies an IP/ASN failure.
//
// "No RIR claims this" gets its own code rather than being folded into a generic
// failure, because it is a definite answer about the input — private, reserved,
// or unallocated space — and an agent should stop rather than retry.
func netErrorResult(resource string, err error) *mcp.CallToolResult {
	switch {
	case errors.Is(err, rdapx.ErrInvalidResource):
		return errorResultCode("invalid_resource", "",
			"not an IP address, CIDR prefix, or ASN: "+resource)
	case errors.Is(err, rdapx.ErrNoRDAPForResource):
		return errorResultCode("unallocated_resource", "",
			"no Regional Internet Registry publishes a record for "+resource+
				"; it is most likely private, reserved, or unallocated space")
	case errors.Is(err, resolve.ErrNoNetRegistry):
		return errorResultCode("not_configured", "", "IP and ASN lookups are not enabled on this server")
	case errors.Is(err, context.DeadlineExceeded):
		return errorResultCode("upstream_timeout", "", err.Error())
	case errors.Is(err, context.Canceled):
		return errorResultCode("cancelled", "", err.Error())
	default:
		return errorResultCode("internal_error", "", err.Error())
	}
}

// summarizeNet renders the compact text block.
func summarizeNet(r *normalize.NetReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s)", r.Query.Normalized, r.Kind)
	if r.Name != "" {
		fmt.Fprintf(&b, " — %s", r.Name)
	}
	b.WriteString("\n")

	switch {
	case r.ASNRange != "":
		fmt.Fprintf(&b, "allocation: AS%s\n", r.ASNRange)
	case r.StartAddress != "":
		fmt.Fprintf(&b, "range: %s – %s", r.StartAddress, r.EndAddress)
		if r.IPVersion != "" {
			fmt.Fprintf(&b, " (%s)", r.IPVersion)
		}
		b.WriteString("\n")
	}
	if r.Type != "" {
		fmt.Fprintf(&b, "type: %s\n", r.Type)
	}
	if r.Country != "" {
		// Said explicitly every time, because this field is routinely read as
		// geolocation and it is not.
		fmt.Fprintf(&b, "registered country: %s (administrative, not the location of any host)\n", r.Country)
	}
	if len(r.Statuses) > 0 {
		fmt.Fprintf(&b, "status: %s\n", strings.Join(r.Statuses, ", "))
	}
	if r.ParentHandle != "" {
		fmt.Fprintf(&b, "parent allocation: %s\n", r.ParentHandle)
	}
	if d := r.Dates; d.Created != nil || d.Updated != nil {
		b.WriteString("dates:")
		if d.Created != nil {
			fmt.Fprintf(&b, " registered=%s", d.Created.Format(time.RFC3339))
		}
		if d.Updated != nil {
			fmt.Fprintf(&b, " updated=%s", d.Updated.Format(time.RFC3339))
		}
		b.WriteString("\n")
	}
	redacted := 0
	for _, e := range r.Entities {
		if e.Redacted {
			redacted++
		}
	}
	if len(r.Entities) > 0 {
		fmt.Fprintf(&b, "contacts: %d", len(r.Entities))
		if redacted > 0 {
			fmt.Fprintf(&b, " (%d withheld by the registry)", redacted)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "source: %s via %s (cache %s)\n",
		r.Source.Protocol, strings.Join(r.Source.Servers, ", "), r.Source.Cache)
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return strings.TrimRight(b.String(), "\n")
}
