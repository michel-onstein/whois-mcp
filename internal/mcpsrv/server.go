// Package mcpsrv registers the MCP tools and adapts the resolver to the
// Model Context Protocol. See docs/MCP_DESIGN.md §6.
package mcpsrv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/resolve"
)

// Version is the server version reported to clients. Overridden at build time.
var Version = "0.1.0-m0"

// LookupInput is the argument schema for domain_lookup.
type LookupInput struct {
	Domain string `json:"domain" jsonschema:"the domain to look up; a URL, an internationalized name, or a subdomain is accepted and reduced to the registrable domain"`
	// IncludeContacts defaults to true via the handler, because an absent
	// contact and a redacted one are different facts an agent should see.
	IncludeContacts *bool `json:"include_contacts,omitempty" jsonschema:"include contact records; they are usually redacted but their redaction state is itself informative (default true)"`
	MaxAgeSeconds   *int  `json:"max_age_seconds,omitempty" jsonschema:"the oldest acceptable cached result in seconds; 0 forces a fresh lookup (default 3600)"`
}

// ToolError is the structured failure payload described in design §6.3. It is
// returned as an error result so the model can reason about and recover from
// the failure rather than only seeing prose.
type ToolError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Domain  string `json:"domain,omitempty"`
	TLD     string `json:"tld,omitempty"`
}

// Options configures the MCP server.
type Options struct {
	Resolver *resolve.Resolver
	Registry *rdapx.Registry
	Log      *slog.Logger
}

// New builds an MCP server with the tool surface registered.
func New(opt Options) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "whois-mcp",
		Title:   "WHOIS/RDAP domain lookup",
		Version: Version,
	}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name: "domain_lookup",
		Description: "Look up registration data for a domain in any TLD. Reports whether the " +
			"domain is registered, who the registrar is, creation/expiry dates, nameservers, " +
			"DNSSEC and EPP status codes. The 'registered' field is tri-state: 'yes', 'no', or " +
			"'unknown' when the upstream signal was ambiguous — treat 'unknown' as 'could not " +
			"determine', never as 'available'.",
	}, lookupHandler(opt))

	registerM1(s, opt)

	return s
}

func lookupHandler(opt Options) mcp.ToolHandlerFor[LookupInput, *normalize.DomainReport] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in LookupInput) (*mcp.CallToolResult, *normalize.DomainReport, error) {
		o := resolve.Options{MaxAge: time.Hour, IncludeContacts: true}
		if in.IncludeContacts != nil {
			o.IncludeContacts = *in.IncludeContacts
		}
		if in.MaxAgeSeconds != nil {
			o.MaxAge = time.Duration(*in.MaxAgeSeconds) * time.Second
		}

		rep, err := opt.Resolver.Lookup(ctx, in.Domain, o)
		if err != nil {
			return errorResult(in.Domain, err), nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summarize(rep)}},
		}, rep, nil
	}
}

// errorResult converts a resolver failure into a structured, machine-readable
// error result.
func errorResult(domain string, err error) *mcp.CallToolResult {
	te := ToolError{Error: "internal_error", Message: err.Error(), Domain: domain}
	switch {
	case errors.Is(err, resolve.ErrInvalidDomain):
		te.Error = "invalid_domain"
	case errors.Is(err, context.DeadlineExceeded):
		te.Error = "upstream_timeout"
	case errors.Is(err, context.Canceled):
		te.Error = "cancelled"
	case errors.Is(err, rdapx.ErrNoRDAPService):
		te.Error = "no_service_for_tld"
	}
	body, _ := json.Marshal(te)
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
	}
}

// errorResultCode builds a structured tool error with an explicit code, for
// the input-validation failures that never reach the resolver.
func errorResultCode(code, domain, message string) *mcp.CallToolResult {
	body, _ := json.Marshal(ToolError{Error: code, Message: message, Domain: domain})
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
	}
}

// summarize renders a compact human-readable block alongside the structured
// output, so models that ignore structuredContent still get usable content.
func summarize(r *normalize.DomainReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — registered: %s", r.Query.ASCII, r.Registered)
	if r.Query.RegistrableDomain != r.Query.ASCII {
		fmt.Fprintf(&b, " (%s)", r.Query.RegistrableDomain)
	}
	b.WriteString("\n")

	if r.Registrar != nil && r.Registrar.Name != "" {
		fmt.Fprintf(&b, "registrar: %s", r.Registrar.Name)
		if r.Registrar.IANAID != 0 {
			fmt.Fprintf(&b, " (IANA %d)", r.Registrar.IANAID)
		}
		b.WriteString("\n")
	}
	if d := r.Dates; d.Created != nil || d.Expires != nil {
		b.WriteString("dates:")
		if d.Created != nil {
			fmt.Fprintf(&b, " created=%s", d.Created.Format(time.RFC3339))
		}
		if d.Updated != nil {
			fmt.Fprintf(&b, " updated=%s", d.Updated.Format(time.RFC3339))
		}
		if d.Expires != nil {
			fmt.Fprintf(&b, " expires=%s", d.Expires.Format(time.RFC3339))
		}
		b.WriteString("\n")
	}
	if len(r.Nameservers) > 0 {
		hosts := make([]string, 0, len(r.Nameservers))
		for _, n := range r.Nameservers {
			hosts = append(hosts, n.Host)
		}
		fmt.Fprintf(&b, "nameservers: %s\n", strings.Join(hosts, ", "))
	}
	if len(r.Statuses) > 0 {
		fmt.Fprintf(&b, "status: %s\n", strings.Join(r.Statuses, ", "))
	}
	redacted := 0
	for _, e := range r.Entities {
		if e.Redacted {
			redacted++
		}
	}
	if redacted > 0 {
		fmt.Fprintf(&b, "contacts: %d of %d withheld by the registry\n", redacted, len(r.Entities))
	}
	fmt.Fprintf(&b, "source: %s via %s (cache %s)\n",
		r.Source.Protocol, strings.Join(r.Source.Servers, ", "), r.Source.Cache)
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return strings.TrimRight(b.String(), "\n")
}
