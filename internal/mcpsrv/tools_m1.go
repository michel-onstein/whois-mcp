package mcpsrv

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/resolve"
	"github.com/qjam/whois-mcp/internal/whois"
)

// BootstrapResourceURI is the TLD coverage map (design §6.2). An agent can read
// it to reason about coverage *before* issuing a query it cannot answer well,
// which is cheaper for everyone than finding out per lookup.
const BootstrapResourceURI = "whois://bootstrap/tlds"

// AvailabilityInput is the argument schema for domain_availability.
type AvailabilityInput struct {
	Domains       []string `json:"domains" jsonschema:"the domains to check, at most 50 per call"`
	MaxAgeSeconds *int     `json:"max_age_seconds,omitempty" jsonschema:"the oldest acceptable cached result in seconds; 0 forces a fresh check (default 300)"`
}

// AvailabilityOutput is the batch result.
type AvailabilityOutput struct {
	Results []resolve.Availability `json:"results" jsonschema:"one entry per requested domain, in the order requested"`
	// Truncated is true if more than 50 domains were supplied and the tail was
	// dropped. Saying so is better than silently answering a different question.
	Truncated bool `json:"truncated,omitempty"`
}

// TLDInfoInput is the argument schema for tld_info.
type TLDInfoInput struct {
	TLD string `json:"tld" jsonschema:"the TLD to describe, with or without a leading dot; a full domain is also accepted and reduced to its TLD"`
}

// TLDInfoOutput describes how a TLD is served.
type TLDInfoOutput struct {
	TLD          string   `json:"tld"`
	HasRDAP      bool     `json:"has_rdap" jsonschema:"true if the IANA bootstrap registry publishes an RDAP service for this TLD"`
	RDAPEndpoint []string `json:"rdap_endpoints,omitempty" jsonschema:"the RDAP base URLs, in the order they would be tried"`
	WHOISHost    string   `json:"whois_host,omitempty" jsonschema:"the port-43 host, when known without querying IANA"`
	// Path names which protocol a lookup would use, so an agent can predict
	// the shape and confidence of the answer it will get.
	Path string `json:"path" jsonschema:"rdap, whois, or unknown"`
	// Quirk describes a registry-specific deviation, when there is one.
	Quirk string `json:"quirk,omitempty"`
	// BootstrapPublished is the publication timestamp of the IANA data backing
	// this answer, so a stale map is visible rather than assumed current.
	BootstrapPublished time.Time `json:"bootstrap_published"`
	BootstrapStale     bool      `json:"bootstrap_stale,omitempty" jsonschema:"true if the bootstrap map is older than its 24h refresh interval"`
	Note               string    `json:"note,omitempty"`
}

// BootstrapResource is the payload of whois://bootstrap/tlds.
type BootstrapResource struct {
	Published     time.Time `json:"published" jsonschema:"the publication timestamp of the IANA bootstrap file itself"`
	LoadedAt      time.Time `json:"loaded_at"`
	Stale         bool      `json:"stale"`
	TLDCount      int       `json:"tld_count"`
	FromNetwork   bool      `json:"from_network" jsonschema:"false when serving the snapshot embedded in the binary"`
	RDAPTLDs      []string  `json:"rdap_tlds" jsonschema:"every TLD with an RDAP service, sorted"`
	QuirkTLDs     []string  `json:"quirk_tlds" jsonschema:"TLDs whose WHOIS service needs a special query form"`
	WHOISFallback string    `json:"whois_fallback" jsonschema:"how TLDs without RDAP are served"`
}

func registerM1(s *mcp.Server, opt Options) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "domain_availability",
		Description: "Cheap registered/available check for up to 50 domains at once. Returns only " +
			"whether each is registered, which protocol answered, and when it was checked — it skips " +
			"contact data and the registrar referral, and uses a tighter timeout than domain_lookup. " +
			"The 'registered' field is tri-state: 'unknown' means the upstream signal was ambiguous " +
			"and MUST NOT be treated as 'available'. Use domain_lookup when you need the full record.",
	}, availabilityHandler(opt))

	mcp.AddTool(s, &mcp.Tool{
		Name: "tld_info",
		Description: "Describe how a TLD is served: whether the IANA bootstrap registry publishes an " +
			"RDAP service for it, which endpoints, whether a lookup would fall back to port-43 WHOIS, " +
			"and any registry-specific quirk. Useful for predicting the confidence of an answer before " +
			"asking for it.",
	}, tldInfoHandler(opt))

	s.AddResource(&mcp.Resource{
		URI:         BootstrapResourceURI,
		Name:        "TLD coverage map",
		Description: "The current TLD to RDAP service map with the IANA bootstrap file's own publication timestamp.",
		MIMEType:    "application/json",
	}, bootstrapResourceHandler(opt))
}

func availabilityHandler(opt Options) mcp.ToolHandlerFor[AvailabilityInput, *AvailabilityOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in AvailabilityInput) (*mcp.CallToolResult, *AvailabilityOutput, error) {
		if len(in.Domains) == 0 {
			return errorResultCode("invalid_domain", "", "domains must contain at least one entry"), nil, nil
		}
		maxAge := 5 * time.Minute // availability is the volatile case (design §9)
		if in.MaxAgeSeconds != nil {
			maxAge = time.Duration(*in.MaxAgeSeconds) * time.Second
		}

		out := &AvailabilityOutput{Truncated: len(in.Domains) > resolve.MaxBatch}
		out.Results = opt.Resolver.CheckAvailability(ctx, in.Domains, maxAge)

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summarizeAvailability(out)}},
		}, out, nil
	}
}

func tldInfoHandler(opt Options) mcp.ToolHandlerFor[TLDInfoInput, *TLDInfoOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in TLDInfoInput) (*mcp.CallToolResult, *TLDInfoOutput, error) {
		tld := lastLabel(strings.ToLower(strings.TrimSpace(strings.TrimPrefix(in.TLD, "."))))
		if tld == "" {
			return errorResultCode("invalid_domain", "", "tld must not be empty"), nil, nil
		}

		out := &TLDInfoOutput{
			TLD:                tld,
			BootstrapPublished: opt.Registry.Publication(),
			BootstrapStale:     opt.Registry.Age() > 24*time.Hour,
		}
		if bases, ok := opt.Registry.Lookup(tld); ok {
			out.HasRDAP = true
			out.RDAPEndpoint = bases
			out.Path = string(normalize.ProtoRDAP)
		} else {
			// Not an error: most ccTLDs are here, and the WHOIS path is why.
			out.Path = string(normalize.ProtoWHOIS)
			out.Note = "no RDAP service published for this TLD; a lookup uses port-43 WHOIS, " +
				"which is parsed heuristically and reports a parse_confidence below 1.0"
		}
		if h := whois.SeedHost(tld); h != "" {
			out.WHOISHost = h
		}
		if q, ok := whois.QuirkFor(tld); ok {
			out.Quirk = q.Why
		}

		body, _ := json.MarshalIndent(out, "", "  ")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
		}, out, nil
	}
}

func bootstrapResourceHandler(opt Options) mcp.ResourceHandler {
	return func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		tlds := opt.Registry.TLDs()
		sort.Strings(tlds)
		quirks := whois.QuirkTLDs()
		sort.Strings(quirks)

		payload := BootstrapResource{
			Published:   opt.Registry.Publication(),
			LoadedAt:    opt.Registry.LoadedAt(),
			Stale:       opt.Registry.Age() > 24*time.Hour,
			TLDCount:    len(tlds),
			FromNetwork: opt.Registry.FromNetwork(),
			RDAPTLDs:    tlds,
			QuirkTLDs:   quirks,
			WHOISFallback: "TLDs absent from this list are served over port-43 WHOIS, discovered via " +
				"whois.iana.org and parsed with a per-host template or a heuristic fallback",
		}
		body, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encoding bootstrap resource: %w", err)
		}
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      req.Params.URI,
				MIMEType: "application/json",
				Text:     string(body),
			}},
		}, nil
	}
}

// summarizeAvailability renders the compact text block. It leads with the
// counts because that is what a caller screening names reads first, and it
// names unknowns explicitly so they are not skimmed as "available".
func summarizeAvailability(out *AvailabilityOutput) string {
	var taken, free, unknown []string
	for _, r := range out.Results {
		switch r.Registered {
		case normalize.Yes:
			taken = append(taken, r.Domain)
		case normalize.No:
			free = append(free, r.Domain)
		default:
			unknown = append(unknown, r.Domain)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d checked: %d registered, %d available, %d unknown\n",
		len(out.Results), len(taken), len(free), len(unknown))
	if len(free) > 0 {
		fmt.Fprintf(&b, "available: %s\n", strings.Join(free, ", "))
	}
	if len(taken) > 0 {
		fmt.Fprintf(&b, "registered: %s\n", strings.Join(taken, ", "))
	}
	if len(unknown) > 0 {
		fmt.Fprintf(&b, "unknown (could NOT determine — do not treat as available): %s\n",
			strings.Join(unknown, ", "))
	}
	if out.Truncated {
		fmt.Fprintf(&b, "note: only the first %d domains were checked\n", resolve.MaxBatch)
	}
	return strings.TrimRight(b.String(), "\n")
}

func lastLabel(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}
