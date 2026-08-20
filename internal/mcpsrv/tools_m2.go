package mcpsrv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/auth"
	"github.com/qjam/whois-mcp/internal/resolve"
)

// PrivilegedTools maps the tools that need more than the baseline scope.
//
// The scope gate uses this, and so does a test asserting nothing privileged is
// missing from it: a raw tool absent here would be reachable with whois:read,
// which is exactly the mistake the map exists to make visible.
var PrivilegedTools = auth.ToolScopes{
	"rdap_raw":       auth.ScopeRaw,
	"whois_raw":      auth.ScopeRaw,
	"session_list":   auth.ScopeAdmin,
	"session_revoke": auth.ScopeAdmin,
}

// RawInput is the argument schema for rdap_raw and whois_raw.
type RawInput struct {
	Domain        string `json:"domain" jsonschema:"the domain whose raw upstream response to return"`
	MaxAgeSeconds *int   `json:"max_age_seconds,omitempty" jsonschema:"the oldest acceptable cached payload in seconds; 0 forces a fresh fetch (default 900)"`
}

// SessionListOutput is the session_list result.
type SessionListOutput struct {
	Sessions []SessionView `json:"sessions" jsonschema:"enrolled sessions, newest first"`
	Count    int           `json:"count"`
}

// SessionView is one session as an operator sees it. It deliberately carries no
// token material of any kind — only the label and timings needed to decide
// which session to revoke.
type SessionView struct {
	SID       string    `json:"sid"`
	Label     string    `json:"label"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
	Rotations int       `json:"rotations" jsonschema:"how many times this session refreshed; an unusually high count on a young session is worth a look"`
	Revoked   bool      `json:"revoked,omitempty"`
	Current   bool      `json:"current,omitempty" jsonschema:"true for the session making this call"`
}

// SessionRevokeInput names a session to revoke.
type SessionRevokeInput struct {
	SID string `json:"sid" jsonschema:"the session id to revoke, as reported by session_list"`
}

// SessionRevokeOutput reports the outcome.
type SessionRevokeOutput struct {
	SID     string `json:"sid"`
	Revoked bool   `json:"revoked"`
	// SelfRevoked is true when a caller revoked the session it is using, which
	// is allowed but worth saying plainly: the caller's next request fails.
	SelfRevoked bool   `json:"self_revoked,omitempty"`
	Note        string `json:"note,omitempty"`
}

// AuthOptions carries the M2 dependencies. They are optional so an
// unauthenticated M0/M1 build still runs: without them the privileged tools are
// simply not registered, which is better than registering tools that cannot
// work.
type AuthOptions struct {
	Sessions auth.SessionStore
	Denylist *auth.Denylist
}

func registerM2(s *mcp.Server, opt Options) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "rdap_raw",
		Description: "Return the verbatim RDAP JSON a registry sent, unparsed and unredacted. " +
			"Requires the whois:raw scope. Use this when the normalized report is insufficient — " +
			"an unusual field, a vendor extension, or to verify what the registry actually said.",
	}, rawHandler(opt, "rdap"))

	mcp.AddTool(s, &mcp.Tool{
		Name: "whois_raw",
		Description: "Return the verbatim port-43 WHOIS text, plus the referral chain that was " +
			"walked to obtain it. Requires the whois:raw scope. This is the authoritative fallback " +
			"when parse_confidence is low: the raw text is always retained even when parsing fails.",
	}, rawHandler(opt, "whois"))

	if opt.Auth.Sessions == nil {
		return
	}
	mcp.AddTool(s, &mcp.Tool{
		Name: "session_list",
		Description: "List enrolled sessions with their labels, scopes and timings. Requires the " +
			"whois:admin scope. Returns no token material — only what is needed to decide which " +
			"session to revoke.",
	}, sessionListHandler(opt))

	mcp.AddTool(s, &mcp.Tool{
		Name: "session_revoke",
		Description: "Revoke one session by id, invalidating its refresh-token family immediately " +
			"and its access tokens within 10 minutes. Requires the whois:admin scope.",
	}, sessionRevokeHandler(opt))
}

// rawHandler serves rdap_raw and whois_raw.
//
// The scope is re-checked here even though the HTTP gate already enforced it.
// That is not redundancy for its own sake: the gate cannot see inside a batched
// request, and a tool that dumps unredacted contact data should not depend on a
// middleware having correctly identified which tool was called.
func rawHandler(opt Options, proto string) mcp.ToolHandlerFor[RawInput, *resolve.RawResponse] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RawInput) (*mcp.CallToolResult, *resolve.RawResponse, error) {
		if err := auth.RequireScope(ctx, auth.ScopeRaw); err != nil && opt.EnforceScopes {
			return insufficientScope(auth.ScopeRaw), nil, nil
		}
		maxAge := resolve.TTLRaw
		if in.MaxAgeSeconds != nil {
			maxAge = time.Duration(*in.MaxAgeSeconds) * time.Second
		}

		var (
			out *resolve.RawResponse
			err error
		)
		switch proto {
		case "rdap":
			out, err = opt.Resolver.RawRDAP(ctx, in.Domain, maxAge)
		default:
			out, err = opt.Resolver.RawWHOIS(ctx, in.Domain, maxAge)
		}
		if err != nil {
			return errorResult(in.Domain, err), nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summarizeRaw(out)}},
		}, out, nil
	}
}

func sessionListHandler(opt Options) mcp.ToolHandlerFor[struct{}, *SessionListOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, *SessionListOutput, error) {
		if err := auth.RequireScope(ctx, auth.ScopeAdmin); err != nil && opt.EnforceScopes {
			return insufficientScope(auth.ScopeAdmin), nil, nil
		}
		sessions, err := opt.Auth.Sessions.List(ctx)
		if err != nil {
			return errorResult("", err), nil, nil
		}
		current := auth.SessionID(ctx)
		out := &SessionListOutput{Count: len(sessions)}
		for _, s := range sessions {
			out.Sessions = append(out.Sessions, SessionView{
				SID: s.ID, Label: s.Label, Scopes: s.Scopes,
				CreatedAt: s.CreatedAt, LastSeen: s.LastSeen, ExpiresAt: s.ExpiresAt,
				Rotations: s.Rotations, Revoked: s.Revoked,
				Current: s.ID == current,
			})
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summarizeSessions(out)}},
		}, out, nil
	}
}

func sessionRevokeHandler(opt Options) mcp.ToolHandlerFor[SessionRevokeInput, *SessionRevokeOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SessionRevokeInput) (*mcp.CallToolResult, *SessionRevokeOutput, error) {
		if err := auth.RequireScope(ctx, auth.ScopeAdmin); err != nil && opt.EnforceScopes {
			return insufficientScope(auth.ScopeAdmin), nil, nil
		}
		sid := strings.TrimSpace(in.SID)
		if sid == "" {
			return errorResultCode("invalid_request", "", "sid is required"), nil, nil
		}

		if err := opt.Auth.Sessions.Revoke(ctx, sid, time.Now().UTC()); err != nil {
			if errors.Is(err, auth.ErrNoSession) {
				return errorResultCode("not_found", "", "no such session: "+sid), nil, nil
			}
			return errorResult("", err), nil, nil
		}
		if opt.Auth.Denylist != nil {
			opt.Auth.Denylist.Add(ctx, sid)
		}

		out := &SessionRevokeOutput{SID: sid, Revoked: true}
		if sid == auth.SessionID(ctx) {
			out.SelfRevoked = true
			out.Note = "this is the session making the call; its access token stops working within 10 minutes and its refresh token is already dead"
		} else {
			out.Note = "refresh tokens are dead immediately; access tokens stop working within 10 minutes"
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "revoked " + sid + ": " + out.Note}},
		}, out, nil
	}
}

// insufficientScope renders the tool-level step-up error.
//
// The HTTP gate produces the real 403 with a WWW-Authenticate challenge; this is
// what a caller sees if it reaches the handler anyway, and it names the scope so
// the remedy is obvious from the tool result alone.
func insufficientScope(scope string) *mcp.CallToolResult {
	return errorResultCode("insufficient_scope", "",
		fmt.Sprintf("this tool requires the %s scope; re-authorize requesting it", scope))
}

func summarizeRaw(r *resolve.RawResponse) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s raw response for %s\n", r.Protocol, r.Query.ASCII)
	if len(r.Servers) > 0 {
		fmt.Fprintf(&b, "servers: %s\n", strings.Join(r.Servers, " -> "))
	}
	fmt.Fprintf(&b, "fetched: %s (cache %s)", r.FetchedAt.Format(time.RFC3339), r.Cache)
	if r.Truncated {
		b.WriteString("\nwarning: the response was truncated at the size cap")
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\nwarning: %s", w)
	}
	fmt.Fprintf(&b, "\n\n%s", r.Body)
	return b.String()
}

func summarizeSessions(out *SessionListOutput) string {
	if out.Count == 0 {
		return "no sessions enrolled"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d session(s)\n", out.Count)
	for _, s := range out.Sessions {
		fmt.Fprintf(&b, "%s  %-24s scopes=%s last_seen=%s rotations=%d",
			s.SID, s.Label, strings.Join(s.Scopes, ","),
			s.LastSeen.Format(time.RFC3339), s.Rotations)
		if s.Revoked {
			b.WriteString(" REVOKED")
		}
		if s.Current {
			b.WriteString(" (this session)")
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
