// Package web is the enrollment browser UI: one page, one form.
//
// No framework and no build step, by design (plan task 2.12). The page is a
// single html/template embedded in the binary, which keeps the deployment a
// single static binary and means the UI cannot drift out of sync with the
// server that serves it.
//
// html/template rather than text/template matters here beyond style: every
// value on this page comes from a query string an attacker can construct, and
// contextual auto-escaping is what stops a crafted state parameter becoming
// script in the page that asks for the enrollment token.
package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/qjam/whois-mcp/internal/auth"
)

//go:embed templates/enroll.html
var templatesFS embed.FS

// preservedParams are the authorization-request values that must survive the
// form round trip. Anything not on this list is dropped rather than reflected:
// echoing arbitrary caller-supplied parameters back into a hidden input is how
// a form becomes a parameter-smuggling vector.
var preservedParams = []string{
	"response_type", "client_id", "redirect_uri", "state",
	"code_challenge", "code_challenge_method", "scope", "resource",
}

// scopeDescriptions explain each scope in the terms a person consenting cares
// about, not in the terms the code uses.
var scopeDescriptions = map[string]string{
	auth.ScopeRead:  "look up domain registration data",
	auth.ScopeRaw:   "read the unredacted raw RDAP and WHOIS responses",
	auth.ScopeAdmin: "list and revoke enrolled sessions",
}

// Form renders the enrollment page.
type Form struct {
	tmpl   *template.Template
	action string
}

// NewForm parses the embedded template.
//
// It returns an error rather than panicking so a template typo surfaces at
// startup, next to the rest of the configuration, instead of on the first
// enrollment attempt.
func NewForm(action string) (*Form, error) {
	t, err := template.ParseFS(templatesFS, "templates/enroll.html")
	if err != nil {
		return nil, fmt.Errorf("parsing enrollment template: %w", err)
	}
	if action == "" {
		action = auth.PathAuthorize
	}
	return &Form{tmpl: t, action: action}, nil
}

type hiddenField struct{ Name, Value string }

type scopeRow struct{ Name, Description string }

type pageData struct {
	Action   string
	Error    string
	Hidden   []hiddenField
	Scopes   []scopeRow
	Label    string
	ClientID string
	Resource string
}

// Render writes the enrollment page. It satisfies auth.EnrollmentForm.
func (f *Form) Render(w http.ResponseWriter, params url.Values, errMsg string) error {
	data := pageData{
		Action:   f.action,
		Error:    errMsg,
		Label:    params.Get("label"),
		ClientID: params.Get("client_id"),
		Resource: params.Get("resource"),
	}
	for _, name := range preservedParams {
		if v := params.Get(name); v != "" {
			data.Hidden = append(data.Hidden, hiddenField{Name: name, Value: v})
		}
	}

	requested := auth.NormalizeScopes(strings.Fields(params.Get("scope")))
	if len(requested) == 0 {
		requested = auth.MinimumScopes
	}
	for _, s := range requested {
		desc, ok := scopeDescriptions[s]
		if !ok {
			// An unknown scope is still shown rather than hidden: the request
			// will be rejected, and a person looking at the page should be able
			// to see why.
			desc = "unrecognised scope"
		}
		data.Scopes = append(data.Scopes, scopeRow{Name: s, Description: desc})
	}
	sort.Slice(data.Scopes, func(i, j int) bool { return data.Scopes[i].Name < data.Scopes[j].Name })

	// Headers first: this page carries a credential field, so it must not be
	// cached, framed, or referred onward.
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	// The page needs no scripts at all, so the strictest useful policy is also
	// the correct one. 'unsafe-inline' is present for the one <style> block and
	// nothing else; there is no script-src allowance of any kind.
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

	return f.tmpl.Execute(w, data)
}
