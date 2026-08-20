package mcpsrv

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/resolve"
)

// newTestServer builds a server whose bootstrap registry knows only "uk", so
// the RDAP and WHOIS branches of tld_info are both reachable without a network.
func newTestServer(t *testing.T) (*mcp.Server, Options) {
	t.Helper()
	reg, err := rdapx.NewRegistryForTest(map[string][]string{"uk": {"https://rdap.nominet.invalid/"}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	hc := rdapx.NewHTTPClientWithOptions(time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	res := resolve.New(rdapx.NewClient(reg, hc, "test"), nil, cache.NewMemory(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	opt := Options{Resolver: res, Registry: reg}
	return New(opt), opt
}

func TestSummarizeAvailabilityNamesUnknownsExplicitly(t *testing.T) {
	out := &AvailabilityOutput{Results: []resolve.Availability{
		{Domain: "taken.test", Registered: normalize.Yes},
		{Domain: "free.test", Registered: normalize.No},
		{Domain: "murky.test", Registered: normalize.Unknown, Warning: "rate limited"},
	}}
	got := summarizeAvailability(out)

	if !strings.Contains(got, "1 registered, 1 available, 1 unknown") {
		t.Errorf("summary lacks the counts:\n%s", got)
	}
	// The unknown must be labelled in a way a skimming model cannot read as
	// "available" — that confusion is the failure this whole design guards.
	if !strings.Contains(got, "do not treat as available") {
		t.Errorf("unknown is not explicitly disclaimed:\n%s", got)
	}
	if !strings.Contains(got, "murky.test") {
		t.Errorf("unknown domain not listed:\n%s", got)
	}
}

func TestSummarizeAvailabilityReportsTruncation(t *testing.T) {
	out := &AvailabilityOutput{
		Results:   []resolve.Availability{{Domain: "a.test", Registered: normalize.No}},
		Truncated: true,
	}
	if !strings.Contains(summarizeAvailability(out), "only the first 50") {
		t.Error("truncation is not surfaced; the caller would think all names were checked")
	}
}

func TestLastLabel(t *testing.T) {
	cases := map[string]string{
		"uk":              "uk",
		"co.uk":           "uk",
		"example.co.uk":   "uk",
		"com":             "com",
		"xn--p1ai":        "xn--p1ai",
		"sub.example.dev": "dev",
	}
	for in, want := range cases {
		if got := lastLabel(in); got != want {
			t.Errorf("lastLabel(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestToolSurfaceIsRegistered pins the M1 tool surface: a tool that is designed
// and implemented but never registered is invisible to every client.
func TestToolSurfaceIsRegistered(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"domain_lookup", "domain_availability", "tld_info"} {
		if !names[want] {
			t.Errorf("tool %q is not registered; registered: %v", want, keys(names))
		}
	}

	res, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	found := false
	for _, r := range res.Resources {
		if r.URI == BootstrapResourceURI {
			found = true
		}
	}
	if !found {
		t.Errorf("resource %q is not registered", BootstrapResourceURI)
	}
}

// TestTLDInfoDescribesRDAPAndWHOISPaths covers both branches: a TLD the
// bootstrap map knows, and one it does not.
func TestTLDInfoDescribesRDAPAndWHOISPaths(t *testing.T) {
	_, opt := newTestServer(t)
	h := tldInfoHandler(opt)

	_, out, err := h(context.Background(), nil, TLDInfoInput{TLD: "uk"})
	if err != nil {
		t.Fatalf("tld_info(uk): %v", err)
	}
	if !out.HasRDAP || len(out.RDAPEndpoint) == 0 {
		t.Errorf("uk: HasRDAP=%v endpoints=%v; the test registry publishes one", out.HasRDAP, out.RDAPEndpoint)
	}
	if out.Path != string(normalize.ProtoRDAP) {
		t.Errorf("uk: Path = %q; want rdap", out.Path)
	}

	_, out, err = h(context.Background(), nil, TLDInfoInput{TLD: ".de"})
	if err != nil {
		t.Fatalf("tld_info(.de): %v", err)
	}
	if out.TLD != "de" {
		t.Errorf("TLD = %q; the leading dot should be stripped", out.TLD)
	}
	if out.HasRDAP {
		t.Error("de: HasRDAP = true; the test registry only knows uk")
	}
	if out.Path != string(normalize.ProtoWHOIS) {
		t.Errorf("de: Path = %q; want whois", out.Path)
	}
	if out.Note == "" {
		t.Error("de: no note explaining the WHOIS path and its lower confidence")
	}
	// .de has a quirk, and tld_info is where an agent would discover it.
	if out.Quirk == "" {
		t.Error("de: Quirk is empty; DENIC's query form is in the quirks table")
	}
	if out.WHOISHost == "" {
		t.Error("de: WHOISHost is empty; the seed table knows denic")
	}
}

func TestTLDInfoAcceptsAFullDomain(t *testing.T) {
	_, opt := newTestServer(t)
	_, out, err := tldInfoHandler(opt)(context.Background(), nil, TLDInfoInput{TLD: "example.co.uk"})
	if err != nil {
		t.Fatalf("tld_info: %v", err)
	}
	if out.TLD != "uk" {
		t.Errorf("TLD = %q; want uk", out.TLD)
	}
}

func TestTLDInfoRejectsEmpty(t *testing.T) {
	_, opt := newTestServer(t)
	res, out, err := tldInfoHandler(opt)(context.Background(), nil, TLDInfoInput{TLD: "  "})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if out != nil {
		t.Errorf("out = %+v; want nil on invalid input", out)
	}
	if res == nil || !res.IsError {
		t.Fatal("empty tld did not produce an error result")
	}
	assertToolErrorCode(t, res, "invalid_domain")
}

func TestAvailabilityRejectsEmptyBatch(t *testing.T) {
	_, opt := newTestServer(t)
	res, _, err := availabilityHandler(opt)(context.Background(), nil, AvailabilityInput{})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("empty domains list did not produce an error result")
	}
	assertToolErrorCode(t, res, "invalid_domain")
}

// TestAvailabilityCapsBatch proves the cap is enforced rather than documented.
func TestAvailabilityCapsBatch(t *testing.T) {
	_, opt := newTestServer(t)
	domains := make([]string, resolve.MaxBatch+5)
	for i := range domains {
		domains[i] = "not a domain at all"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, out, err := availabilityHandler(opt)(ctx, nil, AvailabilityInput{Domains: domains})
	if err != nil {
		t.Fatalf("domain_availability: %v", err)
	}
	if !out.Truncated {
		t.Error("Truncated = false for an over-long batch")
	}
	if len(out.Results) != resolve.MaxBatch {
		t.Errorf("Results = %d; want the %d cap", len(out.Results), resolve.MaxBatch)
	}
	// Each bad input must carry its own error rather than failing the batch.
	for i, r := range out.Results {
		if r.Error == "" {
			t.Fatalf("result %d has no error for an unparseable domain", i)
		}
		if r.Registered != normalize.Unknown {
			t.Errorf("result %d: Registered = %q; want unknown", i, r.Registered)
		}
	}
}

func TestBootstrapResourceContent(t *testing.T) {
	_, opt := newTestServer(t)
	res, err := bootstrapResourceHandler(opt)(context.Background(),
		&mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: BootstrapResourceURI}})
	if err != nil {
		t.Fatalf("read resource: %v", err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("Contents = %d; want 1", len(res.Contents))
	}
	if res.Contents[0].MIMEType != "application/json" {
		t.Errorf("MIMEType = %q; want application/json", res.Contents[0].MIMEType)
	}

	var payload BootstrapResource
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if payload.TLDCount == 0 || len(payload.RDAPTLDs) == 0 {
		t.Error("payload lists no TLDs")
	}
	if len(payload.QuirkTLDs) == 0 {
		t.Error("payload lists no quirk TLDs; the table is not empty")
	}
	if payload.WHOISFallback == "" {
		t.Error("payload does not explain how non-RDAP TLDs are served")
	}
}

func assertToolErrorCode(t *testing.T, res *mcp.CallToolResult, want string) {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("error result has no content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T; want TextContent", res.Content[0])
	}
	var te ToolError
	if err := json.Unmarshal([]byte(tc.Text), &te); err != nil {
		t.Fatalf("error payload is not JSON: %v (%s)", err, tc.Text)
	}
	if te.Error != want {
		t.Errorf("error code = %q; want %q", te.Error, want)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
