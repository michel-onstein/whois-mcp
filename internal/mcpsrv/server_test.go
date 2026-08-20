package mcpsrv

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/normalize"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/resolve"
)

// newStack builds the whole server over a fake registry, then exposes it on a
// real Streamable HTTP endpoint — the same wiring cmd/whois-mcp uses.
func newStack(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	upstream := httptest.NewServer(h)
	t.Cleanup(upstream.Close)

	reg, err := rdapx.NewRegistryForTest(map[string][]string{"com": {upstream.URL + "/"}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	hc := rdapx.NewHTTPClientWithOptions(5*time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	res := resolve.New(rdapx.NewClient(reg, hc, "test"), cache.NewMemory(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	srv := New(Options{Resolver: res, Registry: reg})
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)
	return front
}

func connect(t *testing.T, endpoint string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func comFixture(t *testing.T) http.HandlerFunc {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rdap", "com-registered.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write(body)
	}
}

func TestToolsListAdvertisesDomainLookup(t *testing.T) {
	front := newStack(t, comFixture(t))
	sess := connect(t, front.URL)

	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var found *mcp.Tool
	for _, tool := range res.Tools {
		if tool.Name == "domain_lookup" {
			found = tool
		}
	}
	if found == nil {
		t.Fatalf("domain_lookup not advertised; got %d tools", len(res.Tools))
	}
	if found.InputSchema == nil {
		t.Fatal("domain_lookup has no input schema")
	}
	raw, err := json.Marshal(found.InputSchema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	if !strings.Contains(string(raw), "domain") {
		t.Errorf("input schema does not mention the domain property: %s", raw)
	}
	if found.Description == "" {
		t.Error("tool has no description for the model to reason about")
	}
}

func TestCallDomainLookupEndToEnd(t *testing.T) {
	front := newStack(t, comFixture(t))
	sess := connect(t, front.URL)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "domain_lookup",
		Arguments: map[string]any{"domain": "https://WWW.Example.com/path"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned an error result: %+v", res.Content)
	}

	// Structured output is the contract an agent consumes.
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var rep normalize.DomainReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("structured content is not a DomainReport: %v\n%s", err, raw)
	}
	if rep.Registered != normalize.Yes {
		t.Errorf("Registered = %q, want yes", rep.Registered)
	}
	if rep.Query.ASCII != "example.com" {
		t.Errorf("ASCII = %q, want example.com", rep.Query.ASCII)
	}
	if rep.Dates.Created == nil {
		t.Error("Created missing from structured output")
	}

	// A human-readable block must accompany it for models that ignore
	// structuredContent.
	if len(res.Content) == 0 {
		t.Fatal("no text content returned")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, "example.com") {
		t.Errorf("text content missing or unhelpful: %+v", res.Content[0])
	}
}

func TestCallDomainLookupInvalidInput(t *testing.T) {
	front := newStack(t, comFixture(t))
	sess := connect(t, front.URL)

	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "domain_lookup",
		Arguments: map[string]any{"domain": "not a domain at all"},
	})
	if err != nil {
		t.Fatalf("CallTool transport error: %v", err)
	}
	if !res.IsError {
		t.Fatal("invalid input did not produce an error result")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", res.Content[0])
	}
	var te ToolError
	if err := json.Unmarshal([]byte(text.Text), &te); err != nil {
		t.Fatalf("error payload is not structured JSON: %v (%q)", err, text.Text)
	}
	if te.Error != "invalid_domain" {
		t.Errorf("error code = %q, want invalid_domain", te.Error)
	}
}

// Statelessness is the design target: the server must not issue or require a
// session id, and GET must be refused.
func TestTransportIsStateless(t *testing.T) {
	front := newStack(t, comFixture(t))

	resp, err := http.Get(front.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405 in stateless mode", resp.StatusCode)
	}
	if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
		t.Errorf("server issued Mcp-Session-Id %q; sessions were removed in 2026-07-28", id)
	}
}
