package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// gateStack builds the real middleware pair: authenticate, then gate. Testing
// the gate alone would miss the ordering, which is the part that can silently
// break — a gate that runs before authentication sees no scopes and refuses
// everything.
func gateStack(t *testing.T, scopes ToolScopes) (http.Handler, *Issuer) {
	t.Helper()
	i := testIssuer(t)
	v := NewVerifier(i, NewDenylist(nil))
	reached := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		// Echo the body so a test can prove the gate restored it.
		_, _ = w.Write(body)
	}
	bearer := sdkauth.RequireBearerToken(v.TokenVerifier(), &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: "https://whois.example" + PathPRM,
		Scopes:              MinimumScopes,
	})
	gate := ScopeGate(scopes, "https://whois.example"+PathPRM)
	return bearer(gate(http.HandlerFunc(reached))), i
}

func callTool(t *testing.T, h http.Handler, token, tool string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var testToolScopes = ToolScopes{
	"rdap_raw":     ScopeRaw,
	"session_list": ScopeAdmin,
}

func TestScopeGateAllowsBaselineTool(t *testing.T) {
	h, i := gateStack(t, testToolScopes)
	tok, _, _ := i.Mint("sess_1", "", []string{ScopeRead})

	rec := callTool(t, h, tok, "domain_lookup")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 for an ungated tool: %s", rec.Code, rec.Body)
	}
	// The gate buffered the body to read the tool name; the handler must still
	// have received all of it.
	if !strings.Contains(rec.Body.String(), "domain_lookup") {
		t.Errorf("handler did not receive the full body: %s", rec.Body)
	}
}

// TestScopeGateStepUp is design §5.4: 403 plus a challenge naming the scope, so
// the client can step up in one round trip.
func TestScopeGateStepUp(t *testing.T) {
	h, i := gateStack(t, testToolScopes)
	readOnly, _, _ := i.Mint("sess_1", "", []string{ScopeRead})

	rec := callTool(t, h, readOnly, "rdap_raw")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want 403", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	for _, want := range []string{`error="insufficient_scope"`, `scope="whois:raw"`, "resource_metadata="} {
		if !strings.Contains(challenge, want) {
			t.Errorf("challenge %q lacks %s", challenge, want)
		}
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not JSON: %v (%s)", err, rec.Body)
	}
	if body["error"] != "insufficient_scope" || body["scope"] != ScopeRaw {
		t.Errorf("403 body = %v", body)
	}
}

func TestScopeGateAllowsWithScope(t *testing.T) {
	h, i := gateStack(t, testToolScopes)
	raw, _, _ := i.Mint("sess_1", "", []string{ScopeRead, ScopeRaw})

	if rec := callTool(t, h, raw, "rdap_raw"); rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 with whois:raw: %s", rec.Code, rec.Body)
	}
	// whois:raw does not imply whois:admin.
	if rec := callTool(t, h, raw, "session_list"); rec.Code != http.StatusForbidden {
		t.Errorf("session_list with only whois:raw = %d; want 403", rec.Code)
	}

	admin, _, _ := i.Mint("sess_2", "", []string{ScopeRead, ScopeAdmin})
	if rec := callTool(t, h, admin, "session_list"); rec.Code != http.StatusOK {
		t.Errorf("session_list with whois:admin = %d; want 200", rec.Code)
	}
}

func TestScopeGateRequiresAuthenticationFirst(t *testing.T) {
	h, _ := gateStack(t, testToolScopes)
	// No token at all: the bearer middleware answers 401 before the gate runs.
	rec := callTool(t, h, "", "rdap_raw")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401 with no token", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 carries no WWW-Authenticate challenge")
	}
}

func TestToolNameFromBody(t *testing.T) {
	cases := map[string]string{
		`{"method":"tools/call","params":{"name":"rdap_raw"}}`:   "rdap_raw",
		`  {"method":"tools/call","params":{"name":" padded "}}`: "padded",
		`{"method":"tools/list"}`:                                "",
		`{"method":"tools/call","params":{}}`:                    "",
		`{"method":"tools/call"}`:                                "",
		`not json`:                                               "",
		``:                                                       "",
		// A batch is an array: one 403 cannot answer a mixed batch, so the gate
		// declines to guess and the handler's own check is the backstop.
		`[{"method":"tools/call","params":{"name":"rdap_raw"}}]`: "",
	}
	for body, want := range cases {
		if got := toolNameFromBody([]byte(body)); got != want {
			t.Errorf("toolNameFromBody(%q) = %q; want %q", body, got, want)
		}
	}
}

// TestScopeGateIgnoresNonPostAndUnknownTools keeps the gate from becoming a
// second, divergent implementation of the protocol.
func TestScopeGateIgnoresNonPostAndUnknownTools(t *testing.T) {
	h, i := gateStack(t, testToolScopes)
	tok, _, _ := i.Mint("sess_1", "", []string{ScopeRead})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Error("the gate rejected a GET; it should only inspect tool calls")
	}

	if rec := callTool(t, h, tok, "some_future_tool"); rec.Code != http.StatusOK {
		t.Errorf("unlisted tool = %d; want 200 (the baseline scope already covered it)", rec.Code)
	}
}

func TestScopeGateEmptyMapIsPassthrough(t *testing.T) {
	h, i := gateStack(t, ToolScopes{})
	tok, _, _ := i.Mint("sess_1", "", []string{ScopeRead})
	if rec := callTool(t, h, tok, "rdap_raw"); rec.Code != http.StatusOK {
		t.Errorf("status = %d; want 200 with no gated tools configured", rec.Code)
	}
}
