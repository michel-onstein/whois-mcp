package mcpsrv

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/qjam/whois-mcp/internal/auth"
	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/resolve"
)

const flowSecret = "integration-enrollment-token-long-enough"

// authedStack builds the whole server the way cmd/whois-mcp does: OAuth
// endpoints plus a bearer-protected, scope-gated /mcp.
//
// This exists because M2's exit criterion is a *flow*, and every piece of it
// passing in isolation would not prove the pieces are wired to each other.
type authedStack struct {
	front  *httptest.Server
	issuer *auth.Issuer
	base   string
}

func newAuthedStack(t *testing.T) *authedStack {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	reg, err := rdapx.NewRegistryForTest(map[string][]string{"uk": {"https://rdap.invalid/"}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	hc := rdapx.NewHTTPClientWithOptions(time.Second, rdapx.HTTPClientOptions{AllowPrivateAddresses: true})
	store := cache.NewMemory()
	res := resolve.New(rdapx.NewClient(reg, hc, "test"), nil, store, quiet)

	kp, err := auth.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring := auth.NewKeyring(kp)
	sessions := auth.NewMemoryStore()
	deny := auth.NewDenylist(store)
	enr, err := auth.NewEnrollment(flowSecret, quiet)
	if err != nil {
		t.Fatalf("NewEnrollment: %v", err)
	}

	mux := http.NewServeMux()
	front := httptest.NewServer(mux)
	t.Cleanup(front.Close)

	// The issuer must name the URL clients actually reach, which is only known
	// once the test server is listening — the same ordering problem a real
	// deployment solves with WHOIS_MCP_PUBLIC_URL.
	issuer := auth.NewIssuer(ring, front.URL, front.URL+auth.PathMCP)

	form := &flowForm{}
	oauthSrv, err := auth.NewServer(auth.ServerOptions{
		Issuer: issuer, Keys: ring, Sessions: sessions, Codes: auth.NewCodeStore(),
		Enrollment: enr, Denylist: deny, Form: form, Log: quiet,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	oauthSrv.Routes(mux)

	server := New(Options{
		Resolver: res, Registry: reg, Log: quiet,
		Auth:          AuthOptions{Sessions: sessions, Denylist: deny},
		EnforceScopes: true,
	})
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
	prm := front.URL + auth.PathPRM
	bearer := sdkauth.RequireBearerToken(
		auth.NewVerifier(issuer, deny).TokenVerifier(),
		&sdkauth.RequireBearerTokenOptions{ResourceMetadataURL: prm, Scopes: auth.MinimumScopes},
	)
	gate := auth.ScopeGate(PrivilegedTools, prm)
	mux.Handle(auth.PathMCP, bearer(gate(handler)))

	return &authedStack{front: front, issuer: issuer, base: front.URL}
}

type flowForm struct{}

func (flowForm) Render(w http.ResponseWriter, _ url.Values, _ string) error {
	_, err := io.WriteString(w, "<form>enroll</form>")
	return err
}

// TestM2ExitCriterion walks design §5.2 end to end: 401, PRM discovery, AS
// metadata, browser enrollment, PKCE code exchange, then an authorized call.
func TestM2ExitCriterion(t *testing.T) {
	st := newAuthedStack(t)

	// 1. An unauthenticated call is refused, and the refusal says where to go.
	resp, err := http.Post(st.base+auth.PathMCP, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp = %d; want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("401 challenge %q does not point at the PRM document", challenge)
	}

	// 2. PRM discovery, then AS metadata.
	var prm auth.PRM
	getJSONFlow(t, st.base+auth.PathPRM, &prm)
	if len(prm.AuthorizationServers) == 0 {
		t.Fatal("PRM names no authorization server")
	}
	var md auth.ASMetadata
	getJSONFlow(t, prm.AuthorizationServers[0]+auth.PathASMetadata, &md)
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" {
		t.Fatalf("AS metadata is incomplete: %+v", md)
	}

	// 3. Browser enrollment at the advertised authorization endpoint.
	verifier, challengeS256 := flowPKCE()
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"integration-client"},
		"redirect_uri":          {"http://127.0.0.1:9/cb"},
		"state":                 {"st8"},
		"code_challenge":        {challengeS256},
		"code_challenge_method": {"S256"},
		"scope":                 {auth.ScopeRead},
		"resource":              {prm.Resource},
		"enrollment_token":      {flowSecret},
		"label":                 {"integration test"},
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err = noRedirect.PostForm(md.AuthorizationEndpoint, form)
	if err != nil {
		t.Fatalf("POST authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST authorize = %d; want 302", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", loc)
	}

	// 4. Code exchange with the PKCE verifier.
	tokResp, err := http.PostForm(md.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://127.0.0.1:9/cb"},
		"client_id":     {"integration-client"},
		"resource":      {prm.Resource},
	})
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("POST token = %d: %s", tokResp.StatusCode, body)
	}
	var tok auth.TokenResponse
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("no access token issued")
	}

	// 5. An MCP client using the Bearer token can list tools.
	cs := connectWithToken(t, st.base+auth.PathMCP, tok.AccessToken)
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools with a Bearer token: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatal("no tools listed")
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"domain_lookup", "domain_availability", "tld_info", "rdap_raw", "whois_raw", "session_list", "session_revoke"} {
		if !names[want] {
			t.Errorf("tool %q missing from the authenticated surface", want)
		}
	}

	// 6. Step-up: this session holds only whois:read, so a raw tool is refused
	// with a 403 naming the scope — design §5.4's one-round-trip step-up.
	rawResp := rawCall(t, st.base+auth.PathMCP, tok.AccessToken, "rdap_raw")
	if rawResp.StatusCode != http.StatusForbidden {
		t.Errorf("rdap_raw with only whois:read = %d; want 403", rawResp.StatusCode)
	}
	if sc := rawResp.Header.Get("WWW-Authenticate"); !strings.Contains(sc, "insufficient_scope") ||
		!strings.Contains(sc, auth.ScopeRaw) {
		t.Errorf("403 challenge = %q; want insufficient_scope naming %s", sc, auth.ScopeRaw)
	}
	rawResp.Body.Close()

	// 7. A token minted for another resource is refused even though it is
	// signed by this server's key: the confused-deputy defence, end to end.
	foreign := auth.NewIssuer(st.issuer.Keyring(), st.base, "https://elsewhere.example/mcp")
	badTok, _, err := foreign.Mint("sess_foreign", "", []string{auth.ScopeRead})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	bad := rawCall(t, st.base+auth.PathMCP, badTok, "domain_lookup")
	bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("token for another resource = %d; want 401", bad.StatusCode)
	}
}

// TestM2RevokedSessionStopsWorking closes the loop on revocation through the
// real stack rather than against the store.
func TestM2RevokedSessionStopsWorking(t *testing.T) {
	st := newAuthedStack(t)
	tok := enroll(t, st, auth.ScopeRead+" "+auth.ScopeAdmin)

	cs := connectWithToken(t, st.base+auth.PathMCP, tok.AccessToken)
	ctx := context.Background()

	// The admin scope lets this session list and revoke itself.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "session_list"})
	if err != nil {
		t.Fatalf("session_list: %v", err)
	}
	if res.IsError {
		t.Fatalf("session_list returned an error result: %+v", res.Content)
	}

	claims, err := st.issuer.Verify(tok.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "session_revoke",
		Arguments: map[string]any{"sid": claims.SID},
	})
	if err != nil {
		t.Fatalf("session_revoke: %v", err)
	}
	if res.IsError {
		t.Fatalf("session_revoke returned an error result: %+v", res.Content)
	}

	// The token is now denylisted, so the next call over a fresh connection is
	// refused at the HTTP layer.
	after := rawCall(t, st.base+auth.PathMCP, tok.AccessToken, "domain_lookup")
	after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked session = %d; want 401", after.StatusCode)
	}
}

// ---- helpers -------------------------------------------------------------

func enroll(t *testing.T, st *authedStack, scope string) auth.TokenResponse {
	t.Helper()
	verifier, challenge := flowPKCE()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirect.PostForm(st.base+auth.PathAuthorize, url.Values{
		"response_type":         {"code"},
		"client_id":             {"c"},
		"redirect_uri":          {"http://127.0.0.1:9/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {scope},
		"enrollment_token":      {flowSecret},
		"label":                 {"test"},
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))

	tr, err := http.PostForm(st.base+auth.PathToken, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://127.0.0.1:9/cb"},
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer tr.Body.Close()
	if tr.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tr.Body)
		t.Fatalf("exchange = %d: %s", tr.StatusCode, body)
	}
	var out auth.TokenResponse
	if err := json.NewDecoder(tr.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func connectWithToken(t *testing.T, endpoint, token string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "flow-test", Version: "0"}, nil)
	hc := &http.Client{Transport: &bearerTransport{token: token, base: http.DefaultTransport}}
	tr := &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: hc}
	cs, err := client.Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// rawCall issues a tools/call directly, because the SDK client turns an HTTP
// 403 into a transport error and this test needs the status and headers.
func rawCall(t *testing.T, endpoint, token, tool string) *http.Response {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool +
		`","arguments":{"domain":"example.uk"}}}`
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	return resp
}

func flowPKCE() (verifier, challenge string) {
	verifier = "integration-verifier-0123456789012345678901234567890"
	return verifier, s256(verifier)
}

func getJSONFlow(t *testing.T, url string, into any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decoding %s: %v", url, err)
	}
}

// s256 is the PKCE challenge derivation, spelled out here rather than imported
// so this test computes it the way a client would.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
