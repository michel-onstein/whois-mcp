package auth

import (
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

	"github.com/qjam/whois-mcp/internal/cache"
)

const testSecret = "test-enrollment-token-long-enough-to-be-realistic"

// stubForm stands in for internal/web so this package's tests do not depend on
// the HTML. It records what it was asked to render.
type stubForm struct {
	rendered int
	lastErr  string
	lastVals url.Values
}

func (f *stubForm) Render(w http.ResponseWriter, params url.Values, errMsg string) error {
	f.rendered++
	f.lastErr = errMsg
	f.lastVals = params
	w.Header().Set("Content-Type", "text/html")
	_, err := io.WriteString(w, "<form>stub</form>")
	return err
}

type testServer struct {
	*Server
	sessions *MemoryStore
	deny     *Denylist
	issuer   *Issuer
	form     *stubForm
	mux      *http.ServeMux
	http     *httptest.Server
}

func newTestOAuth(t *testing.T) *testServer {
	t.Helper()
	kp, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ring := NewKeyring(kp)
	issuer := NewIssuer(ring, "https://whois.example", "https://whois.example/mcp")
	sessions := NewMemoryStore()
	deny := NewDenylist(cache.NewMemory())
	enr, err := NewEnrollment(testSecret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewEnrollment: %v", err)
	}
	form := &stubForm{}
	srv, err := NewServer(ServerOptions{
		Issuer: issuer, Keys: ring, Sessions: sessions, Codes: NewCodeStore(),
		Enrollment: enr, Denylist: deny, Form: form,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	mux := http.NewServeMux()
	srv.Routes(mux)
	front := httptest.NewServer(mux)
	t.Cleanup(front.Close)

	return &testServer{Server: srv, sessions: sessions, deny: deny,
		issuer: issuer, form: form, mux: mux, http: front}
}

// pkce returns a verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	verifier = "verifier-0123456789012345678901234567890123456789xyz"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeParams(challenge string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"client_test"},
		"redirect_uri":          {"http://127.0.0.1:9999/callback"},
		"state":                 {"opaque-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"whois:read"},
		"resource":              {"https://whois.example/mcp"},
	}
}

// noRedirectClient stops the test client following the authorization redirect,
// so the Location header can be inspected.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// TestFullEnrollmentFlow is M2's exit criterion in one test: enroll, exchange a
// code with PKCE, then refresh.
func TestFullEnrollmentFlow(t *testing.T) {
	ts := newTestOAuth(t)
	verifier, challenge := pkce()
	params := authorizeParams(challenge)

	// The browser lands on the form.
	resp, err := http.Get(ts.http.URL + PathAuthorize + "?" + params.Encode())
	if err != nil {
		t.Fatalf("GET authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET authorize = %d; want 200", resp.StatusCode)
	}
	if ts.form.rendered != 1 {
		t.Fatalf("form rendered %d times; want 1", ts.form.rendered)
	}

	// The user submits the enrollment token.
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("enrollment_token", testSecret)
	form.Set("label", "work laptop")

	resp, err = noRedirectClient().PostForm(ts.http.URL+PathAuthorize, form)
	if err != nil {
		t.Fatalf("POST authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST authorize = %d; want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %s", loc)
	}
	if got := loc.Query().Get("state"); got != "opaque-state" {
		t.Errorf("state = %q; want it echoed back", got)
	}
	// RFC 9207: the client needs this to detect a mix-up attack.
	if got := loc.Query().Get("iss"); got != "https://whois.example" {
		t.Errorf("iss = %q; want the issuer", got)
	}

	// Code exchange with the PKCE verifier.
	tok := ts.exchange(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"client_id":     {"client_test"},
		"resource":      {"https://whois.example/mcp"},
	}, http.StatusOK)

	if tok.TokenType != "Bearer" {
		t.Errorf("token_type = %q", tok.TokenType)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatal("missing tokens in response")
	}
	if tok.ExpiresIn <= 0 || tok.ExpiresIn > int(AccessTokenTTL.Seconds()) {
		t.Errorf("expires_in = %d; want <= %.0f", tok.ExpiresIn, AccessTokenTTL.Seconds())
	}
	claims, err := ts.issuer.Verify(tok.AccessToken)
	if err != nil {
		t.Fatalf("the access token we just issued does not verify: %v", err)
	}
	if claims.Label != "work laptop" {
		t.Errorf("label = %q; want the name the user gave", claims.Label)
	}

	// Refresh rotates.
	next := ts.exchange(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
	}, http.StatusOK)
	if next.RefreshToken == tok.RefreshToken {
		t.Error("refresh did not rotate the token")
	}
	if _, err := ts.issuer.Verify(next.AccessToken); err != nil {
		t.Errorf("refreshed access token does not verify: %v", err)
	}

	// The spent refresh token is now theft evidence: replaying it must kill the
	// family and denylist the session.
	ts.exchange(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
	}, http.StatusBadRequest)

	if !ts.deny.Denied(t.Context(), claims.SID) {
		t.Error("session was not denylisted after refresh-token reuse")
	}
	sess, err := ts.sessions.Get(t.Context(), claims.SID)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	if !sess.Revoked {
		t.Error("session was not revoked after refresh-token reuse")
	}
}

func (ts *testServer) exchange(t *testing.T, form url.Values, wantStatus int) TokenResponse {
	t.Helper()
	resp, err := http.PostForm(ts.http.URL+PathToken, form)
	if err != nil {
		t.Fatalf("POST token: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST token = %d (want %d): %s", resp.StatusCode, wantStatus, body)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("token response Cache-Control = %q; want no-store", cc)
	}
	var out TokenResponse
	if wantStatus == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("token response is not JSON: %v (%s)", err, body)
		}
	}
	return out
}

func TestAuthorizeRejectsBadRequests(t *testing.T) {
	ts := newTestOAuth(t)
	_, challenge := pkce()

	cases := []struct {
		name   string
		mutate func(url.Values)
		// redirected is true when the error may be reported via redirect.
		redirected bool
	}{
		{"missing redirect_uri", func(v url.Values) { v.Del("redirect_uri") }, false},
		{"non-loopback http redirect", func(v url.Values) { v.Set("redirect_uri", "http://evil.example/cb") }, false},
		{"javascript redirect", func(v url.Values) { v.Set("redirect_uri", "javascript:alert(1)") }, false},
		{"redirect with fragment", func(v url.Values) { v.Set("redirect_uri", "https://ok.example/cb#x") }, false},
		{"missing challenge", func(v url.Values) { v.Del("code_challenge") }, true},
		{"plain pkce", func(v url.Values) { v.Set("code_challenge_method", "plain") }, true},
		{"wrong response_type", func(v url.Values) { v.Set("response_type", "token") }, true},
		{"unknown scope", func(v url.Values) { v.Set("scope", "whois:everything") }, true},
		{"wrong resource", func(v url.Values) { v.Set("resource", "https://other.example/mcp") }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			params := authorizeParams(challenge)
			c.mutate(params)

			resp, err := noRedirectClient().Get(ts.http.URL + PathAuthorize + "?" + params.Encode())
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()

			if c.redirected {
				if resp.StatusCode != http.StatusFound {
					t.Fatalf("status = %d; want a 302 carrying the error", resp.StatusCode)
				}
				loc, _ := url.Parse(resp.Header.Get("Location"))
				if loc.Query().Get("error") == "" {
					t.Errorf("redirect %s carries no error parameter", loc)
				}
				return
			}
			// A bad redirect_uri must never be redirected to — that is the
			// open-redirect bug this split exists to avoid.
			if resp.StatusCode == http.StatusFound {
				t.Fatalf("server redirected to an unvalidated redirect_uri: %s",
					resp.Header.Get("Location"))
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d; want 400", resp.StatusCode)
			}
		})
	}
}

func TestAuthorizeWrongTokenRerendersFormWithoutRedirect(t *testing.T) {
	ts := newTestOAuth(t)
	_, challenge := pkce()
	form := authorizeParams(challenge)
	form.Set("enrollment_token", "wrong")

	resp, err := noRedirectClient().PostForm(ts.http.URL+PathAuthorize, form)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("a wrong token produced a redirect to %s; the client is not at fault and must not be told", loc)
	}
	if ts.form.lastErr == "" {
		t.Error("form was re-rendered without an error message")
	}
	if strings.Contains(ts.form.lastErr, "wrong") {
		t.Error("the error message echoes the presented token")
	}
}

// freshCode enrolls and returns a usable authorization code.
//
// Every rejection case needs its own: Consume spends a code before validating
// it, so even a failed exchange burns it. That is deliberate — leaving a code
// alive after a bad verifier would let someone who intercepted it brute-force
// the PKCE challenge.
func (ts *testServer) freshCode(t *testing.T, challenge string) string {
	t.Helper()
	form := authorizeParams(challenge)
	form.Set("enrollment_token", testSecret)
	resp, err := noRedirectClient().PostForm(ts.http.URL+PathAuthorize, form)
	if err != nil {
		t.Fatalf("POST authorize: %v", err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code issued (status %d)", resp.StatusCode)
	}
	return code
}

func TestTokenEndpointRejections(t *testing.T) {
	ts := newTestOAuth(t)
	verifier, challenge := pkce()

	t.Run("wrong pkce verifier", func(t *testing.T) {
		ts.exchange(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {ts.freshCode(t, challenge)},
			"code_verifier": {"wrong-verifier-that-is-long-enough-to-pass-length-check"},
			"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		}, http.StatusBadRequest)
	})

	t.Run("mismatched redirect_uri", func(t *testing.T) {
		ts.exchange(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {ts.freshCode(t, challenge)},
			"code_verifier": {verifier},
			"redirect_uri":  {"http://127.0.0.1:1111/other"},
		}, http.StatusBadRequest)
	})

	t.Run("wrong resource", func(t *testing.T) {
		ts.exchange(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {ts.freshCode(t, challenge)},
			"code_verifier": {verifier},
			"redirect_uri":  {"http://127.0.0.1:9999/callback"},
			"resource":      {"https://other.example/mcp"},
		}, http.StatusBadRequest)
	})

	t.Run("unsupported grant", func(t *testing.T) {
		ts.exchange(t, url.Values{"grant_type": {"password"}}, http.StatusBadRequest)
	})

	t.Run("missing grant", func(t *testing.T) {
		ts.exchange(t, url.Values{}, http.StatusBadRequest)
	})

	t.Run("code is single use", func(t *testing.T) {
		good := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {ts.freshCode(t, challenge)},
			"code_verifier": {verifier},
			"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		}
		ts.exchange(t, good, http.StatusOK)
		ts.exchange(t, good, http.StatusBadRequest)
	})

	// A failed exchange must also spend the code, not just a successful one.
	t.Run("a rejected exchange still burns the code", func(t *testing.T) {
		code := ts.freshCode(t, challenge)
		ts.exchange(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"code_verifier": {"wrong-verifier-that-is-long-enough-to-pass-length-check"},
			"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		}, http.StatusBadRequest)
		// Now with the correct verifier: still refused, because the code is gone.
		ts.exchange(t, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"code_verifier": {verifier},
			"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		}, http.StatusBadRequest)
	})
}

func TestRevokeIsIdempotentAndSilent(t *testing.T) {
	ts := newTestOAuth(t)
	verifier, challenge := pkce()

	tok := ts.exchange(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {ts.freshCode(t, challenge)},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
	}, http.StatusOK)
	claims, _ := ts.issuer.Verify(tok.AccessToken)

	// Revoking an access token revokes its session.
	post := func(v url.Values) int {
		r, err := http.PostForm(ts.http.URL+PathRevoke, v)
		if err != nil {
			t.Fatalf("POST revoke: %v", err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if got := post(url.Values{"token": {tok.AccessToken}}); got != http.StatusOK {
		t.Errorf("revoke = %d; want 200", got)
	}
	if !ts.deny.Denied(t.Context(), claims.SID) {
		t.Error("session not denylisted after revocation")
	}

	// RFC 7009: an unknown token still gets 200, because distinguishing
	// "revoked" from "never existed" is a token oracle.
	if got := post(url.Values{"token": {"never-existed"}}); got != http.StatusOK {
		t.Errorf("revoke(unknown) = %d; want 200", got)
	}
	// Idempotent.
	if got := post(url.Values{"token": {tok.AccessToken}}); got != http.StatusOK {
		t.Errorf("second revoke = %d; want 200", got)
	}
	if got := post(url.Values{}); got != http.StatusBadRequest {
		t.Errorf("revoke with no token = %d; want 400", got)
	}
}

func TestMetadataDocuments(t *testing.T) {
	ts := newTestOAuth(t)

	t.Run("as metadata", func(t *testing.T) {
		var md ASMetadata
		getJSON(t, ts.http.URL+PathASMetadata, &md)
		if md.Issuer != "https://whois.example" {
			t.Errorf("issuer = %q", md.Issuer)
		}
		if !md.AuthorizationResponseISSParameterSupported {
			t.Error("authorization_response_iss_parameter_supported must be true (RFC 9207)")
		}
		if len(md.CodeChallengeMethodsSupported) != 1 || md.CodeChallengeMethodsSupported[0] != "S256" {
			t.Errorf("code_challenge_methods_supported = %v; want only S256", md.CodeChallengeMethodsSupported)
		}
		if !md.ResourceIndicatorsSupported {
			t.Error("resource_indicators_supported must be true (RFC 8707)")
		}
		for _, want := range []string{"authorization_code", "refresh_token"} {
			found := false
			for _, g := range md.GrantTypesSupported {
				if g == want {
					found = true
				}
			}
			if !found {
				t.Errorf("grant_types_supported lacks %q", want)
			}
		}
	})

	t.Run("prm advertises only the minimum scope", func(t *testing.T) {
		var prm PRM
		getJSON(t, ts.http.URL+PathPRM, &prm)
		if prm.Resource != "https://whois.example/mcp" {
			t.Errorf("resource = %q", prm.Resource)
		}
		if len(prm.ScopesSupported) != 1 || prm.ScopesSupported[0] != ScopeRead {
			t.Errorf("scopes_supported = %v; raw and admin must come via step-up", prm.ScopesSupported)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		var jwks JWKS
		getJSON(t, ts.http.URL+PathJWKS, &jwks)
		if len(jwks.Keys) != 1 || jwks.Keys[0].Alg != "EdDSA" {
			t.Errorf("jwks = %+v", jwks)
		}
	})
}

func TestRegisterIssuesPublicClient(t *testing.T) {
	ts := newTestOAuth(t)

	body := strings.NewReader(`{"redirect_uris":["http://127.0.0.1:7777/cb"],"client_name":"Test Client"}`)
	resp, err := http.Post(ts.http.URL+PathRegister, "application/json", body)
	if err != nil {
		t.Fatalf("POST register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d; want 201", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["client_id"] == "" || out["client_id"] == nil {
		t.Error("no client_id issued")
	}
	// No secret: in a single-tenant server the enrollment token is the only
	// real credential, so a per-client secret would imply a boundary that does
	// not exist.
	if _, ok := out["client_secret"]; ok {
		t.Error("a client_secret was issued; this is a public-client-only server")
	}
	if out["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method = %v; want none", out["token_endpoint_auth_method"])
	}
}

func TestRegisterRejectsBadRedirect(t *testing.T) {
	ts := newTestOAuth(t)
	body := strings.NewReader(`{"redirect_uris":["http://evil.example/cb"]}`)
	resp, err := http.Post(ts.http.URL+PathRegister, "application/json", body)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	ts := newTestOAuth(t)
	cases := map[string]string{
		PathASMetadata: http.MethodPost,
		PathPRM:        http.MethodPost,
		PathJWKS:       http.MethodPost,
		PathToken:      http.MethodGet,
		PathRevoke:     http.MethodGet,
		PathRegister:   http.MethodGet,
	}
	for path, method := range cases {
		req, _ := http.NewRequest(method, ts.http.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d; want 405", method, path, resp.StatusCode)
		}
		if resp.Header.Get("Allow") == "" {
			t.Errorf("%s %s: no Allow header", method, path)
		}
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier, challenge := pkce()
	if !VerifyPKCE(challenge, verifier) {
		t.Error("valid pair rejected")
	}
	if VerifyPKCE(challenge, verifier+"x") {
		t.Error("wrong verifier accepted")
	}
	if VerifyPKCE("", verifier) || VerifyPKCE(challenge, "") {
		t.Error("empty challenge or verifier accepted")
	}
	// RFC 7636 length bounds: a short verifier is brute-forceable.
	if VerifyPKCE(challenge, "tooshort") {
		t.Error("a verifier below 43 characters was accepted")
	}
	if VerifyPKCE(challenge, strings.Repeat("a", 129)) {
		t.Error("a verifier above 128 characters was accepted")
	}
	// A "plain" style challenge (challenge == verifier) must not validate.
	if VerifyPKCE(verifier, verifier) {
		t.Error("plain PKCE was accepted; OAuth 2.1 removed it")
	}
}

func TestValidateRedirectURI(t *testing.T) {
	ok := []string{
		"https://client.example/cb",
		"http://127.0.0.1:9999/cb",
		"http://localhost:1234/cb",
		"http://[::1]:8080/cb",
		"com.example.app:/oauth",
	}
	for _, u := range ok {
		if err := ValidateRedirectURI(u); err != nil {
			t.Errorf("ValidateRedirectURI(%q) = %v; want ok", u, err)
		}
	}
	bad := []string{
		"", "   ",
		"http://evil.example/cb",
		"javascript:alert(1)",
		"data:text/html,<script>",
		"file:///etc/passwd",
		"myapp:/cb", // no dot: any app could claim it
		"/relative",
		"https://ok.example/cb#frag",
	}
	for _, u := range bad {
		if err := ValidateRedirectURI(u); err == nil {
			t.Errorf("ValidateRedirectURI(%q) accepted", u)
		}
	}
}

func TestAuthCodeExpires(t *testing.T) {
	cs := NewCodeStore()
	base := time.Now()
	cs.now = func() time.Time { return base }
	verifier, challenge := pkce()

	code, err := cs.Issue(&AuthCode{SessionID: "sess_1", Challenge: challenge,
		RedirectURI: "https://c.example/cb"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cs.now = func() time.Time { return base.Add(AuthCodeTTL + time.Second) }
	if _, err := cs.Consume(code, verifier, "https://c.example/cb", ""); err == nil {
		t.Error("an expired code was accepted")
	}
}

func getJSON(t *testing.T, url string, into any) {
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
