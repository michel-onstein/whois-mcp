package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Well-known paths (design §5.6).
const (
	PathPRM        = "/.well-known/oauth-protected-resource"
	PathASMetadata = "/.well-known/oauth-authorization-server"
	PathJWKS       = "/.well-known/jwks.json"
	PathAuthorize  = "/oauth/authorize"
	PathToken      = "/oauth/token"
	PathRevoke     = "/oauth/revoke"
	PathRegister   = "/oauth/register"
	PathMCP        = "/mcp"
)

// EnrollmentForm renders the browser page where the operator's token is
// entered. internal/web supplies the implementation; the interface lives here
// so this package does not depend on the HTML.
type EnrollmentForm interface {
	// Render writes the enrollment page. params are the opaque authorization
	// request values that must survive the round trip, and errMsg is non-empty
	// when re-rendering after a failed attempt.
	Render(w http.ResponseWriter, params url.Values, errMsg string) error
}

// ServerOptions configures the authorization server.
type ServerOptions struct {
	Issuer     *Issuer
	Keys       *Keyring
	Sessions   SessionStore
	Codes      *CodeStore
	Enrollment *Enrollment
	Denylist   *Denylist
	Form       EnrollmentForm
	Log        *slog.Logger
	// AllowDirectBearer enables the development escape hatch (design §5.9),
	// where the enrollment token is accepted directly as a bearer token. The
	// caller is responsible for refusing to enable it off loopback.
	AllowDirectBearer bool
}

// Server implements the authorization-server half.
type Server struct {
	opt ServerOptions
	now func() time.Time
}

// NewServer returns a Server.
func NewServer(opt ServerOptions) (*Server, error) {
	if opt.Issuer == nil || opt.Keys == nil || opt.Sessions == nil || opt.Codes == nil {
		return nil, errors.New("issuer, keys, sessions and codes are required")
	}
	if opt.Enrollment == nil {
		return nil, errors.New("enrollment verifier is required")
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.DiscardHandler)
	}
	return &Server{opt: opt, now: time.Now}, nil
}

// Routes registers every OAuth and metadata endpoint on a mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc(PathASMetadata, s.handleASMetadata)
	mux.HandleFunc(PathPRM, s.handlePRM)
	mux.HandleFunc(PathJWKS, s.handleJWKS)
	mux.HandleFunc(PathAuthorize, s.handleAuthorize)
	mux.HandleFunc(PathToken, s.handleToken)
	mux.HandleFunc(PathRevoke, s.handleRevoke)
	mux.HandleFunc(PathRegister, s.handleRegister)
}

// ---------------------------------------------------------------- metadata

// ASMetadata is the RFC 8414 authorization-server metadata document.
type ASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// AuthorizationResponseISSParameterSupported advertises RFC 9207. It is
	// true and it matters: it tells the client to verify which authorization
	// server answered, which is what stops a mix-up attack when a client talks
	// to more than one.
	AuthorizationResponseISSParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
	ResourceIndicatorsSupported                bool `json:"resource_indicators_supported"`
}

func (s *Server) metadata() ASMetadata {
	base := strings.TrimRight(s.opt.Issuer.IssuerURL(), "/")
	return ASMetadata{
		Issuer:                            base,
		AuthorizationEndpoint:             base + PathAuthorize,
		TokenEndpoint:                     base + PathToken,
		RevocationEndpoint:                base + PathRevoke,
		RegistrationEndpoint:              base + PathRegister,
		JWKSURI:                           base + PathJWKS,
		ScopesSupported:                   AllScopes,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		AuthorizationResponseISSParameterSupported: true,
		ResourceIndicatorsSupported:                true,
	}
}

func (s *Server) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, s.metadata())
}

// PRM is the RFC 9728 protected-resource metadata document.
type PRM struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	JWKSURI                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

func (s *Server) handlePRM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	base := strings.TrimRight(s.opt.Issuer.IssuerURL(), "/")
	writeJSON(w, http.StatusOK, PRM{
		Resource:             s.opt.Issuer.Audience(),
		AuthorizationServers: []string{base},
		JWKSURI:              base + PathJWKS,
		// Only the minimum is advertised; raw and admin arrive by step-up, so a
		// read-only client never holds a raw-capable credential.
		ScopesSupported:        MinimumScopes,
		BearerMethodsSupported: []string{"header"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	// Public keys are cacheable, but not for long: a rotation must reach
	// clients within a sensible window or their cached set goes stale.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.opt.Keys.JWKS())
}

// ---------------------------------------------------------------- authorize

// handleAuthorize serves the enrollment page and processes its submission.
//
// GET renders the form. POST verifies the enrollment token and, on success,
// creates a session and redirects with a code. The form is the OAuth
// authorization endpoint's login page, which is what makes "fixed token entered
// in a web interface" a spec-compliant flow rather than a bespoke one.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.authorizeGET(w, r)
	case http.MethodPost:
		s.authorizePOST(w, r)
	default:
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// authRequest is the validated authorization request.
type authRequest struct {
	ClientID    string
	RedirectURI string
	State       string
	Challenge   string
	Resource    string
	Scopes      []string
}

// parseAuthRequest validates an authorization request.
//
// Errors are split by where they can safely be reported. Anything wrong with
// redirect_uri or client_id must be shown to the user in the browser, because
// redirecting to an unvalidated URI to report an error is itself the
// open-redirect bug. Everything else can go back via the redirect.
func (s *Server) parseAuthRequest(q url.Values) (*authRequest, error, bool) {
	redirectURI := q.Get("redirect_uri")
	if err := ValidateRedirectURI(redirectURI); err != nil {
		return nil, err, false // must not redirect
	}

	req := &authRequest{
		ClientID:    q.Get("client_id"),
		RedirectURI: redirectURI,
		State:       q.Get("state"),
		Challenge:   q.Get("code_challenge"),
		Resource:    q.Get("resource"),
	}

	if rt := q.Get("response_type"); rt != "code" {
		return req, fmt.Errorf("unsupported_response_type: %q", rt), true
	}
	if m := q.Get("code_challenge_method"); m != "S256" {
		// OAuth 2.1 requires PKCE and removed "plain"; a client that asks for
		// plain is asking for a challenge equal to its own verifier.
		return req, fmt.Errorf("invalid_request: code_challenge_method must be S256, got %q", m), true
	}
	if req.Challenge == "" {
		return req, errors.New("invalid_request: code_challenge is required"), true
	}
	// RFC 8707: if the client names a resource, it must be this one. Minting a
	// token for a resource the client did not ask for is how a confused-deputy
	// chain starts.
	if req.Resource != "" && !sameResource(req.Resource, s.opt.Issuer.Audience()) {
		return req, fmt.Errorf("invalid_target: this server only issues tokens for %s", s.opt.Issuer.Audience()), true
	}

	req.Scopes = NormalizeScopes(strings.Fields(q.Get("scope")))
	if len(req.Scopes) == 0 {
		req.Scopes = MinimumScopes
	}
	for _, sc := range req.Scopes {
		if !knownScope(sc) {
			return req, fmt.Errorf("invalid_scope: %q", sc), true
		}
	}
	return req, nil, true
}

func (s *Server) authorizeGET(w http.ResponseWriter, r *http.Request) {
	req, err, canRedirect := s.parseAuthRequest(r.URL.Query())
	if err != nil {
		s.authorizeError(w, r, req, err, canRedirect)
		return
	}
	if s.opt.Form == nil {
		http.Error(w, "enrollment form is not configured", http.StatusInternalServerError)
		return
	}
	if err := s.opt.Form.Render(w, r.URL.Query(), ""); err != nil {
		s.opt.Log.Error("rendering enrollment form", "error", err)
	}
}

func (s *Server) authorizePOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return
	}
	req, err, canRedirect := s.parseAuthRequest(r.Form)
	if err != nil {
		s.authorizeError(w, r, req, err, canRedirect)
		return
	}

	presented := r.Form.Get("enrollment_token")
	label := strings.TrimSpace(r.Form.Get("label"))
	if label == "" {
		label = "unnamed session"
	}
	if len(label) > 64 {
		label = label[:64]
	}

	if err := s.opt.Enrollment.Verify(SourceFromRequest(r), presented); err != nil {
		// Re-render the form with a message rather than redirecting: the user is
		// a human in a browser, and the client has nothing to do with a wrong
		// token. The message deliberately does not distinguish wrong-token from
		// locked-out beyond the wait, so it is not an oracle.
		msg := "That enrollment token was not accepted."
		if errors.Is(err, ErrLockedOut) {
			msg = "Too many failed attempts. " + err.Error()
		}
		w.WriteHeader(http.StatusUnauthorized)
		if s.opt.Form != nil {
			if rerr := s.opt.Form.Render(w, r.Form, msg); rerr != nil {
				s.opt.Log.Error("rendering enrollment form", "error", rerr)
			}
		}
		return
	}

	now := s.now().UTC()
	sid, err := NewSessionID()
	if err != nil {
		http.Error(w, "could not create a session", http.StatusInternalServerError)
		return
	}
	sess := &Session{
		ID: sid, Label: label, Scopes: req.Scopes,
		CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(RefreshTTL),
		ClientHint: req.ClientID,
	}
	if err := s.opt.Sessions.Create(r.Context(), sess); err != nil {
		s.opt.Log.Error("creating session", "error", err)
		http.Error(w, "could not create a session", http.StatusInternalServerError)
		return
	}

	code, err := s.opt.Codes.Issue(&AuthCode{
		SessionID: sid, Label: label, Scopes: req.Scopes,
		ClientID: req.ClientID, RedirectURI: req.RedirectURI,
		Challenge: req.Challenge, Resource: req.Resource,
	})
	if err != nil {
		http.Error(w, "could not issue an authorization code", http.StatusInternalServerError)
		return
	}
	// No refresh token exists yet: the client receives its first one from the
	// token endpoint, never from the redirect.
	s.opt.Log.Info("session enrolled", "sid", sid, "label", label, "scopes", req.Scopes)

	target, err := url.Parse(req.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	// RFC 9207: naming ourselves lets the client detect a mix-up attack.
	q.Set("iss", strings.TrimRight(s.opt.Issuer.IssuerURL(), "/"))
	target.RawQuery = q.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// authorizeError reports an authorization failure the correct way round.
func (s *Server) authorizeError(w http.ResponseWriter, r *http.Request, req *authRequest, err error, canRedirect bool) {
	code, desc := splitOAuthError(err)
	if !canRedirect || req == nil || req.RedirectURI == "" {
		// Reporting via the browser, because redirecting to an unvalidated URI
		// to report that it is invalid is the open redirect itself.
		http.Error(w, "authorization request rejected: "+desc, http.StatusBadRequest)
		return
	}
	target, perr := url.Parse(req.RedirectURI)
	if perr != nil {
		http.Error(w, "authorization request rejected: "+desc, http.StatusBadRequest)
		return
	}
	q := target.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", strings.TrimRight(s.opt.Issuer.IssuerURL(), "/"))
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// ---------------------------------------------------------------- token

// TokenResponse is the RFC 6749 token endpoint success payload.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form could not be parsed")
		return
	}
	// The token endpoint must never be cached by anything.
	w.Header().Set("Cache-Control", "no-store")

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.tokenFromCode(w, r)
	case "refresh_token":
		s.tokenFromRefresh(w, r)
	case "":
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"only authorization_code and refresh_token are supported")
	}
}

func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	f := r.Form
	if res := f.Get("resource"); res != "" && !sameResource(res, s.opt.Issuer.Audience()) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target",
			"this server only issues tokens for "+s.opt.Issuer.Audience())
		return
	}

	code, err := s.opt.Codes.Consume(
		f.Get("code"), f.Get("code_verifier"), f.Get("redirect_uri"), f.Get("client_id"))
	if err != nil {
		s.opt.Log.Warn("authorization code exchange failed", "error", err)
		switch {
		case errors.Is(err, ErrPKCEFailed):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		case errors.Is(err, ErrRedirectMismatch):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is not valid")
		}
		return
	}

	sess, err := s.opt.Sessions.Get(r.Context(), code.SessionID)
	if err != nil || !sess.Active(s.now()) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "session is no longer active")
		return
	}

	// The refresh token issued at enrollment is the one bound to this session;
	// find its successor by rotating now, so the client never holds a token the
	// server does not know it holds.
	access, claims, err := s.opt.Issuer.Mint(sess.ID, sess.Label, sess.Scopes)
	if err != nil {
		s.opt.Log.Error("minting access token", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not mint a token")
		return
	}
	refresh, err := s.firstRefresh(r.Context(), sess.ID)
	if err != nil {
		s.opt.Log.Error("issuing refresh token", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue a refresh token")
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(claims.ExpiresAt()).Seconds()),
		RefreshToken: refresh,
		Scope:        strings.Join(sess.Scopes, " "),
	})
}

// firstRefresh issues the refresh token handed to a client at code exchange.
//
// This is the only point at which a session's first refresh token comes into
// existence, so there is never a live token that no client holds.
func (s *Server) firstRefresh(ctx context.Context, sid string) (string, error) {
	next, err := NewRefreshToken()
	if err != nil {
		return "", err
	}
	if err := s.opt.Sessions.IssueRefresh(ctx, sid, next, s.now()); err != nil {
		return "", err
	}
	return next, nil
}

func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	presented := r.Form.Get("refresh_token")
	if presented == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}
	if res := r.Form.Get("resource"); res != "" && !sameResource(res, s.opt.Issuer.Audience()) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target",
			"this server only issues tokens for "+s.opt.Issuer.Audience())
		return
	}

	next, err := NewRefreshToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue a refresh token")
		return
	}
	sess, err := s.opt.Sessions.Rotate(r.Context(), presented, next, s.now().UTC())
	if err != nil {
		var reuse *ReuseError
		if errors.As(err, &reuse) {
			// Theft, not a retry. The family is already revoked by the store;
			// denylist the sid so access tokens stop working within one TTL
			// rather than at the next refresh, and alert.
			if s.opt.Denylist != nil {
				s.opt.Denylist.Add(r.Context(), reuse.SID)
			}
			s.opt.Log.Error("refresh token reuse detected; session family revoked",
				"sid", reuse.SID, "alert", "refresh_token_reuse")
		} else {
			s.opt.Log.Warn("refresh exchange failed", "error", err)
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is not valid")
		return
	}

	access, claims, err := s.opt.Issuer.Mint(sess.ID, sess.Label, sess.Scopes)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not mint a token")
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(time.Until(claims.ExpiresAt()).Seconds()),
		RefreshToken: next,
		Scope:        strings.Join(sess.Scopes, " "),
	})
}

// ---------------------------------------------------------------- revoke

// handleRevoke implements RFC 7009.
//
// The RFC requires 200 for an unrecognised token, which reads wrong at first
// glance: the reason is that a revocation endpoint that distinguishes "revoked"
// from "never existed" is a token oracle.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form could not be parsed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	token := r.Form.Get("token")
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}

	now := s.now().UTC()
	// An access token names its session in a verifiable claim.
	if claims, err := s.opt.Issuer.Verify(token); err == nil {
		s.revokeSession(r.Context(), claims.SID, now)
		w.WriteHeader(http.StatusOK)
		return
	}
	// Otherwise treat it as a refresh token. Rotating it into a throwaway
	// resolves which session it belongs to; the session is then revoked, which
	// also invalidates the successor just issued.
	throwaway, err := NewRefreshToken()
	if err == nil {
		if sess, rerr := s.opt.Sessions.Rotate(r.Context(), token, throwaway, now); rerr == nil {
			s.revokeSession(r.Context(), sess.ID, now)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) revokeSession(ctx context.Context, sid string, now time.Time) {
	if sid == "" {
		return
	}
	if err := s.opt.Sessions.Revoke(ctx, sid, now); err != nil {
		s.opt.Log.Warn("revoking session", "sid", sid, "error", err)
		return
	}
	if s.opt.Denylist != nil {
		s.opt.Denylist.Add(ctx, sid)
	}
	s.opt.Log.Info("session revoked", "sid", sid)
}

// ---------------------------------------------------------------- register

// registrationResponse is the RFC 7591 dynamic client registration reply.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name,omitempty"`
}

// handleRegister implements just enough of RFC 7591 for older clients.
//
// Client ID Metadata Documents are the preferred mechanism in the 2026-07-28
// spec, and this endpoint is retained for compatibility only. It issues a public
// client id and no secret, which is honest rather than lazy: in a single-tenant
// server the enrollment token is the only real credential (design §5.8), so a
// per-client secret would imply a boundary that does not exist.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "body is not valid JSON")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := ValidateRedirectURI(u); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	id, err := randomID(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue a client id")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, registrationResponse{
		ClientID:                "client_" + id,
		ClientIDIssuedAt:        s.now().UTC().Unix(),
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              req.ClientName,
	})
}

// ---------------------------------------------------------------- helpers

func knownScope(s string) bool {
	for _, k := range AllScopes {
		if s == k {
			return true
		}
	}
	return false
}

// sameResource compares resource indicators, ignoring a trailing slash. RFC
// 8707 canonicalization is stricter, but treating ".../mcp" and ".../mcp/" as
// different resources only ever produces a confusing rejection.
func sameResource(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

// splitOAuthError turns "code: description" into its parts.
func splitOAuthError(err error) (code, desc string) {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i > 0 && !strings.Contains(msg[:i], " ") {
		return msg[:i], msg[i+2:]
	}
	return "invalid_request", msg
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status is already written; nothing useful remains but a log, and
		// the caller will see a truncated body.
		return
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
