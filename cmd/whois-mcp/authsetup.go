package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/qjam/whois-mcp/internal/auth"
	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/mcpsrv"
	"github.com/qjam/whois-mcp/internal/web"
)

// authConfig is the M2 configuration.
type authConfig struct {
	// enrollmentToken is the operator's fixed secret. Empty disables auth
	// entirely, which is only permitted on loopback.
	enrollmentToken string
	// signingKey is the Ed25519 seed or PEM. Empty generates an ephemeral key,
	// which is fine for one process and wrong for more than one — every replica
	// would mint tokens the others reject.
	signingKey string
	// publicURL is the canonical https URL clients reach us on. It is the token
	// issuer and, with /mcp appended, the audience, so it must match what
	// clients actually use or every token is rejected.
	publicURL string
	// devStaticBearer enables design §5.9's escape hatch.
	devStaticBearer bool
}

func loadAuthConfig() authConfig {
	return authConfig{
		enrollmentToken: strings.TrimSpace(env("WHOIS_MCP_ENROLLMENT_TOKEN", "")),
		signingKey:      strings.TrimSpace(env("WHOIS_MCP_SIGNING_KEY", "")),
		publicURL:       strings.TrimRight(env("WHOIS_MCP_PUBLIC_URL", ""), "/"),
		devStaticBearer: env("WHOIS_MCP_DEV_STATIC_BEARER", "") == "true",
	}
}

// authStack is everything M2 contributes to the running server.
type authStack struct {
	server    *auth.Server
	verifier  *auth.Verifier
	sessions  auth.SessionStore
	denylist  *auth.Denylist
	issuer    *auth.Issuer
	protect   func(http.Handler) http.Handler
	staticTok string
}

// buildAuth assembles the authorization server.
//
// It returns (nil, nil) when no enrollment token is configured, which is the
// unauthenticated M0/M1 shape. Whether that is permissible is decided by
// checkExposure, not here: this function's job is to build what it was asked
// for, and the security gate is a single explicit check rather than a condition
// scattered across the setup.
// sessions must be the store chosen by configuration, not one built here.
// Building a store locally is exactly how the Redis session store ended up
// implemented, tested, and never connected: WHOIS_MCP_SESSION_STORE=redis
// created a RedisStore in buildStores that nothing referenced, so every replica
// kept sessions in its own memory and a client that enrolled against one was
// rejected by the next. The compose end-to-end run caught it; nothing
// single-process could have.
func buildAuth(cfg config, ac authConfig, store cache.Cache, sessions auth.SessionStore, log *slog.Logger) (*authStack, error) {
	if ac.enrollmentToken == "" {
		return nil, nil
	}
	if sessions == nil {
		return nil, errors.New("a session store is required to enable authentication")
	}

	publicURL := ac.publicURL
	if publicURL == "" {
		// Loopback development: derive it so the flow works without extra
		// configuration. A non-loopback deployment must set it explicitly,
		// because guessing the canonical URI wrong rejects every token.
		publicURL = "http://" + cfg.listen
		log.Warn("WHOIS_MCP_PUBLIC_URL is not set; deriving it from the listen address",
			"public_url", publicURL,
			"note", "set it explicitly for any deployment behind a proxy or ingress")
	}
	if err := requireHTTPSOffLoopback(publicURL); err != nil {
		return nil, err
	}

	keyring, err := buildKeyring(ac.signingKey, log)
	if err != nil {
		return nil, err
	}

	issuer := auth.NewIssuer(keyring, publicURL, publicURL+auth.PathMCP)
	denylist := auth.NewDenylist(store)

	enrollment, err := auth.NewEnrollment(ac.enrollmentToken, log)
	if err != nil {
		return nil, err
	}
	form, err := web.NewForm(auth.PathAuthorize)
	if err != nil {
		return nil, err
	}
	srv, err := auth.NewServer(auth.ServerOptions{
		Issuer: issuer, Keys: keyring, Sessions: sessions,
		Codes: auth.NewCodeStore(), Enrollment: enrollment,
		Denylist: denylist, Form: form, Log: log,
		AllowDirectBearer: ac.devStaticBearer,
	})
	if err != nil {
		return nil, err
	}

	verifier := auth.NewVerifier(issuer, denylist)
	tokenVerifier := verifier.TokenVerifier()
	staticTok := ""
	if ac.devStaticBearer {
		staticTok = ac.enrollmentToken
		tokenVerifier = withStaticBearer(tokenVerifier, ac.enrollmentToken, log)
	}

	prmURL := publicURL + auth.PathPRM
	bearer := sdkauth.RequireBearerToken(tokenVerifier, &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: prmURL,
		Scopes:              auth.MinimumScopes,
		// A few seconds of tolerance: a replica whose clock trails the one that
		// minted a token would otherwise reject tokens that are valid.
		ClockSkew: 5 * 1000 * 1000 * 1000, // 5s
	})
	gate := auth.ScopeGate(mcpsrv.PrivilegedTools, prmURL)

	return &authStack{
		server: srv, verifier: verifier, sessions: sessions,
		denylist: denylist, issuer: issuer, staticTok: staticTok,
		// Order matters: authenticate first so the scope gate can read the
		// token's scopes out of the request context.
		protect: func(next http.Handler) http.Handler { return bearer(gate(next)) },
	}, nil
}

func buildKeyring(spec string, log *slog.Logger) (*auth.Keyring, error) {
	if spec == "" {
		kp, err := auth.GenerateKey()
		if err != nil {
			return nil, err
		}
		log.Warn("no WHOIS_MCP_SIGNING_KEY set; generated an ephemeral signing key",
			"kid", kp.ID,
			"note", "every restart invalidates all tokens, and multiple replicas will reject each other's")
		return auth.NewKeyring(kp), nil
	}
	kp, err := auth.ParseKey(spec)
	if err != nil {
		return nil, fmt.Errorf("WHOIS_MCP_SIGNING_KEY: %w", err)
	}
	log.Info("signing key loaded", "kid", kp.ID)
	return auth.NewKeyring(kp), nil
}

// withStaticBearer wraps a verifier so the enrollment token may be presented
// directly as a bearer token (design §5.9).
//
// It exists so curl and early integration tests are not blocked on a browser
// flow. It grants every scope, because a development hatch that could not reach
// the raw tools would not save anyone any time — which is also exactly why
// checkExposure refuses to let it run anywhere but loopback.
func withStaticBearer(next sdkauth.TokenVerifier, token string, log *slog.Logger) sdkauth.TokenVerifier {
	return func(ctx context.Context, presented string, r *http.Request) (*sdkauth.TokenInfo, error) {
		if presented == token {
			log.Warn("accepted the enrollment token as a bearer token (WHOIS_MCP_DEV_STATIC_BEARER)")
			return &sdkauth.TokenInfo{
				Scopes:     auth.AllScopes,
				Expiration: nowPlusHour(),
				UserID:     "sess_dev_static",
				Extra:      map[string]any{"dev_static_bearer": true},
			}, nil
		}
		return next(ctx, presented, r)
	}
}

// checkExposure is the security gate of plan §7, in one place.
//
// M0 and M1 are a fully functional unauthenticated service, so an
// unauthenticated instance reachable off-host is an open proxy that queries
// registries from our egress IP — and the resulting block presents as a total
// outage for the affected TLD. The development bearer hatch is refused off
// loopback for the same reason: it makes the enrollment token a request
// credential, so anyone who sees one request has full access.
func checkExposure(cfg config, ac authConfig) error {
	loopback := requireLoopback(cfg.listen) == nil

	if ac.enrollmentToken == "" && !loopback {
		return fmt.Errorf("refusing to start: %s binds off-host but WHOIS_MCP_ENROLLMENT_TOKEN is not set; "+
			"an unauthenticated instance is an open proxy onto the registries", cfg.listen)
	}
	if ac.devStaticBearer && !loopback {
		return fmt.Errorf("refusing to start: WHOIS_MCP_DEV_STATIC_BEARER is enabled but %s is not loopback; "+
			"the hatch turns the enrollment token into a request credential", cfg.listen)
	}
	if ac.enrollmentToken != "" && !loopback && ac.publicURL == "" {
		return errors.New("refusing to start: WHOIS_MCP_PUBLIC_URL must be set for a non-loopback listener, " +
			"because it is the token audience and a wrong value rejects every token")
	}
	return nil
}

// requireHTTPSOffLoopback refuses a cleartext canonical URL for anything but
// loopback: the enrollment token is posted to it.
func requireHTTPSOffLoopback(publicURL string) error {
	lower := strings.ToLower(publicURL)
	if strings.HasPrefix(lower, "https://") {
		return nil
	}
	if strings.HasPrefix(lower, "http://127.0.0.1") ||
		strings.HasPrefix(lower, "http://localhost") ||
		strings.HasPrefix(lower, "http://[::1]") {
		return nil
	}
	return fmt.Errorf("WHOIS_MCP_PUBLIC_URL %q must be https; the enrollment token is submitted to it", publicURL)
}
