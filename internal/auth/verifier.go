package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"
)

// Scopes this server understands (design §5.5).
const (
	ScopeRead  = "whois:read"
	ScopeRaw   = "whois:raw"
	ScopeAdmin = "whois:admin"
)

// AllScopes is every scope, for AS metadata.
var AllScopes = []string{ScopeRead, ScopeRaw, ScopeAdmin}

// MinimumScopes is what Protected Resource Metadata advertises. whois:raw and
// whois:admin are reached through step-up authorization rather than granted by
// default, so a client that only ever reads normalized data never holds a
// credential that can dump raw contact text.
var MinimumScopes = []string{ScopeRead}

// Verifier adapts this package to the SDK's resource-server middleware.
//
// The SDK provides RequireBearerToken, the 401 challenge shape and the PRM
// handler; this is the hook it calls per request. Everything expensive is
// avoided here on purpose: signature and claim checks are local, and the only
// shared-state lookup is the denylist, whose whole design exists to make that
// one read cheap and bounded.
type Verifier struct {
	issuer *Issuer
	deny   *Denylist
	now    func() time.Time
}

// NewVerifier returns a Verifier.
func NewVerifier(issuer *Issuer, deny *Denylist) *Verifier {
	return &Verifier{issuer: issuer, deny: deny, now: time.Now}
}

// TokenVerifier returns the SDK callback.
//
// Errors are wrapped in the SDK's ErrInvalidToken so the middleware answers 401
// with the right challenge. The wrapped cause is kept for the log, but the
// client is told only that the token is invalid: distinguishing "expired" from
// "wrong audience" from "revoked" over the wire tells an attacker which of
// their guesses was closest.
func (v *Verifier) TokenVerifier() sdkauth.TokenVerifier {
	return func(ctx context.Context, token string, _ *http.Request) (*sdkauth.TokenInfo, error) {
		claims, err := v.issuer.Verify(token)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", sdkauth.ErrInvalidToken, err)
		}
		if v.deny != nil && v.deny.Denied(ctx, claims.SID) {
			return nil, fmt.Errorf("%w: session %s is revoked", sdkauth.ErrInvalidToken, claims.SID)
		}
		return &sdkauth.TokenInfo{
			Scopes:     claims.Scopes(),
			Expiration: claims.ExpiresAt(),
			// UserID is the session, which is what the SDK uses to keep
			// requests for one session tied to one identity.
			UserID: claims.SID,
			Extra: map[string]any{
				"sid":   claims.SID,
				"label": claims.Label,
				"jti":   claims.JTI,
			},
		}, nil
	}
}

// ErrInsufficientScope is returned by RequireScope. It is distinct from an
// authentication failure because the response differs: 403 with a scope
// challenge, so the client can step up in one round trip rather than
// re-enrolling.
var ErrInsufficientScope = errors.New("insufficient scope")

// HasScope reports whether the request's token carries a scope.
func HasScope(ctx context.Context, want string) bool {
	info := sdkauth.TokenInfoFromContext(ctx)
	if info == nil {
		return false
	}
	for _, s := range info.Scopes {
		if s == want {
			return true
		}
	}
	return false
}

// RequireScope returns ErrInsufficientScope unless the caller holds want.
func RequireScope(ctx context.Context, want string) error {
	if HasScope(ctx, want) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInsufficientScope, want)
}

// SessionID returns the session id from the request context, or "".
func SessionID(ctx context.Context) string {
	info := sdkauth.TokenInfoFromContext(ctx)
	if info == nil {
		return ""
	}
	return info.UserID
}

// ScopeChallenge renders the WWW-Authenticate value for a step-up (design §5.4).
//
// The resource_metadata pointer is included because without it the client has
// to rediscover where to ask, which turns a one-round-trip step-up into three.
func ScopeChallenge(scope, resourceMetadataURL string) string {
	return fmt.Sprintf(
		`Bearer error="insufficient_scope", error_description="this tool requires the %s scope", scope=%q, resource_metadata=%q`,
		scope, scope, resourceMetadataURL)
}
