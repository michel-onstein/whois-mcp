package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/qjam/whois-mcp/internal/cache"
)

func TestTokenVerifierAcceptsGoodToken(t *testing.T) {
	i := testIssuer(t)
	v := NewVerifier(i, NewDenylist(cache.NewMemory()))
	tok, _, _ := i.Mint("sess_1", "laptop", []string{ScopeRead, ScopeRaw})

	info, err := v.TokenVerifier()(context.Background(), tok, nil)
	if err != nil {
		t.Fatalf("TokenVerifier: %v", err)
	}
	if info.UserID != "sess_1" {
		t.Errorf("UserID = %q; want the sid", info.UserID)
	}
	if len(info.Scopes) != 2 {
		t.Errorf("Scopes = %v", info.Scopes)
	}
	if info.Expiration.IsZero() {
		t.Error("Expiration is zero; the SDK middleware rejects that")
	}
	if info.Extra["sid"] != "sess_1" || info.Extra["label"] != "laptop" {
		t.Errorf("Extra = %v", info.Extra)
	}
}

// TestTokenVerifierWrapsErrInvalidToken matters because the SDK keys its 401
// challenge off that sentinel; a bare error would surface as a 500.
func TestTokenVerifierWrapsErrInvalidToken(t *testing.T) {
	i := testIssuer(t)
	v := NewVerifier(i, NewDenylist(cache.NewMemory()))

	_, err := v.TokenVerifier()(context.Background(), "not-a-token", nil)
	if !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("err = %v; want it to wrap sdkauth.ErrInvalidToken", err)
	}
}

// TestTokenVerifierHonoursDenylist is the revocation path: a token that is
// cryptographically perfect must stop working once its session is revoked.
func TestTokenVerifierHonoursDenylist(t *testing.T) {
	ctx := context.Background()
	i := testIssuer(t)
	deny := NewDenylist(cache.NewMemory())
	v := NewVerifier(i, deny)
	tok, _, _ := i.Mint("sess_1", "", []string{ScopeRead})

	if _, err := v.TokenVerifier()(ctx, tok, nil); err != nil {
		t.Fatalf("token rejected before revocation: %v", err)
	}
	deny.Add(ctx, "sess_1")
	if _, err := v.TokenVerifier()(ctx, tok, nil); !errors.Is(err, sdkauth.ErrInvalidToken) {
		t.Fatalf("revoked session still accepted: err = %v", err)
	}
}

// TestTokenVerifierDoesNotLeakWhyToTheClient: distinguishing expired from
// wrong-audience from revoked over the wire tells an attacker which guess was
// closest.
func TestTokenVerifierDoesNotLeakWhyToTheClient(t *testing.T) {
	ctx := context.Background()
	i := testIssuer(t)
	deny := NewDenylist(cache.NewMemory())
	v := NewVerifier(i, deny)

	tok, _, _ := i.Mint("sess_1", "", []string{ScopeRead})
	deny.Add(ctx, "sess_1")
	_, err := v.TokenVerifier()(ctx, tok, nil)
	if err == nil {
		t.Fatal("expected rejection")
	}
	// The sentinel the SDK renders to the client is generic; the cause stays in
	// the wrapped error for the log only.
	if !strings.Contains(err.Error(), sdkauth.ErrInvalidToken.Error()) {
		t.Errorf("error does not carry the generic sentinel: %v", err)
	}
}

func TestDenylistExpiresAfterAccessTokenTTL(t *testing.T) {
	ctx := context.Background()
	d := NewDenylist(nil) // exercise the in-process path
	base := time.Now()
	d.now = func() time.Time { return base }

	d.Add(ctx, "sess_1")
	if !d.Denied(ctx, "sess_1") {
		t.Fatal("session not denied immediately after Add")
	}

	// One access-token TTL later every token minted before the revocation has
	// expired on its own, so the entry has nothing left to protect against.
	d.now = func() time.Time { return base.Add(AccessTokenTTL + time.Second) }
	if d.Denied(ctx, "sess_1") {
		t.Error("denylist entry outlived the access-token TTL")
	}
}

func TestDenylistIgnoresEmptySID(t *testing.T) {
	ctx := context.Background()
	d := NewDenylist(cache.NewMemory())
	d.Add(ctx, "")
	if d.Denied(ctx, "") {
		t.Error("empty sid is denied; that would reject every token with no sid claim for the wrong reason")
	}
}

func TestScopeHelpers(t *testing.T) {
	ctx := context.Background()
	// No token in context at all: nothing is granted.
	if HasScope(ctx, ScopeRead) {
		t.Error("HasScope true with no token in context")
	}
	if err := RequireScope(ctx, ScopeRead); !errors.Is(err, ErrInsufficientScope) {
		t.Errorf("RequireScope = %v; want ErrInsufficientScope", err)
	}
	if SessionID(ctx) != "" {
		t.Error("SessionID non-empty with no token")
	}
}

func TestScopeChallengeShape(t *testing.T) {
	got := ScopeChallenge(ScopeRaw, "https://whois.example/.well-known/oauth-protected-resource")
	for _, want := range []string{
		`error="insufficient_scope"`,
		`scope="whois:raw"`,
		`resource_metadata="https://whois.example/.well-known/oauth-protected-resource"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("challenge %q lacks %s", got, want)
		}
	}
	if !strings.HasPrefix(got, "Bearer ") {
		t.Errorf("challenge does not start with the Bearer scheme: %q", got)
	}
}

func TestMinimumScopesIsReadOnly(t *testing.T) {
	// PRM advertises the minimum; raw and admin come via step-up, so a client
	// that only reads normalized data never holds a raw-capable credential.
	if len(MinimumScopes) != 1 || MinimumScopes[0] != ScopeRead {
		t.Errorf("MinimumScopes = %v; want just %s", MinimumScopes, ScopeRead)
	}
	for _, s := range []string{ScopeRead, ScopeRaw, ScopeAdmin} {
		found := false
		for _, a := range AllScopes {
			if a == s {
				found = true
			}
		}
		if !found {
			t.Errorf("AllScopes is missing %s", s)
		}
	}
}
