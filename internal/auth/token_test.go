package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	kp, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return NewIssuer(NewKeyring(kp), "https://whois.example", "https://whois.example/mcp")
}

func TestMintAndVerify(t *testing.T) {
	i := testIssuer(t)
	tok, minted, err := i.Mint("sess_1", "laptop", []string{"whois:read", "whois:raw"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	got, err := i.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.SID != "sess_1" || got.Subject != "sess_1" {
		t.Errorf("sid/sub = %q/%q; want sess_1", got.SID, got.Subject)
	}
	if got.Label != "laptop" {
		t.Errorf("label = %q; want laptop", got.Label)
	}
	if strings.Join(got.Scopes(), " ") != "whois:read whois:raw" {
		t.Errorf("scopes = %v", got.Scopes())
	}
	if got.Audience != "https://whois.example/mcp" {
		t.Errorf("aud = %q", got.Audience)
	}
	if got.Issuer != "https://whois.example" {
		t.Errorf("iss = %q", got.Issuer)
	}
	if got.JTI == "" {
		t.Error("jti is empty")
	}
	if d := minted.ExpiresAt().Sub(time.Unix(minted.IssuedAt, 0)); d != AccessTokenTTL {
		t.Errorf("TTL = %v; want %v", d, AccessTokenTTL)
	}
}

// TestVerifyRejectsWrongAudience is the confused-deputy defence (design §5.4).
// A token minted for another resource must not be accepted here even though it
// is signed by a key we trust.
func TestVerifyRejectsWrongAudience(t *testing.T) {
	kp, _ := GenerateKey()
	ring := NewKeyring(kp)
	other := NewIssuer(ring, "https://whois.example", "https://other.example/mcp")
	ours := NewIssuer(ring, "https://whois.example", "https://whois.example/mcp")

	tok, _, err := other.Mint("sess_1", "", []string{"whois:read"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := ours.Verify(tok); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("Verify accepted a token for another resource: err = %v", err)
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	kp, _ := GenerateKey()
	ring := NewKeyring(kp)
	impostor := NewIssuer(ring, "https://evil.example", "https://whois.example/mcp")
	ours := NewIssuer(ring, "https://whois.example", "https://whois.example/mcp")

	tok, _, _ := impostor.Mint("sess_1", "", []string{"whois:read"})
	if _, err := ours.Verify(tok); !errors.Is(err, ErrWrongIssuer) {
		t.Fatalf("Verify accepted a token from another issuer: err = %v", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	i := testIssuer(t)
	base := time.Now()
	i.now = func() time.Time { return base }

	tok, _, _ := i.Mint("sess_1", "", []string{"whois:read"})
	i.now = func() time.Time { return base.Add(AccessTokenTTL + time.Second) }

	if _, err := i.Verify(tok); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("Verify accepted an expired token: err = %v", err)
	}
}

// TestVerifyRejectsAlgorithmConfusion is the reason this package does not
// implement algorithm agility. Each case is a real attack against verifiers
// that read the algorithm out of the token and believe it.
func TestVerifyRejectsAlgorithmConfusion(t *testing.T) {
	i := testIssuer(t)
	kid := i.keys.Active().ID
	claims := Claims{
		Issuer: "https://whois.example", Subject: "sess_1", Audience: "https://whois.example/mcp",
		SID: "sess_1", Scope: "whois:read whois:admin",
		Expires: time.Now().Add(time.Hour).Unix(), IssuedAt: time.Now().Unix(), JTI: "x",
	}
	payload := mustB64JSON(t, claims)

	t.Run("alg none with empty signature", func(t *testing.T) {
		h := mustB64JSON(t, header{Alg: "none", Typ: "JWT", Kid: kid})
		if _, err := i.Verify(h + "." + payload + "."); err == nil {
			t.Fatal("accepted an unsigned token")
		}
	})

	t.Run("alg HS256 keyed with the public key", func(t *testing.T) {
		// The classic: treat the Ed25519 public key, which is public, as an
		// HMAC secret. A verifier that dispatches on alg would accept this.
		h := mustB64JSON(t, header{Alg: "HS256", Typ: "JWT", Kid: kid})
		signing := h + "." + payload
		mac := hmac.New(sha256.New, i.keys.Active().Public)
		mac.Write([]byte(signing))
		forged := signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		if _, err := i.Verify(forged); !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("HS256 forgery was not rejected as malformed: err = %v", err)
		}
	})

	t.Run("valid structure, signature from another key", func(t *testing.T) {
		attacker, _ := GenerateKey()
		h := mustB64JSON(t, header{Alg: "EdDSA", Typ: "JWT", Kid: kid})
		signing := h + "." + payload
		sig := ed25519.Sign(attacker.Private, []byte(signing))
		forged := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

		if _, err := i.Verify(forged); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("token signed by an unrelated key was not rejected: err = %v", err)
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		other, _ := GenerateKey()
		h := mustB64JSON(t, header{Alg: "EdDSA", Typ: "JWT", Kid: other.ID})
		signing := h + "." + payload
		sig := ed25519.Sign(other.Private, []byte(signing))
		if _, err := i.Verify(signing + "." + base64.RawURLEncoding.EncodeToString(sig)); !errors.Is(err, ErrNoSuchKey) {
			t.Fatalf("token naming an unknown key was not rejected: err = %v", err)
		}
	})
}

// TestVerifyRejectsTamperedClaims proves the signature covers the payload: the
// interesting case is escalating scope, which is what an attacker would try.
func TestVerifyRejectsTamperedClaims(t *testing.T) {
	i := testIssuer(t)
	tok, _, _ := i.Mint("sess_1", "", []string{"whois:read"})

	parts := strings.Split(tok, ".")
	var c Claims
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decoding own token: %v", err)
	}
	c.Scope = "whois:read whois:raw whois:admin"
	tampered := parts[0] + "." + mustB64JSON(t, c) + "." + parts[2]

	if _, err := i.Verify(tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("scope escalation was not rejected: err = %v", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	i := testIssuer(t)
	for _, tok := range []string{
		"", "not-a-token", "a.b", "a.b.c.d",
		"!!!.eyJ4IjoxfQ.sig",
		"eyJhbGciOiJFZERTQSJ9.!!!.sig",
	} {
		if _, err := i.Verify(tok); err == nil {
			t.Errorf("Verify(%q) succeeded", tok)
		}
	}
}

func TestVerifyRequiresSIDAndExp(t *testing.T) {
	i := testIssuer(t)
	kp := i.keys.Active()

	noSID := Claims{Issuer: "https://whois.example", Audience: "https://whois.example/mcp",
		Expires: time.Now().Add(time.Hour).Unix()}
	tok, err := sign(kp, noSID)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := i.Verify(tok); !errors.Is(err, ErrMalformedToken) {
		t.Errorf("token with no sid accepted: %v", err)
	}

	noExp := Claims{Issuer: "https://whois.example", Audience: "https://whois.example/mcp", SID: "s"}
	tok, _ = sign(kp, noExp)
	if _, err := i.Verify(tok); !errors.Is(err, ErrMalformedToken) {
		t.Errorf("token with no exp accepted: %v", err)
	}
}

// TestRotationKeepsOldTokensValid is the property the publish-then-retire
// runbook exists for: a token minted a second before a rotation must still
// verify, or every rotation is a brief outage for every client.
func TestRotationKeepsOldTokensValid(t *testing.T) {
	i := testIssuer(t)
	oldTok, _, _ := i.Mint("sess_1", "", []string{"whois:read"})
	oldKid := i.keys.Active().ID

	next, _ := GenerateKey()
	i.keys.Rotate(next)

	if _, err := i.Verify(oldTok); err != nil {
		t.Fatalf("token minted before rotation no longer verifies: %v", err)
	}
	newTok, _, _ := i.Mint("sess_2", "", []string{"whois:read"})
	if _, err := i.Verify(newTok); err != nil {
		t.Fatalf("token minted after rotation does not verify: %v", err)
	}

	// Both keys must be published, or a caching client cannot verify the old one.
	jwks := i.keys.JWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("JWKS has %d keys after rotation; want 2", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != next.ID {
		t.Errorf("JWKS[0].kid = %q; want the active key first", jwks.Keys[0].Kid)
	}

	// After retiring the old key, its tokens stop verifying — which is why the
	// runbook says to wait one access-token TTL first.
	i.keys.Retire(oldKid)
	if _, err := i.Verify(oldTok); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("retired key still verifies: %v", err)
	}
}

func mustB64JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
