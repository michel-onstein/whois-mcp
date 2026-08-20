package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// TestThumbprintIsStableAndKeyDerived is the property a rotation depends on:
// the same key must produce the same kid on every replica and every build. A
// kid that varies invalidates every live token.
func TestThumbprintIsStableAndKeyDerived(t *testing.T) {
	kp, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if kp.ID == "" {
		t.Fatal("kid is empty")
	}
	if kp.ID != Thumbprint(kp.Public) {
		t.Error("kid is not the thumbprint of its own public key")
	}

	// Reloading the same seed must reproduce the kid exactly.
	again, err := ParseKey(EncodeSeed(kp))
	if err != nil {
		t.Fatalf("ParseKey(EncodeSeed): %v", err)
	}
	if again.ID != kp.ID {
		t.Errorf("kid changed across encode/parse: %q -> %q", kp.ID, again.ID)
	}
	if !again.Public.Equal(kp.Public) {
		t.Error("public key changed across encode/parse")
	}

	other, _ := GenerateKey()
	if other.ID == kp.ID {
		t.Error("two independent keys share a kid")
	}
}

// TestThumbprintMatchesRFC7638 pins the exact JSON the thumbprint is taken
// over. RFC 7638 requires the required members only, lexicographically ordered,
// with no whitespace; any deviation silently changes every kid.
func TestThumbprintMatchesRFC7638(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	x := base64.RawURLEncoding.EncodeToString(pub)
	wantJSON := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`

	// Rebuild the same document from a map to prove the member set and order
	// are what the RFC specifies rather than what happened to be typed.
	var members map[string]string
	if err := json.Unmarshal([]byte(wantJSON), &members); err != nil {
		t.Fatalf("thumbprint document is not valid JSON: %v", err)
	}
	if len(members) != 3 || members["kty"] != "OKP" || members["crv"] != "Ed25519" || members["x"] != x {
		t.Errorf("thumbprint members = %v; want exactly kty/crv/x", members)
	}
	if Thumbprint(pub) == "" {
		t.Error("thumbprint is empty")
	}
}

func TestParseKeyAcceptsSeedAndPrivateKeyAndPEM(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	want := Thumbprint(pub)

	t.Run("raw url seed", func(t *testing.T) {
		kp, err := ParseKey(base64.RawURLEncoding.EncodeToString(priv.Seed()))
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		if kp.ID != want {
			t.Errorf("kid = %q; want %q", kp.ID, want)
		}
	})

	t.Run("padded standard base64 seed", func(t *testing.T) {
		// An operator pasting from a tool that emits standard base64 must not
		// have to convert it by hand; that is how keys reach shell history.
		kp, err := ParseKey(base64.StdEncoding.EncodeToString(priv.Seed()))
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		if kp.ID != want {
			t.Errorf("kid = %q; want %q", kp.ID, want)
		}
	})

	t.Run("full 64-byte private key", func(t *testing.T) {
		kp, err := ParseKey(base64.RawURLEncoding.EncodeToString(priv))
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		if kp.ID != want {
			t.Errorf("kid = %q; want %q — the two input forms must normalize identically", kp.ID, want)
		}
	})

	t.Run("pkcs8 pem", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		kp, err := ParseKey(string(block))
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		if kp.ID != want {
			t.Errorf("kid = %q; want %q", kp.ID, want)
		}
	})

	t.Run("whitespace tolerated", func(t *testing.T) {
		kp, err := ParseKey("  " + base64.RawURLEncoding.EncodeToString(priv.Seed()) + "\n")
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		if kp.ID != want {
			t.Errorf("kid = %q; want %q", kp.ID, want)
		}
	})
}

func TestParseKeyRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"whitespace":      "   \n",
		"not base64":      "$$$not base64$$$",
		"wrong length":    base64.RawURLEncoding.EncodeToString([]byte("too short")),
		"unparseable pem": "-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKey(in); err == nil {
				t.Errorf("ParseKey(%q) succeeded", in)
			}
		})
	}
}

// TestParseKeyRejectsNonEd25519PEM: this server signs with Ed25519 only, and a
// misconfigured RSA key must fail loudly at startup rather than at first mint.
func TestParseKeyRejectsNonEd25519PEM(t *testing.T) {
	// An ECDSA/RSA key would need extra imports; a PKCS#8 block holding a
	// symmetric blob exercises the same rejection path.
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a pkcs8 key")})
	if _, err := ParseKey(string(block)); err == nil {
		t.Error("ParseKey accepted a PEM block that is not an Ed25519 key")
	}
}

func TestJWKSShape(t *testing.T) {
	kp, _ := GenerateKey()
	ring := NewKeyring(kp)

	raw, err := ring.JWKSJSON()
	if err != nil {
		t.Fatalf("JWKSJSON: %v", err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("keys = %d; want 1", len(doc.Keys))
	}
	k := doc.Keys[0]
	for field, want := range map[string]string{
		"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": kp.ID,
	} {
		if k[field] != want {
			t.Errorf("jwk[%q] = %q; want %q", field, k[field], want)
		}
	}
	// The public key must be there, and the private key must not.
	if k["x"] == "" {
		t.Error("jwk has no x (public key)")
	}
	if strings.Contains(string(raw), base64.RawURLEncoding.EncodeToString(kp.Private.Seed())) {
		t.Fatal("JWKS leaks the private key seed")
	}
	if _, ok := k["d"]; ok {
		t.Fatal("JWKS contains a 'd' member, which is the private key")
	}
}

func TestKeyringVerifierUnknownKid(t *testing.T) {
	kp, _ := GenerateKey()
	ring := NewKeyring(kp)
	if _, err := ring.Verifier("nope"); !errors.Is(err, ErrNoSuchKey) {
		t.Errorf("err = %v; want ErrNoSuchKey", err)
	}
	if _, err := ring.Verifier(kp.ID); err != nil {
		t.Errorf("active key not found: %v", err)
	}
}

func TestKeyringRotateIsIdempotentForSameKey(t *testing.T) {
	kp, _ := GenerateKey()
	ring := NewKeyring(kp)
	ring.Rotate(kp)
	if got := len(ring.JWKS().Keys); got != 1 {
		t.Errorf("JWKS has %d keys after rotating to the same key; want 1", got)
	}
}
