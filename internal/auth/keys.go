// Package auth is the authorization-server half of this server: signing keys,
// access and refresh tokens, sessions, scopes, and the enrollment secret.
//
// The resource-server half comes from github.com/modelcontextprotocol/go-sdk/auth
// and is not reimplemented here (design §5, plan §6.1). What is here is the part
// the SDK does not provide, because its OAuth handlers are client-side.
//
// The shape of everything in this package follows from one property: an access
// token must be verifiable by any replica with no store lookup, so that replicas
// stay stateless and interchangeable. That is why tokens are signed JWTs rather
// than opaque handles, and why the only per-request state consulted on the hot
// path is a short-TTL revocation denylist.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ErrNoSuchKey means a token names a key this server does not hold.
var ErrNoSuchKey = errors.New("unknown signing key")

// KeyPair is one Ed25519 signing key with its JWK thumbprint as `kid`.
//
// The kid is derived from the public key (RFC 7638) rather than assigned. That
// makes it stable across restarts and identical on every replica that loads the
// same key, which is what lets a rotation be reasoned about at all: two
// replicas that disagree about a key's name would produce tokens neither can
// verify from the other.
type KeyPair struct {
	ID      string
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// GenerateKey creates a fresh signing key.
func GenerateKey() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	return newKeyPair(pub, priv), nil
}

func newKeyPair(pub ed25519.PublicKey, priv ed25519.PrivateKey) KeyPair {
	return KeyPair{ID: Thumbprint(pub), Public: pub, Private: priv}
}

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key.
//
// The member ordering below is not stylistic: RFC 7638 requires the JSON to
// contain exactly the required members, lexicographically ordered, with no
// whitespace. Any deviation produces a different kid, and a kid that differs
// between two builds of this server silently invalidates every live token.
func Thumbprint(pub ed25519.PublicKey) string {
	j := `{"crv":"Ed25519","kty":"OKP","x":"` + b64(pub) + `"}`
	sum := sha256.Sum256([]byte(j))
	return b64(sum[:])
}

// EncodeSeed renders a private key as the 32-byte seed, base64url encoded.
//
// This is the form an operator puts in a Kubernetes Secret. The seed rather
// than the expanded private key because it is half the size and because
// ed25519.NewKeyFromSeed is the only supported way back — there is no ambiguity
// about which 64-byte layout was meant.
func EncodeSeed(kp KeyPair) string {
	return b64(kp.Private.Seed())
}

// ParseKey reads a signing key from operator-supplied text.
//
// Two forms are accepted because two are genuinely in use: a base64url or
// base64 seed (what EncodeSeed emits, and what fits in an env var), and a
// PKCS#8 PEM block (what every other tool emits). Refusing one of them would
// mean an operator has to convert a key by hand, which is how keys end up in
// shell history.
func ParseKey(s string) (KeyPair, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return KeyPair{}, errors.New("signing key is empty")
	}

	if strings.Contains(trimmed, "-----BEGIN") {
		return parsePEM(trimmed)
	}

	seed, err := decodeB64(trimmed)
	if err != nil {
		return KeyPair{}, fmt.Errorf("signing key is neither PEM nor base64: %w", err)
	}
	switch len(seed) {
	case ed25519.SeedSize:
		priv := ed25519.NewKeyFromSeed(seed)
		return newKeyPair(priv.Public().(ed25519.PublicKey), priv), nil
	case ed25519.PrivateKeySize:
		// A full 64-byte private key. Accepted, but normalized through the seed
		// so the two input forms cannot produce different kids.
		priv := ed25519.PrivateKey(seed)
		reparsed := ed25519.NewKeyFromSeed(priv.Seed())
		return newKeyPair(reparsed.Public().(ed25519.PublicKey), reparsed), nil
	default:
		return KeyPair{}, fmt.Errorf("signing key is %d bytes; want %d (seed) or %d (private key)",
			len(seed), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func parsePEM(s string) (KeyPair, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return KeyPair{}, errors.New("signing key PEM could not be decoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return KeyPair{}, fmt.Errorf("parsing PKCS#8 signing key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return KeyPair{}, fmt.Errorf("signing key is %T; this server signs with Ed25519 only", key)
	}
	return newKeyPair(priv.Public().(ed25519.PublicKey), priv), nil
}

// Keyring holds the active signing key plus any keys kept for verification.
//
// Rotation is publish-then-retire (design §5, runbook at plan task 4.7): a new
// key becomes active while the old one stays verifiable for at least one
// access-token TTL, so tokens minted seconds before the rotation still work.
// Without that overlap every rotation is a brief outage for every client.
type Keyring struct {
	mu       sync.RWMutex
	active   KeyPair
	previous []KeyPair
}

// NewKeyring returns a keyring with one active key.
func NewKeyring(active KeyPair) *Keyring {
	return &Keyring{active: active}
}

// Active returns the key new tokens are signed with.
func (k *Keyring) Active() KeyPair {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active
}

// Rotate makes next the active key and retains the outgoing one for
// verification. Retire drops it once no live token can reference it.
func (k *Keyring) Rotate(next KeyPair) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.active.ID != "" && k.active.ID != next.ID {
		k.previous = append(k.previous, k.active)
	}
	k.active = next
}

// Retire removes a key from the verification set. Calling it before one
// access-token TTL has elapsed since the rotation will reject tokens that are
// still valid, which is why the runbook says to wait.
func (k *Keyring) Retire(kid string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	kept := k.previous[:0]
	for _, p := range k.previous {
		if p.ID != kid {
			kept = append(kept, p)
		}
	}
	k.previous = kept
}

// Verifier returns the public key for a kid.
func (k *Keyring) Verifier(kid string) (ed25519.PublicKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if kid == k.active.ID {
		return k.active.Public, nil
	}
	for _, p := range k.previous {
		if p.ID == kid {
			return p.Public, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrNoSuchKey, kid)
}

// JWK is one public key in the JWKS document.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is the /.well-known/jwks.json document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS renders the public keys, active first.
//
// Retired-but-not-yet-dropped keys are included deliberately: a client that
// caches JWKS and sees only the new key cannot verify a token minted moments
// before the rotation.
func (k *Keyring) JWKS() JWKS {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := JWKS{Keys: make([]JWK, 0, 1+len(k.previous))}
	out.Keys = append(out.Keys, jwkFor(k.active))
	for _, p := range k.previous {
		out.Keys = append(out.Keys, jwkFor(p))
	}
	return out
}

// JWKSJSON is JWKS marshalled, for serving directly.
func (k *Keyring) JWKSJSON() ([]byte, error) {
	return json.Marshal(k.JWKS())
}

func jwkFor(kp KeyPair) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   b64(kp.Public),
		Kid: kp.ID,
		Use: "sig",
		Alg: "EdDSA",
	}
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeB64 accepts both base64url and standard base64, padded or not, because
// an operator pasting a key should not have to know which variant a tool emitted.
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}
