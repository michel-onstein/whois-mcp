package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// AccessTokenTTL is the access-token lifetime (design §5.3).
//
// Ten minutes is the number the whole revocation design rests on: it is the
// worst-case delay between revoking a session and the last valid token for it
// expiring, and it is the TTL of the denylist entry that closes that window.
// Changing it changes both.
const AccessTokenTTL = 10 * time.Minute

// Errors a verifier can return. They are distinguished because the responses
// differ: a malformed token is a client bug, an expired one is routine and the
// client should refresh, and a wrong audience is a confused-deputy attempt that
// is worth noticing.
var (
	ErrMalformedToken = errors.New("malformed token")
	ErrBadSignature   = errors.New("token signature is not valid")
	ErrExpiredToken   = errors.New("token has expired")
	ErrWrongAudience  = errors.New("token audience does not match this resource")
	ErrWrongIssuer    = errors.New("token issuer does not match this server")
)

// header is the JWT header. Alg is fixed at EdDSA on both mint and verify.
//
// This server does not implement algorithm agility, and that is a security
// property rather than a limitation: the entire class of algorithm-confusion
// attacks — alg:none, or alg:HS256 with the Ed25519 public key used as an HMAC
// secret — depends on a verifier that reads the algorithm out of the token and
// believes it. This one does not read it except to reject anything that is not
// EdDSA.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Claims is the access-token payload (design §5.3).
type Claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	SID      string `json:"sid"`
	Scope    string `json:"scope"`
	Expires  int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	JTI      string `json:"jti"`
	// Label is the human name the enrolling user gave this session. Carried in
	// the token so session_list can name sessions without a store read.
	Label string `json:"label,omitempty"`
}

// Scopes splits the space-delimited scope claim.
func (c Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// ExpiresAt is the expiry as a time.
func (c Claims) ExpiresAt() time.Time {
	return time.Unix(c.Expires, 0).UTC()
}

// Issuer identifies this server and is the only thing that mints tokens.
type Issuer struct {
	keys *Keyring
	// issuer is the canonical https URL of this server.
	issuer string
	// audience is the canonical URI of the protected resource, which RFC 8707
	// requires the token to name. It is the /mcp endpoint, not the server root:
	// a token minted for a different resource must not be accepted here.
	audience string
	now      func() time.Time
}

// NewIssuer returns an Issuer. The issuer and audience must be the canonical
// URLs clients discover through metadata; a mismatch between what is minted and
// what is advertised rejects every token.
func NewIssuer(keys *Keyring, issuerURL, audienceURI string) *Issuer {
	return &Issuer{keys: keys, issuer: issuerURL, audience: audienceURI, now: time.Now}
}

// Issuer returns the canonical issuer URL.
func (i *Issuer) IssuerURL() string { return i.issuer }

// Audience returns the canonical resource URI tokens are minted for.
func (i *Issuer) Audience() string { return i.audience }

// Mint signs an access token for a session.
func (i *Issuer) Mint(sid, label string, scopes []string) (string, Claims, error) {
	now := i.now().UTC()
	jti, err := randomID(16)
	if err != nil {
		return "", Claims{}, err
	}
	c := Claims{
		Issuer:   i.issuer,
		Subject:  sid,
		Audience: i.audience,
		SID:      sid,
		Scope:    strings.Join(scopes, " "),
		Expires:  now.Add(AccessTokenTTL).Unix(),
		IssuedAt: now.Unix(),
		JTI:      jti,
		Label:    label,
	}
	kp := i.keys.Active()
	tok, err := sign(kp, c)
	if err != nil {
		return "", Claims{}, err
	}
	return tok, c, nil
}

func sign(kp KeyPair, c Claims) (string, error) {
	h, err := json.Marshal(header{Alg: "EdDSA", Typ: "JWT", Kid: kp.ID})
	if err != nil {
		return "", fmt.Errorf("encoding token header: %w", err)
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encoding token claims: %w", err)
	}
	signing := b64(h) + "." + b64(p)
	sig := ed25519.Sign(kp.Private, []byte(signing))
	return signing + "." + b64(sig), nil
}

// Verify checks a token and returns its claims.
//
// Every check here is mandatory, and the order is deliberate: structure, then
// signature, then the claims. Reading claims out of an unverified token — even
// to decide how to handle it — is how a verifier ends up trusting attacker
// input, so nothing but the kid is used before the signature is checked.
func (i *Issuer) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformedToken, len(parts))
	}

	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: header is not base64url: %v", ErrMalformedToken, err)
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return Claims{}, fmt.Errorf("%w: header is not JSON: %v", ErrMalformedToken, err)
	}
	// The only algorithm this server has ever issued.
	if h.Alg != "EdDSA" {
		return Claims{}, fmt.Errorf("%w: algorithm %q is not accepted", ErrMalformedToken, h.Alg)
	}
	if h.Typ != "" && h.Typ != "JWT" {
		return Claims{}, fmt.Errorf("%w: typ %q is not accepted", ErrMalformedToken, h.Typ)
	}

	pub, err := i.keys.Verifier(h.Kid)
	if err != nil {
		return Claims{}, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: signature is not base64url: %v", ErrMalformedToken, err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, ErrBadSignature
	}

	rawClaims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("%w: payload is not base64url: %v", ErrMalformedToken, err)
	}
	var c Claims
	if err := json.Unmarshal(rawClaims, &c); err != nil {
		return Claims{}, fmt.Errorf("%w: payload is not JSON: %v", ErrMalformedToken, err)
	}

	// RFC 8707. This single comparison is the confused-deputy defence: without
	// it, a token this server minted for one resource, or a token minted by a
	// server sharing our keys for another, would be accepted here.
	if c.Audience != i.audience {
		return Claims{}, fmt.Errorf("%w: %q", ErrWrongAudience, c.Audience)
	}
	if c.Issuer != i.issuer {
		return Claims{}, fmt.Errorf("%w: %q", ErrWrongIssuer, c.Issuer)
	}
	if c.Expires == 0 {
		return Claims{}, fmt.Errorf("%w: no exp claim", ErrMalformedToken)
	}
	if i.now().UTC().After(c.ExpiresAt()) {
		return Claims{}, fmt.Errorf("%w at %s", ErrExpiredToken, c.ExpiresAt().Format(time.RFC3339))
	}
	if c.SID == "" {
		return Claims{}, fmt.Errorf("%w: no sid claim", ErrMalformedToken)
	}
	return c, nil
}

// randomID returns a base64url random identifier of n bytes of entropy.
func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return b64(b), nil
}
