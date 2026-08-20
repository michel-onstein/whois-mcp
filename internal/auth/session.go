package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// RefreshTTL is the refresh-token lifetime and therefore the session lifetime
// (design §5.3).
//
// Thirty days is a *sliding* window: every rotation issues a fresh thirty days,
// so an actively used session continues indefinitely and an idle one dies thirty
// days after its last use. This is deliberately both the session lifetime and
// the inactivity timeout — one rule rather than two competing ones. There is no
// absolute cap.
const RefreshTTL = 30 * 24 * time.Hour

// Errors from the session store.
var (
	ErrNoSession      = errors.New("no such session")
	ErrRefreshUnknown = errors.New("refresh token is not recognised")
	ErrRefreshExpired = errors.New("refresh token has expired")
	ErrRefreshReused  = errors.New("refresh token was already used")
	ErrSessionRevoked = errors.New("session has been revoked")
)

// ReuseError reports a replayed refresh token and names the session that was
// revoked because of it.
//
// It carries the sid rather than only a message because the caller has to act
// on it — denylisting the session and raising an alert — and recovering an
// identifier by parsing an error string is the kind of coupling that breaks
// silently the first time the message is reworded.
type ReuseError struct {
	SID string
}

func (e *ReuseError) Error() string {
	return fmt.Sprintf("refresh token was already used: session %s revoked as a precaution", e.SID)
}

// Unwrap lets errors.Is(err, ErrRefreshReused) keep working.
func (e *ReuseError) Unwrap() error { return ErrRefreshReused }

// Session is one enrollment: the token family created by one successful use of
// the enrollment secret.
//
// It is the unit of revocation, which is the point of the whole design: the
// fixed secret is used exactly once per client, and compromise of one session's
// tokens does not touch any other.
type Session struct {
	ID        string    `json:"sid"`
	Label     string    `json:"label"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	// Rotations counts refresh exchanges. Surfaced by session_list because an
	// unusually high count on a young session is a signal worth seeing.
	Rotations int `json:"rotations"`
	// ClientHint records what enrolled, for a human reading session_list. It is
	// not a credential and is never trusted for anything.
	ClientHint string `json:"client_hint,omitempty"`
}

// Active reports whether a session may still be used.
func (s *Session) Active(now time.Time) bool {
	return s != nil && !s.Revoked && now.Before(s.ExpiresAt)
}

// SessionStore holds sessions and their refresh-token families.
//
// It is an interface because the memory implementation here is replaced by
// Redis at M3 (plan task 3.3) so that replicas share state. Everything on the
// hot request path deliberately avoids it: access tokens verify locally, and
// only refresh and revocation touch the store.
type SessionStore interface {
	// Create records a new session. It deliberately does not take a refresh
	// token: a refresh token is only ever handed to a client by the token
	// endpoint, so creating one at enrollment would mean a live token nobody
	// holds, which breaks the one-time-use invariant the theft detection needs.
	Create(ctx context.Context, s *Session) error
	// IssueRefresh records the first refresh token for a session, at code
	// exchange.
	IssueRefresh(ctx context.Context, sid, token string, now time.Time) error
	// Get returns a session by id.
	Get(ctx context.Context, sid string) (*Session, error)
	// List returns every session, newest first.
	List(ctx context.Context) ([]*Session, error)
	// Rotate consumes a refresh token and issues its successor atomically.
	//
	// Atomicity is the entire security property: two concurrent uses of the
	// same token must produce exactly one success and one ErrRefreshReused, or
	// the theft-detection below is decorative.
	Rotate(ctx context.Context, oldToken, newToken string, now time.Time) (*Session, error)
	// Revoke marks a session revoked and invalidates its whole family.
	Revoke(ctx context.Context, sid string, now time.Time) error
	// Touch updates last-seen without rotating.
	Touch(ctx context.Context, sid string, now time.Time) error
}

// refreshRecord is one issued refresh token.
type refreshRecord struct {
	sid       string
	expiresAt time.Time
	// used marks a token that has already been exchanged. Consumed tokens are
	// retained rather than deleted, because "I have never seen this token" and
	// "this token was already spent" must be distinguishable: the second is a
	// theft signal and the first is not.
	used     bool
	usedAt   time.Time
	replaced string
}

// MemoryStore is an in-process SessionStore for development and single-replica
// deployments.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	refresh  map[string]*refreshRecord
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*Session),
		refresh:  make(map[string]*refreshRecord),
	}
}

// Create records a session in memory.
func (m *MemoryStore) Create(_ context.Context, s *Session) error {
	if s == nil || s.ID == "" {
		return errors.New("session id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[s.ID]; exists {
		return fmt.Errorf("session %s already exists", s.ID)
	}
	snapshot := *s
	m.sessions[s.ID] = &snapshot
	return nil
}

// IssueRefresh records a session's first refresh token.
func (m *MemoryStore) IssueRefresh(_ context.Context, sid, token string, now time.Time) error {
	if token == "" {
		return errors.New("refresh token is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSession, sid)
	}
	if s.Revoked {
		return fmt.Errorf("%w: %s", ErrSessionRevoked, sid)
	}
	if _, exists := m.refresh[token]; exists {
		return errors.New("refresh token already issued")
	}
	s.LastSeen = now.UTC()
	m.refresh[token] = &refreshRecord{sid: sid, expiresAt: s.ExpiresAt}
	return nil
}

// Get returns a copy of a session, so a caller cannot mutate stored state.
func (m *MemoryStore) Get(_ context.Context, sid string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSession, sid)
	}
	snapshot := *s
	return &snapshot, nil
}

// List returns copies of every session, newest first.
func (m *MemoryStore) List(_ context.Context) ([]*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		snapshot := *s
		out = append(out, &snapshot)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Rotate implements one-time-use refresh with theft detection.
//
// Presenting a token that was already exchanged is treated as theft, not as a
// retry: the legitimate client and the attacker cannot both hold the current
// token, so a second use means the family leaked. The whole family dies, which
// logs both parties out and forces re-enrollment — deliberately more disruptive
// than the alternative of letting an attacker keep a working session.
func (m *MemoryStore) Rotate(_ context.Context, oldToken, newToken string, now time.Time) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.refresh[oldToken]
	if !ok {
		return nil, ErrRefreshUnknown
	}
	s, ok := m.sessions[rec.sid]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSession, rec.sid)
	}

	if rec.used {
		s.Revoked = true
		s.RevokedAt = now.UTC()
		m.revokeFamilyLocked(s.ID, now)
		return nil, &ReuseError{SID: s.ID}
	}
	if s.Revoked {
		return nil, fmt.Errorf("%w: %s", ErrSessionRevoked, s.ID)
	}
	if now.After(rec.expiresAt) {
		return nil, fmt.Errorf("%w at %s", ErrRefreshExpired, rec.expiresAt.Format(time.RFC3339))
	}

	rec.used = true
	rec.usedAt = now.UTC()
	rec.replaced = newToken

	// The sliding window: a rotation extends the session from now, so activity
	// keeps it alive and silence ends it.
	s.LastSeen = now.UTC()
	s.ExpiresAt = now.UTC().Add(RefreshTTL)
	s.Rotations++
	m.refresh[newToken] = &refreshRecord{sid: s.ID, expiresAt: s.ExpiresAt}

	snapshot := *s
	return &snapshot, nil
}

// Revoke marks a session revoked and spends every refresh token in its family.
func (m *MemoryStore) Revoke(_ context.Context, sid string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSession, sid)
	}
	s.Revoked = true
	s.RevokedAt = now.UTC()
	m.revokeFamilyLocked(sid, now)
	return nil
}

// revokeFamilyLocked marks every refresh token of a session spent, so no
// surviving member of the family can be exchanged.
func (m *MemoryStore) revokeFamilyLocked(sid string, now time.Time) {
	for tok, rec := range m.refresh {
		if rec.sid == sid && !rec.used {
			rec.used = true
			rec.usedAt = now.UTC()
			_ = tok
		}
	}
}

// Touch updates last-seen without extending the refresh window.
func (m *MemoryStore) Touch(_ context.Context, sid string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSession, sid)
	}
	s.LastSeen = now.UTC()
	return nil
}

// NewSessionID returns a session identifier.
//
// The sess_ prefix is not decoration: these appear in logs and in operator
// commands, and a bare base64 string is indistinguishable from a token. Making
// the harmless identifier obviously not-a-credential reduces the chance someone
// treats a real token as one.
func NewSessionID() (string, error) {
	id, err := randomID(16)
	if err != nil {
		return "", err
	}
	return "sess_" + id, nil
}

// NewRefreshToken returns an opaque 256-bit refresh token (design §5.3).
func NewRefreshToken() (string, error) {
	return randomID(32)
}

// NormalizeScopes lowercases, de-duplicates and sorts a scope list so that two
// grants of the same scopes compare equal.
func NormalizeScopes(scopes []string) []string {
	seen := make(map[string]bool, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		v := strings.ToLower(strings.TrimSpace(s))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
