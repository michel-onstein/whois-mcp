package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newSession(t *testing.T, now time.Time) (*Session, string) {
	t.Helper()
	sid, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	rt, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	return &Session{
		ID:        sid,
		Label:     "laptop",
		Scopes:    []string{ScopeRead},
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(RefreshTTL),
	}, rt
}

// createWithRefresh creates a session and issues its first refresh token, which
// is what the code-exchange path does in one go.
func createWithRefresh(t *testing.T, st *MemoryStore, s *Session, token string) error {
	t.Helper()
	if err := st.Create(context.Background(), s); err != nil {
		return err
	}
	return st.IssueRefresh(context.Background(), s.ID, token, s.CreatedAt)
}

func TestCreateAndGet(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := NewMemoryStore()
	s, rt := newSession(t, now)

	if err := createWithRefresh(t, st, s, rt); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := st.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Label != "laptop" || got.ID != s.ID {
		t.Errorf("got %+v", got)
	}
	if !got.Active(now) {
		t.Error("fresh session is not active")
	}

	// The store must hand out copies: a caller mutating its result must not
	// silently revoke or extend the stored session.
	got.Revoked = true
	again, _ := st.Get(ctx, s.ID)
	if again.Revoked {
		t.Error("mutating a returned session changed the stored one")
	}

	if _, err := st.Get(ctx, "sess_nope"); !errors.Is(err, ErrNoSession) {
		t.Errorf("Get(unknown) = %v; want ErrNoSession", err)
	}
}

func TestRotateIssuesSuccessorAndSlidesWindow(t *testing.T) {
	ctx := context.Background()
	start := time.Now().UTC()
	st := NewMemoryStore()
	s, rt1 := newSession(t, start)
	if err := createWithRefresh(t, st, s, rt1); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Ten days later the client refreshes.
	later := start.Add(10 * 24 * time.Hour)
	rt2, _ := NewRefreshToken()
	got, err := st.Rotate(ctx, rt1, rt2, later)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got.Rotations != 1 {
		t.Errorf("Rotations = %d; want 1", got.Rotations)
	}
	// The sliding window: expiry moves to 30 days from the rotation, not from
	// creation, so an active session never dies of old age.
	wantExpiry := later.Add(RefreshTTL)
	if !got.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %s; want %s (30 days from the rotation)", got.ExpiresAt, wantExpiry)
	}
	if !got.LastSeen.Equal(later) {
		t.Errorf("LastSeen = %s; want %s", got.LastSeen, later)
	}

	// The successor works.
	rt3, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt2, rt3, later.Add(time.Hour)); err != nil {
		t.Fatalf("second Rotate: %v", err)
	}
}

// TestRotateReuseRevokesWholeFamily is the theft-detection rule (design §5.3).
// The legitimate client and an attacker cannot both hold the current token, so
// a second use of a spent one means the family leaked.
func TestRotateReuseRevokesWholeFamily(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := NewMemoryStore()
	s, rt1 := newSession(t, now)
	if err := createWithRefresh(t, st, s, rt1); err != nil {
		t.Fatalf("Create: %v", err)
	}

	rt2, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt1, rt2, now); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The attacker replays the token the legitimate client already spent.
	stolen, _ := NewRefreshToken()
	_, err := st.Rotate(ctx, rt1, stolen, now.Add(time.Second))
	if !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("replay of a spent token = %v; want ErrRefreshReused", err)
	}

	// The session is now dead for everyone, including the legitimate client
	// holding the current token. That is deliberate: it is better to log both
	// parties out than to let an attacker keep a working session.
	got, err := st.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Revoked {
		t.Error("session was not revoked after refresh-token reuse")
	}
	rt3, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt2, rt3, now.Add(2*time.Second)); err == nil {
		t.Error("the current token still works after the family was revoked")
	}
}

// TestRotateIsAtomicUnderConcurrency is the property the theft detection rests
// on: two simultaneous uses of one token must yield exactly one success.
func TestRotateIsAtomicUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := NewMemoryStore()
	s, rt1 := newSession(t, now)
	if err := createWithRefresh(t, st, s, rt1); err != nil {
		t.Fatalf("Create: %v", err)
	}

	const racers = 16
	var wg sync.WaitGroup
	results := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next, _ := NewRefreshToken()
			<-start
			_, err := st.Rotate(ctx, rt1, next, now)
			results[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("%d concurrent rotations succeeded; want exactly 1", successes)
	}
}

func TestRotateRejectsUnknownAndExpired(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := NewMemoryStore()
	s, rt1 := newSession(t, now)
	if err := createWithRefresh(t, st, s, rt1); err != nil {
		t.Fatalf("Create: %v", err)
	}

	next, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, "never-issued", next, now); !errors.Is(err, ErrRefreshUnknown) {
		t.Errorf("unknown token = %v; want ErrRefreshUnknown", err)
	}

	// Past the sliding window: the session died of inactivity.
	if _, err := st.Rotate(ctx, rt1, next, now.Add(RefreshTTL+time.Minute)); !errors.Is(err, ErrRefreshExpired) {
		t.Errorf("expired token = %v; want ErrRefreshExpired", err)
	}
}

func TestRevokeKillsFamily(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := NewMemoryStore()
	s, rt1 := newSession(t, now)
	if err := createWithRefresh(t, st, s, rt1); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Revoke(ctx, s.ID, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, _ := st.Get(ctx, s.ID)
	if !got.Revoked || got.RevokedAt.IsZero() {
		t.Errorf("session not marked revoked: %+v", got)
	}
	if got.Active(now) {
		t.Error("revoked session reports itself active")
	}
	next, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt1, next, now); err == nil {
		t.Error("refresh still works after revocation")
	}
	if err := st.Revoke(ctx, "sess_nope", now); !errors.Is(err, ErrNoSession) {
		t.Errorf("Revoke(unknown) = %v; want ErrNoSession", err)
	}
}

func TestListNewestFirst(t *testing.T) {
	ctx := context.Background()
	base := time.Now().UTC()
	st := NewMemoryStore()
	for i := range 3 {
		s, rt := newSession(t, base.Add(time.Duration(i)*time.Hour))
		if err := createWithRefresh(t, st, s, rt); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	got, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d; want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].CreatedAt.Before(got[i].CreatedAt) {
			t.Error("List is not newest-first")
		}
	}
}

func TestTouchUpdatesLastSeenWithoutRotating(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	st := NewMemoryStore()
	s, rt := newSession(t, now)
	if err := createWithRefresh(t, st, s, rt); err != nil {
		t.Fatalf("Create: %v", err)
	}
	later := now.Add(time.Hour)
	if err := st.Touch(ctx, s.ID, later); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, _ := st.Get(ctx, s.ID)
	if !got.LastSeen.Equal(later) {
		t.Errorf("LastSeen = %s; want %s", got.LastSeen, later)
	}
	if got.Rotations != 0 {
		t.Errorf("Touch incremented Rotations to %d", got.Rotations)
	}
	// Touch must not extend the window; only a rotation does that.
	if !got.ExpiresAt.Equal(now.Add(RefreshTTL)) {
		t.Errorf("ExpiresAt moved on Touch: %s", got.ExpiresAt)
	}
}

func TestCreateValidates(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	if err := st.Create(ctx, nil); err == nil {
		t.Error("Create(nil) succeeded")
	}
	if err := st.Create(ctx, &Session{}); err == nil {
		t.Error("Create with no id succeeded")
	}
	s, _ := newSession(t, time.Now())
	if err := st.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.Create(ctx, s); err == nil {
		t.Error("creating the same session twice succeeded")
	}
	if err := st.IssueRefresh(ctx, s.ID, "", time.Now()); err == nil {
		t.Error("IssueRefresh with an empty token succeeded")
	}
	if err := st.IssueRefresh(ctx, "sess_nope", "tok", time.Now()); err == nil {
		t.Error("IssueRefresh for an unknown session succeeded")
	}
}

func TestTokensAreUnpredictable(t *testing.T) {
	seen := make(map[string]bool, 200)
	for range 100 {
		rt, err := NewRefreshToken()
		if err != nil {
			t.Fatalf("NewRefreshToken: %v", err)
		}
		// 256 bits, base64url: 43 characters.
		if len(rt) != 43 {
			t.Fatalf("refresh token length = %d; want 43 (256 bits)", len(rt))
		}
		if seen[rt] {
			t.Fatal("duplicate refresh token")
		}
		seen[rt] = true

		sid, err := NewSessionID()
		if err != nil {
			t.Fatalf("NewSessionID: %v", err)
		}
		if seen[sid] {
			t.Fatal("duplicate session id")
		}
		seen[sid] = true
	}
}

func TestNormalizeScopes(t *testing.T) {
	got := NormalizeScopes([]string{"WHOIS:RAW", " whois:read ", "whois:read", ""})
	if len(got) != 2 || got[0] != "whois:raw" || got[1] != "whois:read" {
		t.Errorf("NormalizeScopes = %v; want [whois:raw whois:read]", got)
	}
}
