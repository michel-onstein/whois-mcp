package main

import (
	"context"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/auth"
)

// TestActiveSessionsCountsOnlyLiveOnes pins what the gauge reports: sessions
// that are revoked or past their expiry are excluded, so the number tracks the
// store's own view rather than a counter something has to remember to decrement.
func TestActiveSessionsCountsOnlyLiveOnes(t *testing.T) {
	ctx := context.Background()
	store := auth.NewMemoryStore()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	for _, s := range []*auth.Session{
		{ID: "sess_live", ExpiresAt: now.Add(time.Hour)},
		{ID: "sess_expired", ExpiresAt: now.Add(-time.Minute)},
		{ID: "sess_revoked", ExpiresAt: now.Add(time.Hour), Revoked: true},
	} {
		if err := store.Create(ctx, s); err != nil {
			t.Fatalf("Create(%s): %v", s.ID, err)
		}
	}

	if got := activeSessions(ctx, store, now); got != 1 {
		t.Errorf("activeSessions = %d; want 1 (one live, one expired, one revoked)", got)
	}
}

func TestActiveSessionsIsZeroOnAnEmptyStore(t *testing.T) {
	if got := activeSessions(context.Background(), auth.NewMemoryStore(), time.Now()); got != 0 {
		t.Errorf("activeSessions on an empty store = %d; want 0, not the -1 that means 'cannot answer'", got)
	}
}
