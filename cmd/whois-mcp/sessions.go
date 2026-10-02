package main

import (
	"context"
	"time"

	"github.com/qjam/whois-mcp/internal/auth"
)

// activeSessions reports the live session count for the metrics gauge, or -1
// when the store cannot answer.
//
// It counts rather than reading a maintained gauge because the store's own view
// is authoritative: a session that expired or was revoked since the last poll
// must drop out of the number without anything having to remember to decrement.
func activeSessions(ctx context.Context, store *auth.MemoryStore, now time.Time) int {
	sessions, err := store.List(ctx)
	if err != nil {
		return -1
	}
	n := 0
	for _, sess := range sessions {
		if sess.Active(now) {
			n++
		}
	}
	return n
}
