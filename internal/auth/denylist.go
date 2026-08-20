package auth

import (
	"context"
	"sync"
	"time"

	"github.com/qjam/whois-mcp/internal/cache"
)

// Denylist bounds how long a revoked session keeps working.
//
// Access tokens verify locally with no store read, which is what makes replicas
// stateless — and also means revoking a session cannot instantly stop tokens
// already minted for it. The denylist is the deliberate compromise: one lookup
// on the hot path, keyed by sid, with entries expiring after exactly one
// access-token TTL.
//
// That TTL is not arbitrary. After AccessTokenTTL has elapsed, every token
// minted before the revocation has expired on its own, so the entry has nothing
// left to protect against and holding it longer would only grow the set. The
// worst-case window between "revoked" and "no longer usable" is therefore one
// access-token lifetime, and it is bounded without a per-request database read.
type Denylist struct {
	store cache.Cache
	ttl   time.Duration
	now   func() time.Time

	// local is a fallback when no shared cache is configured. It exists so a
	// single-replica deployment still revokes correctly; with several replicas
	// and no shared cache, a revocation would only bind on the replica that
	// received it, which is why M3 wires Redis in here.
	mu    sync.RWMutex
	local map[string]time.Time
}

// NewDenylist returns a Denylist. A nil cache uses in-process storage only.
func NewDenylist(store cache.Cache) *Denylist {
	return &Denylist{
		store: store,
		ttl:   AccessTokenTTL,
		now:   time.Now,
		local: make(map[string]time.Time),
	}
}

func denyKey(sid string) string { return "auth:revoked:" + sid }

// Add denies a session for one access-token lifetime.
func (d *Denylist) Add(ctx context.Context, sid string) {
	if sid == "" {
		return
	}
	if d.store != nil {
		d.store.Set(ctx, denyKey(sid), []byte("1"), d.ttl)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.local[sid] = d.now().Add(d.ttl)
}

// Denied reports whether a session is currently revoked.
func (d *Denylist) Denied(ctx context.Context, sid string) bool {
	if sid == "" {
		return false
	}
	if d.store != nil {
		_, ok := d.store.Get(ctx, denyKey(sid))
		return ok
	}
	d.mu.RLock()
	until, ok := d.local[sid]
	d.mu.RUnlock()
	if !ok {
		return false
	}
	if d.now().After(until) {
		d.mu.Lock()
		delete(d.local, sid)
		d.mu.Unlock()
		return false
	}
	return true
}
