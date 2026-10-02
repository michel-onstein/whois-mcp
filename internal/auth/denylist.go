package auth

import (
	"context"
	"sync"
	"time"
)

// Denylist bounds how long a revoked session keeps working.
//
// Access tokens verify locally with no store read, and that also means revoking
// a session cannot instantly stop tokens already minted for it. The denylist is
// the deliberate compromise: one map lookup on the hot path, keyed by sid, with
// entries expiring after exactly one access-token TTL.
//
// That TTL is not arbitrary. After AccessTokenTTL has elapsed, every token
// minted before the revocation has expired on its own, so the entry has nothing
// left to protect against and holding it longer would only grow the set. The
// worst-case window between "revoked" and "no longer usable" is therefore one
// access-token lifetime, and it is bounded without a per-request database read.
//
// It is in-process because the server is: there is one replica (design §11.3),
// so the process that receives a revocation is the only one that ever verifies
// a token.
type Denylist struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.RWMutex
	revoked map[string]time.Time
}

// NewDenylist returns an empty Denylist.
func NewDenylist() *Denylist {
	return &Denylist{
		ttl:     AccessTokenTTL,
		now:     time.Now,
		revoked: make(map[string]time.Time),
	}
}

// Add denies a session for one access-token lifetime.
func (d *Denylist) Add(_ context.Context, sid string) {
	if sid == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.revoked[sid] = d.now().Add(d.ttl)
}

// Denied reports whether a session is currently revoked.
func (d *Denylist) Denied(_ context.Context, sid string) bool {
	if sid == "" {
		return false
	}
	d.mu.RLock()
	until, ok := d.revoked[sid]
	d.mu.RUnlock()
	if !ok {
		return false
	}
	if d.now().After(until) {
		d.mu.Lock()
		delete(d.revoked, sid)
		d.mu.Unlock()
		return false
	}
	return true
}
