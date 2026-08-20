// Package cache defines the result-cache contract and its in-process
// implementation. A Redis implementation lands at M3; the interface exists now
// so that swapping it in requires no changes to callers.
package cache

import (
	"context"
	"sync"
	"time"
)

// Cache is a TTL key/value store. Implementations must be safe for concurrent
// use. Values are opaque bytes so that implementations need not know about
// domain types.
type Cache interface {
	// Get returns the value and true if present and unexpired.
	Get(ctx context.Context, key string) ([]byte, bool)
	// Set stores a value with a time-to-live. A non-positive ttl is a no-op.
	Set(ctx context.Context, key string, val []byte, ttl time.Duration)
	// Delete removes a key if present.
	Delete(ctx context.Context, key string)
}

type entry struct {
	val       []byte
	expiresAt time.Time
}

// Memory is an in-process Cache suitable for development and single-replica
// deployments. Expired entries are evicted lazily on read and by an optional
// background sweep, so a key that is written once and never read again does not
// pin memory forever.
type Memory struct {
	mu    sync.RWMutex
	items map[string]entry
	now   func() time.Time // injectable for tests
}

// NewMemory returns an empty in-process cache.
func NewMemory() *Memory {
	return &Memory{items: make(map[string]entry), now: time.Now}
}

// Get returns the value if present and unexpired, evicting it lazily if not.
func (m *Memory) Get(_ context.Context, key string) ([]byte, bool) {
	m.mu.RLock()
	e, ok := m.items[key]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if m.now().After(e.expiresAt) {
		m.mu.Lock()
		// Re-check under the write lock: another goroutine may have replaced it.
		if cur, still := m.items[key]; still && m.now().After(cur.expiresAt) {
			delete(m.items, key)
		}
		m.mu.Unlock()
		return nil, false
	}
	return e.val, true
}

// Set stores a value. A non-positive ttl is a no-op, per the Cache contract.
func (m *Memory) Set(_ context.Context, key string, val []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	m.mu.Lock()
	m.items[key] = entry{val: val, expiresAt: m.now().Add(ttl)}
	m.mu.Unlock()
}

// Delete removes a key if present.
func (m *Memory) Delete(_ context.Context, key string) {
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
}

// Sweep removes all expired entries. Callers may run it periodically.
func (m *Memory) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, e := range m.items {
		if now.After(e.expiresAt) {
			delete(m.items, k)
		}
	}
}

// Len reports the number of entries, including any not yet swept.
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}
