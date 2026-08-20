package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/qjam/whois-mcp/internal/auth"
	"github.com/qjam/whois-mcp/internal/cache"
)

// TestBuildAuthUsesTheStoreItWasGiven is a regression test.
//
// buildAuth used to construct auth.NewMemoryStore() internally and ignore the
// configured backend, so WHOIS_MCP_SESSION_STORE=redis built a RedisStore in
// buildStores that nothing referenced. Every replica kept sessions in its own
// memory, and a client that enrolled against one replica was rejected by the
// next request the load balancer routed elsewhere.
//
// Nothing single-process could see it: with one replica, a private memory store
// behaves exactly like a shared one. The compose end-to-end run caught it. This
// test makes the wiring itself checkable without a two-replica stack — it
// asserts identity, not behaviour, because identity is the property that broke.
func TestBuildAuthUsesTheStoreItWasGiven(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	want := auth.NewMemoryStore()

	stack, err := buildAuth(
		config{listen: "127.0.0.1:8080"},
		authConfig{enrollmentToken: "an-enrollment-token-long-enough-to-pass"},
		cache.NewMemory(),
		want,
		quiet,
	)
	if err != nil {
		t.Fatalf("buildAuth: %v", err)
	}
	if stack == nil {
		t.Fatal("buildAuth returned no stack with an enrollment token configured")
	}
	if stack.sessions != auth.SessionStore(want) {
		t.Error("buildAuth substituted its own session store for the one it was given; " +
			"with a Redis-backed store configured, sessions would silently be per-replica")
	}
}

// TestBuildAuthRefusesWithoutASessionStore: enabling authentication with no
// store would fail at the first enrollment rather than at startup.
func TestBuildAuthRefusesWithoutASessionStore(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := buildAuth(
		config{listen: "127.0.0.1:8080"},
		authConfig{enrollmentToken: "an-enrollment-token-long-enough-to-pass"},
		cache.NewMemory(),
		nil,
		quiet,
	)
	if err == nil {
		t.Error("buildAuth accepted a nil session store")
	}
}

// TestBuildAuthDisabledWithoutAToken pins the unauthenticated shape: no token
// means no stack, which is what leaves the M0/M1 loopback-only mode working.
func TestBuildAuthDisabledWithoutAToken(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	stack, err := buildAuth(
		config{listen: "127.0.0.1:8080"},
		authConfig{},
		cache.NewMemory(),
		auth.NewMemoryStore(),
		quiet,
	)
	if err != nil {
		t.Fatalf("buildAuth: %v", err)
	}
	if stack != nil {
		t.Error("buildAuth built an auth stack with no enrollment token configured")
	}
}
