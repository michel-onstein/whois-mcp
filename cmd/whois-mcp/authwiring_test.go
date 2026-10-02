package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/qjam/whois-mcp/internal/auth"
)

// TestBuildAuthUsesTheStoreItWasGiven is a regression test.
//
// buildAuth used to construct auth.NewMemoryStore() internally and ignore the
// store it was handed, so the store the rest of the process held — and reported
// sessions from — was never the one enrollment wrote to. Only an end-to-end
// run noticed. This test asserts identity, not behaviour, because identity is
// the property that broke.
func TestBuildAuthUsesTheStoreItWasGiven(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	want := auth.NewMemoryStore()

	stack, err := buildAuth(
		config{listen: "127.0.0.1:8080"},
		authConfig{enrollmentToken: "an-enrollment-token-long-enough-to-pass"},
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
			"the rest of the process would then never see the sessions enrollment creates")
	}
}

// TestBuildAuthRefusesWithoutASessionStore: enabling authentication with no
// store would fail at the first enrollment rather than at startup.
func TestBuildAuthRefusesWithoutASessionStore(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := buildAuth(
		config{listen: "127.0.0.1:8080"},
		authConfig{enrollmentToken: "an-enrollment-token-long-enough-to-pass"},
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
