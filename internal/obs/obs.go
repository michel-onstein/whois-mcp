// Package obs provides structured logging, redaction helpers, and (later)
// metrics and tracing. MCP's Logging feature is deprecated as of the
// 2026-07-28 revision, so diagnostics go to stderr and OpenTelemetry.
package obs

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger returns a JSON logger writing to stderr at the given level.
// Unrecognised levels fall back to info rather than failing startup.
func NewLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// RedactSecret renders a secret safe to log: it reveals nothing about short
// values and only a length hint for longer ones. Never log the raw value of an
// enrollment token, access token, or refresh token.
func RedactSecret(s string) string {
	if s == "" {
		return ""
	}
	return "[redacted len=" + itoa(len(s)) + "]"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
