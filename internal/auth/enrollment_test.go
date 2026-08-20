package auth

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func testEnrollment(t *testing.T, secret string) (*Enrollment, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e, err := NewEnrollment(secret, log)
	if err != nil {
		t.Fatalf("NewEnrollment: %v", err)
	}
	return e, &logBuf
}

func TestVerifyAcceptsCorrectSecret(t *testing.T) {
	secret, err := GenerateEnrollmentToken()
	if err != nil {
		t.Fatalf("GenerateEnrollmentToken: %v", err)
	}
	e, _ := testEnrollment(t, secret)

	if err := e.Verify("10.1.2.3:5000", secret); err != nil {
		t.Fatalf("Verify with the correct secret: %v", err)
	}
	// Surrounding whitespace is tolerated: an operator pasting into a browser
	// form will bring a trailing newline sooner or later.
	if err := e.Verify("10.1.2.3:5000", "  "+secret+"\n"); err != nil {
		t.Errorf("Verify with padded secret: %v", err)
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	e, _ := testEnrollment(t, "the-real-secret-value-long-enough")

	for _, wrong := range []string{"", "wrong", "the-real-secret-value-long-enoug", "The-Real-Secret-Value-Long-Enough"} {
		if err := e.Verify("10.1.2.3:5000", wrong); !errors.Is(err, ErrWrongSecret) {
			t.Errorf("Verify(%q) = %v; want ErrWrongSecret", wrong, err)
		}
	}
}

func TestNewEnrollmentRejectsEmptySecret(t *testing.T) {
	// An empty enrollment token authorizes everyone; refusing to start is the
	// correct failure.
	for _, s := range []string{"", "   ", "\n\t"} {
		if _, err := NewEnrollment(s, nil); err == nil {
			t.Errorf("NewEnrollment(%q) succeeded", s)
		}
	}
}

// TestLockoutTripsAndBacksOff is the brute-force defence: the guesser's cost
// must rise, while a human who mistyped once waits seconds.
func TestLockoutTripsAndBacksOff(t *testing.T) {
	e, _ := testEnrollment(t, "correct-horse-battery-staple-long")
	base := time.Now()
	e.now = func() time.Time { return base }

	const src = "10.9.9.9:1234"
	for i := range LockoutThreshold - 1 {
		if err := e.Verify(src, "nope"); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("attempt %d = %v; want ErrWrongSecret", i, err)
		}
	}
	if err := e.Verify(src, "nope"); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("threshold attempt = %v; want ErrWrongSecret", err)
	}
	// Now even the correct secret is refused until the lockout elapses, which
	// is the point: an attacker who guesses right on attempt six still waits.
	if err := e.Verify(src, "correct-horse-battery-staple-long"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("during lockout = %v; want ErrLockedOut", err)
	}

	e.now = func() time.Time { return base.Add(LockoutBase + time.Second) }
	if err := e.Verify(src, "correct-horse-battery-staple-long"); err != nil {
		t.Fatalf("after lockout elapsed: %v", err)
	}
}

func TestLockoutBackoffGrowsAndIsCapped(t *testing.T) {
	e, _ := testEnrollment(t, "correct-horse-battery-staple-long")
	base := time.Now()
	now := base
	e.now = func() time.Time { return now }

	const src = "10.9.9.9:1"
	var lockouts []time.Duration
	for range 12 {
		err := e.Verify(src, "wrong")
		if errors.Is(err, ErrLockedOut) {
			e.mu.Lock()
			st := e.sources[hashSource(src)]
			wait := st.lockedThru.Sub(now)
			e.mu.Unlock()
			lockouts = append(lockouts, wait)
			now = now.Add(wait + time.Millisecond)
		}
	}
	if len(lockouts) < 2 {
		t.Fatalf("expected several lockouts, got %d", len(lockouts))
	}
	for i := 1; i < len(lockouts); i++ {
		if lockouts[i] < lockouts[i-1] {
			t.Errorf("backoff shrank: %v then %v", lockouts[i-1], lockouts[i])
		}
		if lockouts[i] > LockoutMax {
			t.Errorf("backoff %v exceeds the %v cap", lockouts[i], LockoutMax)
		}
	}
}

// TestLockoutIsPerSource keeps one noisy client from locking everyone out.
func TestLockoutIsPerSource(t *testing.T) {
	secret := "correct-horse-battery-staple-long"
	e, _ := testEnrollment(t, secret)
	base := time.Now()
	e.now = func() time.Time { return base }

	for range LockoutThreshold + 1 {
		_ = e.Verify("10.0.0.1:1", "wrong")
	}
	if err := e.Verify("10.0.0.1:1", secret); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("noisy source not locked out: %v", err)
	}
	if err := e.Verify("10.0.0.2:1", secret); err != nil {
		t.Errorf("unrelated source was locked out: %v", err)
	}
}

// TestFailuresExpireAfterWindow: yesterday's typo must not count today, but a
// patient guesser should not get a free reset either — hence an hour.
func TestFailuresExpireAfterWindow(t *testing.T) {
	secret := "correct-horse-battery-staple-long"
	e, _ := testEnrollment(t, secret)
	base := time.Now()
	e.now = func() time.Time { return base }

	for range LockoutThreshold + 1 {
		_ = e.Verify("10.0.0.5:1", "wrong")
	}
	e.now = func() time.Time { return base.Add(AttemptWindow + time.Minute) }
	if err := e.Verify("10.0.0.5:1", secret); err != nil {
		t.Errorf("stale failures still counted: %v", err)
	}
}

// TestAuditLogNeverRecordsTheToken is design §5.7's explicit requirement.
func TestAuditLogNeverRecordsTheToken(t *testing.T) {
	secret := "super-secret-enrollment-token-value"
	e, logBuf := testEnrollment(t, secret)

	_ = e.Verify("203.0.113.7:4444", secret)
	_ = e.Verify("203.0.113.7:4444", "wrong-guess")
	for range LockoutThreshold {
		_ = e.Verify("203.0.113.7:4444", "wrong-guess")
	}
	_ = e.Verify("203.0.113.7:4444", secret)

	logged := logBuf.String()
	if logged == "" {
		t.Fatal("nothing was audit-logged")
	}
	if strings.Contains(logged, secret) {
		t.Error("the audit log contains the enrollment token")
	}
	if strings.Contains(logged, "wrong-guess") {
		t.Error("the audit log contains a presented token value")
	}
	for _, want := range []string{"enrollment succeeded", "enrollment attempt failed", "locked out"} {
		if !strings.Contains(logged, want) {
			t.Errorf("audit log lacks %q:\n%s", want, logged)
		}
	}
	// The exact client address is not recorded; a /24 answers the operational
	// question without turning the log into a record of who probed us.
	if strings.Contains(logged, "203.0.113.7") {
		t.Error("the audit log contains the exact client address")
	}
	if !strings.Contains(logged, "203.0.113.0/24") {
		t.Errorf("audit log lacks the redacted source:\n%s", logged)
	}
}

func TestRedactSource(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7:4444":  "203.0.113.0/24",
		"203.0.113.7":       "203.0.113.0/24",
		"[2001:db8::1]:443": "2001:db8::/48",
		"garbage":           "unknown",
		"":                  "unknown",
	}
	for in, want := range cases {
		if got := redactSource(in); got != want {
			t.Errorf("redactSource(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestGeneratedTokenIsLongAndUnique(t *testing.T) {
	seen := make(map[string]bool, 64)
	for range 64 {
		tok, err := GenerateEnrollmentToken()
		if err != nil {
			t.Fatalf("GenerateEnrollmentToken: %v", err)
		}
		if len(tok) != 43 {
			t.Fatalf("token length = %d; want 43 (256 bits)", len(tok))
		}
		if seen[tok] {
			t.Fatal("duplicate generated token")
		}
		seen[tok] = true
	}
}

func TestShortSecretWarnsButStarts(t *testing.T) {
	e, logBuf := testEnrollment(t, "short")
	if e == nil {
		t.Fatal("NewEnrollment refused a short secret; it should warn instead")
	}
	if !strings.Contains(logBuf.String(), "shorter than recommended") {
		t.Errorf("no warning for a short secret:\n%s", logBuf.String())
	}
}
