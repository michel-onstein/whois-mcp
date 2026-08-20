package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHostKey(t *testing.T) {
	cases := map[string]string{
		"whois.nic.uk":                       "whois.nic.uk",
		"WHOIS.NIC.UK":                       "whois.nic.uk",
		"whois.nic.uk:43":                    "whois.nic.uk",
		"whois.nic.uk.":                      "whois.nic.uk",
		"https://rdap.verisign.com/com/v1/":  "rdap.verisign.com",
		"https://rdap.example.com:8443/path": "rdap.example.com",
		"  https://Rdap.Example.com/x  ":     "rdap.example.com",
		"[2001:db8::1]:43":                   "[2001:db8::1]",
		"":                                   "unknown",
	}
	for in, want := range cases {
		if got := HostKey(in); got != want {
			t.Errorf("HostKey(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestHostKeyGroupsSharedRegistries is the point of keying by host: .com and
// .net share one Verisign endpoint, and two separately-polite streams to it
// would add up to one impolite one.
func TestHostKeyGroupsSharedRegistries(t *testing.T) {
	com := HostKey("https://rdap.verisign.com/com/v1/domain/example.com")
	net := HostKey("https://rdap.verisign.com/net/v1/domain/example.net")
	if com != net {
		t.Errorf("%q and %q are different keys; they are the same quota", com, net)
	}
}

func TestAcquireAllowsBurstThenPaces(t *testing.T) {
	l := New(Options{Rate: 100, Burst: 3})
	var slept []time.Duration
	l.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		return nil
	}
	ctx := context.Background()

	// The burst goes straight through: an agent checking a handful of names
	// should not be serialised to a metronome.
	for i := range 3 {
		if err := l.Acquire(ctx, "whois.example"); err != nil {
			t.Fatalf("burst request %d: %v", i, err)
		}
	}
	if len(slept) != 0 {
		t.Errorf("burst was delayed: %v", slept)
	}
	// The next one waits.
	if err := l.Acquire(ctx, "whois.example"); err != nil {
		t.Fatalf("post-burst request: %v", err)
	}
	if len(slept) != 1 || slept[0] <= 0 {
		t.Errorf("post-burst request was not paced: %v", slept)
	}
}

func TestAcquireIsPerHost(t *testing.T) {
	l := New(Options{Rate: 1, Burst: 1})
	l.sleep = func(context.Context, time.Duration) error {
		t.Error("a different host should not have to wait")
		return nil
	}
	ctx := context.Background()
	if err := l.Acquire(ctx, "a.example"); err != nil {
		t.Fatalf("a: %v", err)
	}
	if err := l.Acquire(ctx, "b.example"); err != nil {
		t.Fatalf("b: %v", err)
	}
}

func TestAcquireRefusesWhenTokenWouldOutliveDeadline(t *testing.T) {
	l := New(Options{Rate: 0.001, Burst: 1}) // one token per ~17 minutes
	ctx := context.Background()
	if err := l.Acquire(ctx, "slow.example"); err != nil {
		t.Fatalf("first request: %v", err)
	}
	err := l.Acquire(ctx, "slow.example")
	if !errors.Is(err, ErrWouldExceedDeadline) {
		t.Fatalf("err = %v; want ErrWouldExceedDeadline rather than a long block", err)
	}
}

func TestAcquireHonoursContextDeadline(t *testing.T) {
	l := New(Options{Rate: 1, Burst: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	if err := l.Acquire(ctx, "x.example"); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// The next token is a second away; the deadline is 10ms.
	if err := l.Acquire(ctx, "x.example"); err == nil {
		t.Fatal("Acquire waited past the caller's deadline")
	}
}

// TestObserveHonoursRetryAfterExactly is design §9's requirement: guessing a
// shorter pause than the registry asked for is how a polite client becomes an
// impolite one.
func TestObserveHonoursRetryAfterExactly(t *testing.T) {
	l := New(Options{})
	base := time.Now()
	l.now = func() time.Time { return base }

	l.Observe("denic.example", http.StatusTooManyRequests, "120")

	until, paused := l.PausedUntil("denic.example")
	if !paused {
		t.Fatal("no pause recorded after a 429 with Retry-After")
	}
	if got := until.Sub(base); got != 120*time.Second {
		t.Errorf("pause = %v; want exactly the 120s the upstream asked for", got)
	}

	// During the pause, Acquire refuses rather than waiting it out silently.
	err := l.Acquire(context.Background(), "denic.example")
	var throttled *ErrThrottled
	if !errors.As(err, &throttled) {
		t.Fatalf("err = %v; want ErrThrottled", err)
	}
	if throttled.RetryAfter(base) != 120*time.Second {
		t.Errorf("RetryAfter = %v; want 120s", throttled.RetryAfter(base))
	}

	// After it elapses, traffic resumes.
	l.now = func() time.Time { return base.Add(121 * time.Second) }
	if err := l.Acquire(context.Background(), "denic.example"); err != nil {
		t.Errorf("still throttled after the pause elapsed: %v", err)
	}
}

func TestObserveBacksOffWithoutAHint(t *testing.T) {
	l := New(Options{})
	base := time.Now()
	l.now = func() time.Time { return base }

	l.Observe("quiet.example", http.StatusInternalServerError, "")
	if _, paused := l.PausedUntil("quiet.example"); !paused {
		t.Error("no pause after a 5xx with no Retry-After")
	}
	if l.Failures("quiet.example") != 1 {
		t.Errorf("failures = %d; want 1", l.Failures("quiet.example"))
	}

	// A success clears both.
	l.Observe("quiet.example", http.StatusOK, "")
	if l.Failures("quiet.example") != 0 {
		t.Error("failures not reset after success")
	}
	if _, paused := l.PausedUntil("quiet.example"); paused {
		t.Error("pause survived a success")
	}
}

// TestObserveTransportFailureCountsButDoesNotPause is the division of labour
// between the two mechanisms. Pausing here as well would stop the breaker ever
// reaching its threshold, because every call after the first would be refused by
// the limiter before it reached the upstream.
func TestObserveTransportFailureCountsButDoesNotPause(t *testing.T) {
	l := New(Options{})
	l.Observe("dead.example", 0, "")

	if l.Failures("dead.example") != 1 {
		t.Errorf("failures = %d; want 1 for a transport failure", l.Failures("dead.example"))
	}
	if until, paused := l.PausedUntil("dead.example"); paused {
		t.Errorf("a transport failure set a pause until %s; that is the breaker's job", until)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	if d, ok := ParseRetryAfter("30", now); !ok || d != 30*time.Second {
		t.Errorf("delta-seconds: %v %v", d, ok)
	}
	if d, ok := ParseRetryAfter("  30  ", now); !ok || d != 30*time.Second {
		t.Errorf("padded delta-seconds: %v %v", d, ok)
	}
	// HTTP-date form.
	future := now.Add(90 * time.Second).Format(http.TimeFormat)
	if d, ok := ParseRetryAfter(future, now); !ok || d < 89*time.Second || d > 90*time.Second {
		t.Errorf("http-date: %v %v", d, ok)
	}
	// A past date is an answer ("no pause"), not an absence of one.
	past := now.Add(-time.Hour).Format(http.TimeFormat)
	if d, ok := ParseRetryAfter(past, now); !ok || d != 0 {
		t.Errorf("past http-date: %v %v; want 0, true", d, ok)
	}
	// Absent or nonsense: no instruction.
	for _, v := range []string{"", "   ", "soon", "-5"} {
		if _, ok := ParseRetryAfter(v, now); ok {
			t.Errorf("ParseRetryAfter(%q) reported an instruction", v)
		}
	}
	// A wildly long pause is capped: a registry asking for a day is asking us
	// to stop serving that TLD.
	if d, _ := ParseRetryAfter("86400", now); d != maxPause {
		t.Errorf("a 24h Retry-After was honoured as %v; want the %v cap", d, maxPause)
	}
}

// TestBackoffIsJitteredAndBounded: full jitter is the part that matters. Without
// it every replica that saw the same failure retries at the same instant.
func TestBackoffIsJitteredAndBounded(t *testing.T) {
	seen := make(map[time.Duration]bool)
	for range 200 {
		d := Backoff(5)
		if d <= 0 {
			t.Fatalf("Backoff returned %v", d)
		}
		seen[d] = true
	}
	if len(seen) < 20 {
		t.Errorf("only %d distinct delays in 200 draws; the jitter is not doing anything", len(seen))
	}
	for _, failures := range []int{1, 5, 20, 100, 1000} {
		if d := Backoff(failures); d > backoffMax {
			t.Errorf("Backoff(%d) = %v; exceeds the %v ceiling", failures, d, backoffMax)
		}
	}
	// Monotonic in expectation: the ceiling grows with failures.
	if maxOf(t, 1) >= maxOf(t, 8) {
		t.Error("backoff does not grow with the failure count")
	}
}

func maxOf(t *testing.T, failures int) time.Duration {
	t.Helper()
	var m time.Duration
	for range 500 {
		if d := Backoff(failures); d > m {
			m = d
		}
	}
	return m
}

func TestBreakerOpensAfterThreshold(t *testing.T) {
	b := NewBreaker(BreakerOptions{Threshold: 3, Cooldown: time.Minute})
	base := time.Now()
	b.now = func() time.Time { return base }

	for i := range 3 {
		rel, err := b.Allow("bad.example")
		if err != nil {
			t.Fatalf("call %d refused too early: %v", i, err)
		}
		rel(false)
	}
	if got := b.State("bad.example"); got != Open {
		t.Fatalf("state = %q; want open", got)
	}
	_, err := b.Allow("bad.example")
	if !IsOpen(err) {
		t.Fatalf("err = %v; want ErrCircuitOpen", err)
	}
	if !strings.Contains(err.Error(), "bad.example") {
		t.Errorf("error does not name the host: %v", err)
	}
	if hosts := b.OpenHosts(); len(hosts) != 1 || hosts[0] != "bad.example" {
		t.Errorf("OpenHosts = %v", hosts)
	}
}

// TestBreakerIsPerHost is the reason it exists: one dead registry must not
// consume the concurrency budget that keeps every other TLD working.
func TestBreakerIsPerHost(t *testing.T) {
	b := NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute})
	for range 2 {
		rel, _ := b.Allow("dead.example")
		rel(false)
	}
	if _, err := b.Allow("dead.example"); !IsOpen(err) {
		t.Fatal("dead host is not open")
	}
	rel, err := b.Allow("healthy.example")
	if err != nil {
		t.Fatalf("healthy host was refused: %v", err)
	}
	rel(true)
}

func TestBreakerHalfOpenRecovery(t *testing.T) {
	b := NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute, Probes: 2})
	base := time.Now()
	now := base
	b.now = func() time.Time { return now }

	for range 2 {
		rel, _ := b.Allow("flappy.example")
		rel(false)
	}
	if _, err := b.Allow("flappy.example"); !IsOpen(err) {
		t.Fatal("not open after the threshold")
	}

	// Cooldown elapses: one probe is admitted, and only one.
	now = base.Add(time.Minute + time.Second)
	rel, err := b.Allow("flappy.example")
	if err != nil {
		t.Fatalf("probe refused after cooldown: %v", err)
	}
	if _, err := b.Allow("flappy.example"); !IsOpen(err) {
		t.Error("a second concurrent probe was admitted; half-open means one at a time")
	}
	rel(true)

	// One success is not enough — a lucky response from a flapping registry is
	// not evidence of recovery.
	if got := b.State("flappy.example"); got != HalfOpen {
		t.Errorf("state after one success = %q; want half-open", got)
	}
	rel2, err := b.Allow("flappy.example")
	if err != nil {
		t.Fatalf("second probe refused: %v", err)
	}
	rel2(true)
	if got := b.State("flappy.example"); got != Closed {
		t.Errorf("state after %d successes = %q; want closed", 2, got)
	}
}

func TestBreakerFailedProbeReopensImmediately(t *testing.T) {
	b := NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute})
	base := time.Now()
	now := base
	b.now = func() time.Time { return now }

	for range 2 {
		rel, _ := b.Allow("still.example")
		rel(false)
	}
	now = base.Add(2 * time.Minute)
	rel, err := b.Allow("still.example")
	if err != nil {
		t.Fatalf("probe refused: %v", err)
	}
	rel(false)
	// Half-open already established doubt, so one failure re-opens rather than
	// needing another threshold's worth.
	if _, err := b.Allow("still.example"); !IsOpen(err) {
		t.Error("a failed probe did not re-open the circuit")
	}
}

func TestBreakerReleaseIsIdempotent(t *testing.T) {
	b := NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute})
	rel, err := b.Allow("x.example")
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	rel(false)
	rel(false) // a double release must not count twice
	if got := b.State("x.example"); got == Open {
		t.Error("a double release counted as two failures and opened the circuit")
	}
}

func TestBreakerConcurrentUse(t *testing.T) {
	b := NewBreaker(BreakerOptions{Threshold: 100, Cooldown: time.Second})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rel, err := b.Allow("busy.example")
			if err == nil {
				rel(i%2 == 0)
			}
		}(i)
	}
	wg.Wait()
	// Nothing to assert beyond "no race and no panic"; -race is the test.
	_ = b.State("busy.example")
}

func TestLimiterConcurrentUse(t *testing.T) {
	l := New(Options{Rate: 1000, Burst: 1000})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = l.Acquire(context.Background(), "busy.example")
			l.Observe("busy.example", http.StatusOK, "")
		}(i)
	}
	wg.Wait()
}
