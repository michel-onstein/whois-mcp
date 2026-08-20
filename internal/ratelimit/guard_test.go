package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestGuardNilIsPassthrough(t *testing.T) {
	var g *Guard
	called := false
	err := g.Do(context.Background(), "h", func(context.Context) Outcome {
		called = true
		return Outcome{Status: 200}
	})
	if err != nil || !called {
		t.Errorf("nil guard did not call through: called=%v err=%v", called, err)
	}
}

// TestGuardOpensBreakerOnRepeatedFailures walks the combined path rather than
// the parts: this is the behaviour a transport actually gets.
func TestGuardOpensBreakerOnRepeatedFailures(t *testing.T) {
	lim := New(Options{Rate: 1000, Burst: 1000})
	br := NewBreaker(BreakerOptions{Threshold: 3, Cooldown: time.Minute})
	g := NewGuard(lim, br)
	ctx := context.Background()
	boom := errors.New("upstream is down")

	for i := range 3 {
		err := g.Do(ctx, "dead.example", func(context.Context) Outcome {
			return Outcome{Status: 0, Err: boom}
		})
		if !errors.Is(err, boom) {
			t.Fatalf("call %d: err = %v; want the upstream error", i, err)
		}
	}

	// The fourth call is refused without being attempted, which is the point:
	// one dead registry must not hold requests open and starve the others.
	attempted := false
	err := g.Do(ctx, "dead.example", func(context.Context) Outcome {
		attempted = true
		return Outcome{Status: 200}
	})
	if !IsOpen(err) {
		t.Fatalf("err = %v; want ErrCircuitOpen", err)
	}
	if attempted {
		t.Error("the call was attempted despite an open circuit")
	}
	if g.State("dead.example") != Open {
		t.Errorf("state = %q; want open", g.State("dead.example"))
	}
}

// TestGuardTreats404AsHealthy is the subtle one: a 404 is a successful
// conversation with a working registry, and counting it as a failure would open
// the breaker on a host that is answering perfectly.
func TestGuardTreats404AsHealthy(t *testing.T) {
	g := NewGuard(New(Options{Rate: 1000, Burst: 1000}),
		NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute}))
	ctx := context.Background()

	for range 10 {
		if err := g.Do(ctx, "fine.example", func(context.Context) Outcome {
			return Outcome{Status: http.StatusNotFound}
		}); err != nil {
			t.Fatalf("404 produced an error: %v", err)
		}
	}
	if got := g.State("fine.example"); got != Closed {
		t.Errorf("state = %q after ten 404s; want closed", got)
	}
}

func TestGuard429CountsAgainstBoth(t *testing.T) {
	lim := New(Options{Rate: 1000, Burst: 1000})
	base := time.Now()
	lim.now = func() time.Time { return base }
	g := NewGuard(lim, NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute}))
	ctx := context.Background()

	err := g.Do(ctx, "busy.example", func(context.Context) Outcome {
		return Outcome{Status: http.StatusTooManyRequests, RetryAfter: "60"}
	})
	if err != nil {
		t.Fatalf("a 429 with no error should not itself error: %v", err)
	}
	// The pause is recorded, so the next attempt is refused by the limiter
	// rather than sent.
	if until, ok := lim.PausedUntil("busy.example"); !ok || until.Sub(base) != time.Minute {
		t.Errorf("pause = %v %v; want exactly 60s", until.Sub(base), ok)
	}
	var throttled *ErrThrottled
	if err := g.Do(ctx, "busy.example", func(context.Context) Outcome {
		t.Error("the call was attempted during a Retry-After pause")
		return Outcome{}
	}); !errors.As(err, &throttled) {
		t.Errorf("err = %v; want ErrThrottled", err)
	}
}

// TestGuardThrottleDoesNotCountAgainstBreaker: a throttle is our own policy
// talking, so it must not be recorded as the upstream failing.
func TestGuardThrottleDoesNotCountAgainstBreaker(t *testing.T) {
	lim := New(Options{Rate: 1000, Burst: 1000})
	base := time.Now()
	lim.now = func() time.Time { return base }
	br := NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute})
	g := NewGuard(lim, br)
	ctx := context.Background()

	// Put the host into a pause.
	lim.Observe("paused.example", http.StatusTooManyRequests, "300")

	for range 5 {
		if err := g.Do(ctx, "paused.example", func(context.Context) Outcome {
			return Outcome{Status: 200}
		}); err == nil {
			t.Fatal("expected a throttle error")
		}
	}
	if got := br.State("paused.example"); got != Closed {
		t.Errorf("breaker state = %q; a throttle must not count as an upstream failure", got)
	}
}

func TestGuardRecoversAfterSuccess(t *testing.T) {
	lim := New(Options{Rate: 1000, Burst: 1000})
	base := time.Now()
	now := base
	lim.now = func() time.Time { return now }
	br := NewBreaker(BreakerOptions{Threshold: 2, Cooldown: time.Minute, Probes: 1})
	br.now = func() time.Time { return now }
	g := NewGuard(lim, br)
	ctx := context.Background()

	for range 2 {
		_ = g.Do(ctx, "flappy.example", func(context.Context) Outcome {
			return Outcome{Status: 0, Err: errors.New("down")}
		})
	}
	if !IsOpen(mustErr(g.Do(ctx, "flappy.example", okOutcome))) {
		t.Fatal("circuit did not open")
	}

	now = base.Add(2 * time.Minute)
	if err := g.Do(ctx, "flappy.example", okOutcome); err != nil {
		t.Fatalf("probe after cooldown: %v", err)
	}
	if got := g.State("flappy.example"); got != Closed {
		t.Errorf("state = %q after a successful probe; want closed", got)
	}
	if hosts := g.OpenHosts(); len(hosts) != 0 {
		t.Errorf("OpenHosts = %v; want empty", hosts)
	}
}

func okOutcome(context.Context) Outcome { return Outcome{Status: 200} }

func mustErr(err error) error { return err }
