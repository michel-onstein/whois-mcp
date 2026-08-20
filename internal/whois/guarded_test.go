package whois

import (
	"context"
	"testing"
	"time"

	"github.com/qjam/whois-mcp/internal/ratelimit"
	"github.com/qjam/whois-mcp/internal/whois/whoistest"
)

// TestBreakerStopsDialingInPractice proves the guard is wired into the
// transport rather than merely attachable. The failure it guards against is
// silent: a breaker that is never consulted looks exactly like a healthy one.
func TestBreakerStopsDialingInPractice(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "Domain Name: x.test\r\n")

	br := ratelimit.NewBreaker(ratelimit.BreakerOptions{Threshold: 1, Cooldown: time.Hour})
	tr := NewTransportWithOptions(2*time.Second, TransportOptions{AllowPrivateAddresses: true}).
		WithGuard(ratelimit.NewGuard(nil, br))

	// Trip the breaker by hand on the exact key the transport will use.
	rel, err := br.Allow(srv.Addr)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	rel(false)

	before := srv.Conns()
	_, err = tr.Query(context.Background(), srv.Addr, "x.test")
	if !ratelimit.IsOpen(err) {
		t.Fatalf("err = %v; want ErrCircuitOpen", err)
	}
	if srv.Conns() != before {
		t.Error("the transport dialled despite an open circuit")
	}
}

// TestThrottlePreventsQuery covers the other half: an active Retry-After pause
// must stop the exchange, not merely be recorded.
func TestThrottlePreventsQuery(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "Domain Name: x.test\r\n")

	lim := ratelimit.New(ratelimit.Options{Rate: 100, Burst: 100})
	// A 429-equivalent with an explicit pause. Port 43 has no status codes, so
	// this models an HTTP upstream; the limiter is shared across both protocols.
	lim.Observe(srv.Addr, 429, "300")

	tr := NewTransportWithOptions(2*time.Second, TransportOptions{AllowPrivateAddresses: true}).
		WithGuard(ratelimit.NewGuard(lim, nil))

	before := srv.Conns()
	if _, err := tr.Query(context.Background(), srv.Addr, "x.test"); err == nil {
		t.Fatal("Query succeeded during a Retry-After pause")
	}
	if srv.Conns() != before {
		t.Error("the transport dialled during a Retry-After pause")
	}
}

// TestGuardRecordsPort43FailuresAgainstTheBreaker: a registry that stops
// answering is precisely what the breaker is for, and port 43 gives no status
// code to work from, so the transport-level error is the only signal.
func TestGuardRecordsPort43FailuresAgainstTheBreaker(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "")
	addr := srv.Addr
	srv.Close() // nothing listening

	br := ratelimit.NewBreaker(ratelimit.BreakerOptions{Threshold: 2, Cooldown: time.Hour})
	tr := NewTransportWithOptions(500*time.Millisecond, TransportOptions{AllowPrivateAddresses: true}).
		WithGuard(ratelimit.NewGuard(nil, br))

	for range 2 {
		if _, err := tr.Query(context.Background(), addr, "x.test"); err == nil {
			t.Fatal("Query succeeded against a closed port")
		}
	}
	if got := br.State(addr); got != ratelimit.Open {
		t.Errorf("breaker state = %q after two dial failures; want open", got)
	}
	// And now it fails fast rather than waiting out another dial timeout.
	start := time.Now()
	_, err := tr.Query(context.Background(), addr, "x.test")
	if !ratelimit.IsOpen(err) {
		t.Fatalf("err = %v; want ErrCircuitOpen", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("open circuit took %v to refuse; the point is to fail fast", elapsed)
	}
}

// TestSuccessKeepsCircuitClosed is the control: without it, a breaker that
// opened on every call would pass the tests above.
func TestSuccessKeepsCircuitClosed(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "Domain Name: x.test\r\n")
	br := ratelimit.NewBreaker(ratelimit.BreakerOptions{Threshold: 2, Cooldown: time.Hour})
	tr := NewTransportWithOptions(2*time.Second, TransportOptions{AllowPrivateAddresses: true}).
		WithGuard(ratelimit.NewGuard(ratelimit.New(ratelimit.Options{Rate: 100, Burst: 100}), br))

	for i := range 5 {
		if _, err := tr.Query(context.Background(), srv.Addr, "x.test"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := br.State(srv.Addr); got != ratelimit.Closed {
		t.Errorf("breaker state = %q after five successes; want closed", got)
	}
	if srv.Conns() != 5 {
		t.Errorf("server saw %d connections; want 5", srv.Conns())
	}
}

// TestNilGuardIsTransparent keeps the unit tests in this package honest: they
// construct transports without a guard, and that must mean "no policy" rather
// than "no calls".
func TestNilGuardIsTransparent(t *testing.T) {
	srv := whoistest.New(t, whoistest.ModeNormal, "Domain Name: x.test\r\n")
	tr := testTransport(t, 2*time.Second) // no guard attached
	if _, err := tr.Query(context.Background(), srv.Addr, "x.test"); err != nil {
		t.Fatalf("Query with no guard: %v", err)
	}
}
