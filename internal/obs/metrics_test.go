package obs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsRegisterAndExpose(t *testing.T) {
	m := NewMetrics()

	m.ObserveLookup("rdap", "com", "registered", 120*time.Millisecond)
	m.ObserveUpstream("rdap.verisign.com", "200")
	m.ObserveCache("hit")
	m.ObserveCache("miss")
	m.ObserveParse(0.85)
	m.ObserveRateLimited("whois.denic.de", "retry_after")
	m.ObserveAuthFailure("wrong_audience")
	m.SetActiveSessions(3)
	m.SetBreakerOpen("whois.dead.example", true)

	// Every series from design §12 must actually appear, because a metric that
	// is defined but never emitted is indistinguishable from a healthy zero.
	for _, want := range []string{
		"whois_mcp_lookup_duration_seconds",
		"whois_mcp_upstream_requests_total",
		"whois_mcp_cache_hits_total",
		"whois_mcp_parse_confidence",
		"whois_mcp_rate_limited_total",
		"whois_mcp_auth_failures_total",
		"whois_mcp_active_sessions",
		"whois_mcp_breaker_open",
	} {
		if n, err := testutil.GatherAndCount(m.Registry(), want); err != nil || n == 0 {
			t.Errorf("metric %s: count=%d err=%v", want, n, err)
		}
	}

	if got := testutil.ToFloat64(m.ActiveSessions); got != 3 {
		t.Errorf("active_sessions = %v; want 3", got)
	}
	if got := testutil.ToFloat64(m.CacheHits.WithLabelValues("hit")); got != 1 {
		t.Errorf("cache hits = %v; want 1", got)
	}
}

// TestMultipleRegistriesDoNotCollide is why NewMetrics uses its own registry
// rather than the global default: several servers in one test binary would
// otherwise panic on duplicate registration.
func TestMultipleRegistriesDoNotCollide(t *testing.T) {
	a := NewMetrics()
	b := NewMetrics()
	a.ObserveCache("hit")
	b.ObserveCache("hit")
	if a.Registry() == b.Registry() {
		t.Error("two Metrics share one registry")
	}
}

// TestNilMetricsIsSafe lets a caller run without instrumentation rather than
// forcing nil checks at every call site.
func TestNilMetricsIsSafe(t *testing.T) {
	var m *Metrics
	m.ObserveLookup("rdap", "com", "ok", time.Second)
	m.ObserveUpstream("h", "200")
	m.ObserveCache("hit")
	m.ObserveParse(1)
	m.ObserveRateLimited("h", "r")
	m.ObserveAuthFailure("r")
	m.SetActiveSessions(1)
	m.SetBreakerOpen("h", true)
}

// TestSafeTLDBoundsCardinality: a TLD label is bounded by the public suffix
// list, but an unrecognised value must not become a permanent series.
func TestSafeTLDBoundsCardinality(t *testing.T) {
	cases := map[string]string{
		"com":                   "com",
		"COM":                   "com",
		"  uk  ":                "uk",
		"xn--p1ai":              "xn--p1ai",
		"":                      "other",
		"not a tld":             "other",
		"exa/mple":              "other",
		strings.Repeat("a", 40): "other",
	}
	for in, want := range cases {
		if got := safeTLD(in); got != want {
			t.Errorf("safeTLD(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestNoDomainInLabels is the privacy property from §12: a query stream is
// itself sensitive, so no series may carry the domain being looked up.
func TestNoDomainInLabels(t *testing.T) {
	m := NewMetrics()
	m.ObserveLookup("whois", "test", "registered", time.Second)
	m.ObserveUpstream("whois.nic.test", "200")

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if !strings.HasPrefix(f.GetName(), "whois_mcp_") {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "domain" {
					t.Errorf("%s carries a domain label; a query stream must not be in metrics", f.GetName())
				}
			}
		}
	}
}

func TestInitTracingWithoutEndpointIsNoOp(t *testing.T) {
	tr, shutdown, err := InitTracing(context.Background(), TraceOptions{}, nil)
	if err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	if tr == nil {
		t.Fatal("tracer is nil; call sites would need nil checks")
	}
	// The propagator is configured even with no exporter, so an agent's
	// traceparent still flows through to the upstream call.
	ctx, span := UpstreamSpan(context.Background(), tr, "rdap", "rdap.example")
	span.End()
	if ctx == nil {
		t.Error("UpstreamSpan returned a nil context")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestInitTracingRejectsBadEndpoint(t *testing.T) {
	// A malformed endpoint must fail at startup rather than silently dropping
	// every span.
	if _, _, err := InitTracing(context.Background(), TraceOptions{Endpoint: "://not a url"}, nil); err == nil {
		t.Error("InitTracing accepted a malformed endpoint")
	}
}

func TestUpstreamSpanWithNilTracer(t *testing.T) {
	ctx, span := UpstreamSpan(context.Background(), nil, "whois", "h")
	if ctx == nil {
		t.Error("nil context returned")
	}
	span.End() // must not panic
}
