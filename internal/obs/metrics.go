package obs

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics is the instrument set from design §12.
//
// Every series here answers an operational question we will actually be asked.
// Cache hit rate in particular is not a vanity metric: §9 calls it the main
// lever keeping our query volume off registry radar, so a falling hit rate is an
// early warning that we are about to be blocked, not merely that we are slower.
type Metrics struct {
	LookupDuration  *prometheus.HistogramVec
	UpstreamTotal   *prometheus.CounterVec
	CacheHits       *prometheus.CounterVec
	ParseConfidence prometheus.Histogram
	RateLimited     *prometheus.CounterVec
	AuthFailures    *prometheus.CounterVec
	ActiveSessions  prometheus.Gauge
	BreakerOpen     *prometheus.GaugeVec

	reg *prometheus.Registry
}

// NewMetrics builds the instruments against a fresh registry.
//
// A dedicated registry rather than the global default: tests can build several
// without a duplicate-registration panic, and nothing we did not choose ends up
// on our /metrics endpoint.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}

	m.LookupDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "whois_mcp_lookup_duration_seconds",
		Help: "End-to-end lookup duration.",
		// Buckets span a cache hit (sub-millisecond) to the 10s whole-tool
		// ceiling, because the interesting question is which side of that a
		// request fell on.
		Buckets: []float64{0.001, 0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"protocol", "tld", "outcome"})

	m.UpstreamTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "whois_mcp_upstream_requests_total",
		Help: "Requests sent to an upstream registry, by host and status.",
	}, []string{"host", "status"})

	m.CacheHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "whois_mcp_cache_hits_total",
		Help: "Cache lookups by result. Hit rate is the main lever keeping query volume off registry radar.",
	}, []string{"result"})

	m.ParseConfidence = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "whois_mcp_parse_confidence",
		Help:    "Distribution of WHOIS parse confidence. A falling distribution means a registry changed its format.",
		Buckets: []float64{0.1, 0.25, 0.5, 0.7, 0.85, 0.95, 1.0},
	})

	m.RateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "whois_mcp_rate_limited_total",
		Help: "Times we declined to call an upstream because of our own limits or its Retry-After.",
	}, []string{"host", "reason"})

	m.AuthFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "whois_mcp_auth_failures_total",
		Help: "Authentication and authorization failures by reason.",
	}, []string{"reason"})

	m.ActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "whois_mcp_active_sessions",
		Help: "Enrolled sessions that are neither revoked nor expired.",
	})

	m.BreakerOpen = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "whois_mcp_breaker_open",
		Help: "1 when an upstream host's circuit is open.",
	}, []string{"host"})

	reg.MustRegister(
		m.LookupDuration, m.UpstreamTotal, m.CacheHits, m.ParseConfidence,
		m.RateLimited, m.AuthFailures, m.ActiveSessions, m.BreakerOpen,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Registry exposes the collector registry for the /metrics handler.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// ObserveLookup records one completed lookup.
//
// tld is bounded by the number of TLDs, which is ~1,500 — acceptable
// cardinality for a label. The domain deliberately never appears: a query
// stream is itself sensitive (§12), and a per-domain label would put it in
// every scrape.
func (m *Metrics) ObserveLookup(protocol, tld, outcome string, d time.Duration) {
	if m == nil {
		return
	}
	m.LookupDuration.WithLabelValues(protocol, safeTLD(tld), outcome).Observe(d.Seconds())
}

// ObserveUpstream records an upstream call.
func (m *Metrics) ObserveUpstream(host, status string) {
	if m == nil {
		return
	}
	m.UpstreamTotal.WithLabelValues(host, status).Inc()
}

// ObserveCache records a cache lookup: "hit" or "miss".
func (m *Metrics) ObserveCache(result string) {
	if m == nil {
		return
	}
	m.CacheHits.WithLabelValues(result).Inc()
}

// ObserveParse records a WHOIS parse confidence score.
func (m *Metrics) ObserveParse(confidence float64) {
	if m == nil {
		return
	}
	m.ParseConfidence.Observe(confidence)
}

// ObserveRateLimited records a declined upstream call.
func (m *Metrics) ObserveRateLimited(host, reason string) {
	if m == nil {
		return
	}
	m.RateLimited.WithLabelValues(host, reason).Inc()
}

// ObserveAuthFailure records an auth failure by reason.
//
// The reason is a fixed vocabulary, never an error string: error text can carry
// attacker-controlled content, and putting it in a label would let a caller
// mint unbounded series.
func (m *Metrics) ObserveAuthFailure(reason string) {
	if m == nil {
		return
	}
	m.AuthFailures.WithLabelValues(reason).Inc()
}

// SetActiveSessions publishes the current session count.
func (m *Metrics) SetActiveSessions(n int) {
	if m == nil {
		return
	}
	m.ActiveSessions.Set(float64(n))
}

// SetBreakerOpen publishes a host's breaker state.
func (m *Metrics) SetBreakerOpen(host string, open bool) {
	if m == nil {
		return
	}
	v := 0.0
	if open {
		v = 1
	}
	m.BreakerOpen.WithLabelValues(host).Set(v)
}

// safeTLD bounds label cardinality.
//
// A TLD arrives from caller input via the public suffix list, so it is already
// constrained — but an unrecognised or absurd value must not become a permanent
// series. Anything implausible is folded into "other".
func safeTLD(tld string) string {
	t := strings.ToLower(strings.TrimSpace(tld))
	if t == "" || len(t) > 24 {
		return "other"
	}
	for _, r := range t {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return "other"
		}
	}
	return t
}
