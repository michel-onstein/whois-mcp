// Command whois-mcp serves domain registration lookups over the Model Context
// Protocol. See docs/MCP_DESIGN.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/qjam/whois-mcp/internal/mcpsrv"
	"github.com/qjam/whois-mcp/internal/obs"
	"github.com/qjam/whois-mcp/internal/ratelimit"
	"github.com/qjam/whois-mcp/internal/rdapx"
	"github.com/qjam/whois-mcp/internal/resolve"
	"github.com/qjam/whois-mcp/internal/whois"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	listen       string
	logLevel     string
	bootstrapURL string
	otelEndpoint string
}

func loadConfig() config {
	return config{
		listen:       env("WHOIS_MCP_LISTEN", "127.0.0.1:8080"),
		logLevel:     env("WHOIS_MCP_LOG_LEVEL", "info"),
		bootstrapURL: env("WHOIS_MCP_RDAP_BOOTSTRAP_URL", rdapx.BootstrapURL),
		otelEndpoint: env("WHOIS_MCP_OTEL_ENDPOINT", ""),
	}
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func run() error {
	cfg := loadConfig()
	log := obs.NewLogger(cfg.logLevel)

	// Security gate (docs/IMPLEMENTATION_PLAN.md §7), now scope-aware: an
	// authenticated instance may bind off-host, an unauthenticated one may not.
	// Refuse rather than warn — the failure mode is an IP block that reads as a
	// total outage for a TLD.
	acfg := loadAuthConfig()
	if err := checkExposure(cfg, acfg); err != nil {
		return err
	}

	reg, err := rdapx.NewRegistry()
	if err != nil {
		return fmt.Errorf("loading RDAP bootstrap: %w", err)
	}
	log.Info("bootstrap registry loaded from embedded snapshot",
		"tlds", reg.Count(), "published", reg.Publication().Format(time.RFC3339))

	// One upstream policy shared by both protocols, keyed by host: several TLDs
	// resolve to the same registry endpoint, and separate policies per protocol
	// would let two "polite" streams add up to one impolite one.
	guard := ratelimit.NewGuard(
		ratelimit.New(ratelimit.Options{}),
		ratelimit.NewBreaker(ratelimit.BreakerOptions{}),
	)

	netReg, err := rdapx.NewNetRegistry()
	if err != nil {
		return fmt.Errorf("loading IP/ASN bootstrap: %w", err)
	}
	v4, v6, asn := netReg.Counts()
	log.Info("IP/ASN bootstrap loaded from embedded snapshot",
		"ipv4_prefixes", v4, "ipv6_prefixes", v6, "asn_ranges", asn,
		"published", netReg.Publication().Format(time.RFC3339))

	hc := rdapx.NewHTTPClient(rdapx.DefaultTimeout)
	rc := rdapx.NewClient(reg, hc, rdapx.DefaultUserAgent(mcpsrv.Version)).WithGuard(guard)

	// One cache backs both protocols and the WHOIS host map; Redis slots in
	// behind the same interface (design §9-§10).
	backends, err := buildStores(context.Background(), loadStoreConfig(), log)
	if err != nil {
		return err
	}
	defer func() { _ = backends.close() }()
	store := backends.cache
	wc := whois.NewClient(whois.NewTransport(whois.DefaultTimeout).WithGuard(guard), store, log)
	res := resolve.New(rc, wc, store, log).WithNetRegistry(netReg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Refresh the bootstrap map in the background. A failure is logged and
	// tolerated: the embedded snapshot keeps the server useful.
	go refreshBootstrap(ctx, reg, hc, cfg.bootstrapURL, log)
	go refreshNetBootstrap(ctx, netReg, hc, log)

	metrics := obs.NewMetrics()
	tracer, shutdownTracing, err := obs.InitTracing(ctx, obs.TraceOptions{
		Endpoint:       cfg.otelEndpoint,
		ServiceName:    "whois-mcp",
		ServiceVersion: mcpsrv.Version,
	}, log)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			log.Warn("flushing traces", "error", err)
		}
	}()
	_ = tracer // spans are attached at the upstream call sites

	// Keep the breaker and session gauges current. Cheap, and it is what turns
	// "something is wrong" into "this registry is down" on a dashboard.
	go publishGauges(ctx, metrics, guard, backends)

	stack, err := buildAuth(cfg, acfg, store, backends.sessions, log)
	if err != nil {
		return err
	}

	mopt := mcpsrv.Options{Resolver: res, Registry: reg, Log: log, NetLookups: true}
	if stack != nil {
		mopt.Auth = mcpsrv.AuthOptions{Sessions: stack.sessions, Denylist: stack.denylist}
		mopt.EnforceScopes = true
	}
	server := mcpsrv.New(mopt)
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{
			// The 2026-07-28 revision is the sole design target: no protocol
			// sessions, no Mcp-Session-Id. Any replica can serve any request.
			Stateless: true,
			Logger:    log,
		},
	)

	mux := http.NewServeMux()
	if stack != nil {
		// Authenticated: the bearer middleware runs first so the scope gate can
		// read the token's scopes out of the request context, and the OAuth
		// endpoints are registered unprotected because they are how a client
		// obtains a token in the first place.
		mux.Handle("/mcp", stack.protect(handler))
		stack.server.Routes(mux)
	} else {
		mux.Handle("/mcp", handler)
	}
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry(),
		promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})
	// /readyz is gated on everything a replica needs in order to answer, so a
	// replica that cannot is taken out of rotation rather than left to fail
	// requests: the bootstrap map, the cache backend, and — per plan task 3.1 —
	// the assertion that we are not serving unauthenticated off-host.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if reg.Count() == 0 {
			http.Error(w, "not ready: bootstrap registry empty", http.StatusServiceUnavailable)
			return
		}
		if stack == nil && requireLoopback(cfg.listen) != nil {
			// Defence in depth. checkExposure already refuses to start in this
			// state, so reaching here means something bypassed it — and a
			// replica in this state must not receive traffic.
			http.Error(w, "not ready: no authentication configured on a non-loopback listener",
				http.StatusServiceUnavailable)
			return
		}
		if backends.ready != nil {
			checkCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := backends.ready(checkCtx); err != nil {
				http.Error(w, "not ready: cache backend unreachable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ready")
	})

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		authState := "NONE - loopback only"
		if stack != nil {
			authState = "OAuth 2.1, issuer " + stack.issuer.IssuerURL()
			if stack.staticTok != "" {
				authState += " (WHOIS_MCP_DEV_STATIC_BEARER enabled)"
			}
		}
		log.Info("listening", "addr", cfg.listen, "mcp", "POST http://"+cfg.listen+"/mcp",
			"auth", authState)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// requireLoopback rejects any listen address that is reachable off-host.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parsing WHOIS_MCP_LISTEN %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("WHOIS_MCP_LISTEN %q binds all interfaces; authentication is not implemented until M2, so only loopback is permitted", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("WHOIS_MCP_LISTEN %q is not a loopback address; authentication is not implemented until M2, so only loopback is permitted", addr)
	}
	return nil
}

func refreshBootstrap(ctx context.Context, reg *rdapx.Registry, hc *http.Client, url string, log *slog.Logger) {
	do := func() {
		rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := reg.Refresh(rctx, hc, url); err != nil {
			log.Warn("bootstrap refresh failed; continuing with existing data",
				"error", err, "tlds", reg.Count(), "from_network", reg.FromNetwork())
			return
		}
		log.Info("bootstrap registry refreshed",
			"tlds", reg.Count(), "published", reg.Publication().Format(time.RFC3339))
	}
	do()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			do()
		}
	}
}

// nowPlusHour is the expiry stamped on a development static-bearer session. The
// SDK middleware rejects a TokenInfo with no expiration, and an hour is long
// enough for a debugging session without being indefinite.
func nowPlusHour() time.Time {
	return time.Now().Add(time.Hour)
}

// publishGauges keeps the breaker and session gauges current.
//
// Counters and histograms are updated where the work happens; these two are
// state rather than events, so they need a poller. The interval is short enough
// that a dashboard shows a registry going down within a scrape or two.
func publishGauges(ctx context.Context, m *obs.Metrics, guard *ratelimit.Guard, backends *stores) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()

	// Hosts that have ever been open, so a recovered host is published as 0
	// rather than silently disappearing from the series — a vanished series
	// looks like a scrape failure, not a recovery.
	known := make(map[string]bool)

	publish := func() {
		open := guard.OpenHosts()
		nowOpen := make(map[string]bool, len(open))
		for _, host := range open {
			nowOpen[host] = true
			known[host] = true
			m.SetBreakerOpen(host, true)
		}
		for host := range known {
			if !nowOpen[host] {
				m.SetBreakerOpen(host, false)
			}
		}
		if n := backends.activeSessions(ctx, time.Now().UTC()); n >= 0 {
			m.SetActiveSessions(n)
		}
	}
	publish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			publish()
		}
	}
}

// refreshNetBootstrap keeps the IP and ASN maps current.
//
// Separate from the domain refresh because it fetches three files rather than
// one and tolerates partial success: a failure on any single file leaves that
// family's previous data in place, since stale bootstrap data is far better than
// none.
func refreshNetBootstrap(ctx context.Context, reg *rdapx.NetRegistry, hc *http.Client, log *slog.Logger) {
	do := func() {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := reg.Refresh(rctx, hc, rdapx.BootstrapIPv4URL, rdapx.BootstrapIPv6URL, rdapx.BootstrapASNURL); err != nil {
			v4, v6, asn := reg.Counts()
			log.Warn("IP/ASN bootstrap refresh incomplete; continuing with existing data",
				"error", err, "ipv4_prefixes", v4, "ipv6_prefixes", v6, "asn_ranges", asn)
			return
		}
		v4, v6, asn := reg.Counts()
		log.Info("IP/ASN bootstrap refreshed",
			"ipv4_prefixes", v4, "ipv6_prefixes", v6, "asn_ranges", asn,
			"published", reg.Publication().Format(time.RFC3339))
	}
	do()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			do()
		}
	}
}
