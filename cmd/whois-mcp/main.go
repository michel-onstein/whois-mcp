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

	"github.com/qjam/whois-mcp/internal/cache"
	"github.com/qjam/whois-mcp/internal/mcpsrv"
	"github.com/qjam/whois-mcp/internal/obs"
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
}

func loadConfig() config {
	return config{
		listen:       env("WHOIS_MCP_LISTEN", "127.0.0.1:8080"),
		logLevel:     env("WHOIS_MCP_LOG_LEVEL", "info"),
		bootstrapURL: env("WHOIS_MCP_RDAP_BOOTSTRAP_URL", rdapx.BootstrapURL),
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

	// Security gate (docs/IMPLEMENTATION_PLAN.md §7). M0 and M1 have no
	// authentication, so a non-loopback bind would publish an open proxy that
	// queries registries from our egress IP. Refuse rather than warn: the
	// failure mode is an IP block that reads as a total outage for a TLD.
	if err := requireLoopback(cfg.listen); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	reg, err := rdapx.NewRegistry()
	if err != nil {
		return fmt.Errorf("loading RDAP bootstrap: %w", err)
	}
	log.Info("bootstrap registry loaded from embedded snapshot",
		"tlds", reg.Count(), "published", reg.Publication().Format(time.RFC3339))

	hc := rdapx.NewHTTPClient(rdapx.DefaultTimeout)
	rc := rdapx.NewClient(reg, hc, rdapx.DefaultUserAgent(mcpsrv.Version))

	// One cache backs both protocols and the WHOIS host map; M3 swaps in Redis
	// behind the same interface.
	store := cache.NewMemory()
	wc := whois.NewClient(whois.NewTransport(whois.DefaultTimeout), store, log)
	res := resolve.New(rc, wc, store, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Refresh the bootstrap map in the background. A failure is logged and
	// tolerated: the embedded snapshot keeps the server useful.
	go refreshBootstrap(ctx, reg, hc, cfg.bootstrapURL, log)

	server := mcpsrv.New(mcpsrv.Options{Resolver: res, Registry: reg, Log: log})
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
	mux.Handle("/mcp", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if reg.Count() == 0 {
			http.Error(w, "bootstrap registry empty", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ready")
	})

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.listen, "mcp", "POST http://"+cfg.listen+"/mcp",
			"auth", "NONE - M0/M1 loopback only")
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
