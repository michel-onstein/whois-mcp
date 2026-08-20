package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/qjam/whois-mcp/internal/auth"
	"github.com/qjam/whois-mcp/internal/cache"
)

// storeConfig selects the cache and session-store backends (design §10).
type storeConfig struct {
	// cacheKind is "memory" or "redis".
	cacheKind string
	// sessionKind is "memory" or "redis".
	sessionKind string
	redisURL    string
}

func loadStoreConfig() storeConfig {
	return storeConfig{
		cacheKind:   strings.ToLower(env("WHOIS_MCP_CACHE", "memory")),
		sessionKind: strings.ToLower(env("WHOIS_MCP_SESSION_STORE", "memory")),
		redisURL:    strings.TrimSpace(env("WHOIS_MCP_REDIS_URL", "")),
	}
}

// stores is what the rest of the process needs, plus the readiness check.
type stores struct {
	cache    cache.Cache
	sessions auth.SessionStore
	// ready reports whether the backing store is reachable, for /readyz. It is
	// nil for in-memory backends, which cannot be unreachable.
	ready func(context.Context) error
	close func() error
	// description is for the startup log, so an operator can see at a glance
	// which backends are live rather than inferring it from behaviour.
	description string
}

// buildStores wires the cache and session store.
//
// A Redis backend that cannot be reached is a startup failure rather than a
// warning. The alternative — silently falling back to in-memory — is the worst
// outcome available: a multi-replica deployment would appear healthy while every
// replica held its own sessions, so a client that enrolled against one replica
// would be mysteriously logged out by the load balancer.
func buildStores(ctx context.Context, cfg storeConfig, log *slog.Logger) (*stores, error) {
	needsRedis := cfg.cacheKind == "redis" || cfg.sessionKind == "redis"
	if !needsRedis {
		return &stores{
			cache:       cache.NewMemory(),
			sessions:    auth.NewMemoryStore(),
			close:       func() error { return nil },
			description: "cache=memory sessions=memory",
		}, nil
	}
	if cfg.redisURL == "" {
		return nil, errors.New("WHOIS_MCP_REDIS_URL is required when cache or session store is redis")
	}

	parsed, err := redis.ParseURL(cfg.redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing WHOIS_MCP_REDIS_URL: %w", err)
	}
	client := redis.NewClient(parsed)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connecting to redis: %w", err)
	}

	out := &stores{close: client.Close}

	rc := cache.NewRedisWithClient(client, "whois-mcp:", 250*time.Millisecond)
	if cfg.cacheKind == "redis" {
		out.cache = rc
	} else {
		out.cache = cache.NewMemory()
	}
	if cfg.sessionKind == "redis" {
		out.sessions = auth.NewRedisStore(client, auth.RedisStoreOptions{})
	} else {
		out.sessions = auth.NewMemoryStore()
	}
	// Readiness is gated on the store actually answering, because a replica that
	// cannot reach Redis cannot serve a refresh or honour a revocation, and
	// should be taken out of rotation rather than left to fail requests.
	out.ready = rc.Ping
	out.description = fmt.Sprintf("cache=%s sessions=%s redis=reachable", cfg.cacheKind, cfg.sessionKind)

	log.Info("redis backends connected", "cache", cfg.cacheKind, "sessions", cfg.sessionKind)
	return out, nil
}

// activeSessions reports the live session count for the metrics gauge, or -1
// when the store cannot answer cheaply.
func (s *stores) activeSessions(ctx context.Context, now time.Time) int {
	switch st := s.sessions.(type) {
	case *auth.RedisStore:
		n, err := st.ActiveCount(ctx, now)
		if err != nil {
			return -1
		}
		return n
	case *auth.MemoryStore:
		sessions, err := st.List(ctx)
		if err != nil {
			return -1
		}
		n := 0
		for _, sess := range sessions {
			if sess.Active(now) {
				n++
			}
		}
		return n
	default:
		return -1
	}
}
