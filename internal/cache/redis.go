package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a Cache backed by Redis, so replicas share warmth and upstreams see
// one logical client rather than N.
//
// That second property is the operational point. Design §9 makes cache hit rate
// the main lever keeping our query volume off registry radar, and with per-replica
// caches a three-replica deployment triples the traffic a registry sees for the
// same user demand.
type Redis struct {
	client redis.UniversalClient
	// prefix namespaces our keys so a shared Redis is safe to use.
	prefix string
	// timeout bounds every operation. A cache that blocks is worse than a cache
	// that misses: the whole point is to be faster than the upstream.
	timeout time.Duration
}

// RedisOptions configures the client.
type RedisOptions struct {
	// URL is a redis:// or rediss:// DSN.
	URL string
	// Prefix namespaces keys. Empty uses "whois-mcp:".
	Prefix string
	// Timeout bounds each operation. Zero uses 250ms.
	Timeout time.Duration
}

// NewRedis connects to Redis and verifies the connection.
//
// It pings before returning, because a cache misconfiguration that surfaces as
// slow lookups an hour later is much harder to diagnose than one that refuses to
// start.
func NewRedis(ctx context.Context, opt RedisOptions) (*Redis, error) {
	if opt.URL == "" {
		return nil, errors.New("redis URL is required")
	}
	parsed, err := redis.ParseURL(opt.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}
	prefix := opt.Prefix
	if prefix == "" {
		prefix = "whois-mcp:"
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}

	client := redis.NewClient(parsed)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connecting to redis: %w", err)
	}
	return &Redis{client: client, prefix: prefix, timeout: timeout}, nil
}

// NewRedisWithClient wraps an existing client, for tests and for a caller that
// wants its own connection settings.
func NewRedisWithClient(client redis.UniversalClient, prefix string, timeout time.Duration) *Redis {
	if prefix == "" {
		prefix = "whois-mcp:"
	}
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	return &Redis{client: client, prefix: prefix, timeout: timeout}
}

// Close releases the connection pool.
func (r *Redis) Close() error { return r.client.Close() }

func (r *Redis) key(k string) string { return r.prefix + k }

// Get returns a value if present and unexpired.
//
// A Redis failure is reported as a miss rather than an error, because the Cache
// interface has no error to return and because that is the correct behaviour
// anyway: a broken cache should degrade to querying upstream, not to failing
// every lookup.
func (r *Redis) Get(ctx context.Context, k string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	b, err := r.client.Get(ctx, r.key(k)).Bytes()
	if err != nil {
		return nil, false
	}
	return b, true
}

// Set stores a value with a TTL. A non-positive TTL is a no-op, matching the
// interface contract — and deliberately not "store forever", which is how a
// cache of personal data outlives the policy that allowed it (§13).
func (r *Redis) Set(ctx context.Context, k string, val []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	_ = r.client.Set(ctx, r.key(k), val, ttl).Err()
}

// Delete removes a key.
func (r *Redis) Delete(ctx context.Context, k string) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	_ = r.client.Del(ctx, r.key(k)).Err()
}

// Ping reports whether Redis is reachable, for /readyz.
func (r *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.client.Ping(ctx).Err()
}

// Compile-time proof that Redis satisfies the interface the resolver uses.
var _ Cache = (*Redis)(nil)
