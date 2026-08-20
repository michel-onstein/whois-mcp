package cache

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisCache connects to a real Redis, or skips. Opt-in for the same reason as
// the session-store tests: the suite must stay hermetic.
func redisCache(t *testing.T) *Redis {
	t.Helper()
	url := os.Getenv("WHOIS_MCP_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set WHOIS_MCP_TEST_REDIS_URL to run the Redis cache tests")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parsing WHOIS_MCP_TEST_REDIS_URL: %v", err)
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("connecting to redis: %v", err)
	}
	prefix := "test:" + t.Name() + ":" + time.Now().Format("150405.000000000") + ":"
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		iter := client.Scan(ctx, 0, prefix+"*", 0).Iterator()
		for iter.Next(ctx) {
			_ = client.Del(ctx, iter.Val()).Err()
		}
		_ = client.Close()
	})
	return NewRedisWithClient(client, prefix, 3*time.Second)
}

func TestRedisRoundTrip(t *testing.T) {
	c := redisCache(t)
	ctx := context.Background()

	if _, ok := c.Get(ctx, "absent"); ok {
		t.Error("Get reported a hit for an absent key")
	}
	c.Set(ctx, "k", []byte("value"), time.Minute)
	got, ok := c.Get(ctx, "k")
	if !ok || string(got) != "value" {
		t.Fatalf("Get = %q %v", got, ok)
	}
	c.Delete(ctx, "k")
	if _, ok := c.Get(ctx, "k"); ok {
		t.Error("key survived Delete")
	}
}

func TestRedisHonoursTTL(t *testing.T) {
	c := redisCache(t)
	ctx := context.Background()

	c.Set(ctx, "brief", []byte("v"), 300*time.Millisecond)
	if _, ok := c.Get(ctx, "brief"); !ok {
		t.Fatal("value missing immediately after Set")
	}
	time.Sleep(500 * time.Millisecond)
	if _, ok := c.Get(ctx, "brief"); ok {
		t.Error("value outlived its TTL; contact data resting past its TTL is a policy violation, not just a bug")
	}
}

// TestRedisNonPositiveTTLIsNoOp pins the interface contract, and the reason for
// it: storing forever is how a cache of personal data outlives the policy that
// allowed it (design §13).
func TestRedisNonPositiveTTLIsNoOp(t *testing.T) {
	c := redisCache(t)
	ctx := context.Background()

	c.Set(ctx, "zero", []byte("v"), 0)
	if _, ok := c.Get(ctx, "zero"); ok {
		t.Error("a zero TTL stored a value")
	}
	c.Set(ctx, "negative", []byte("v"), -time.Second)
	if _, ok := c.Get(ctx, "negative"); ok {
		t.Error("a negative TTL stored a value")
	}
}

// TestRedisKeysArePrefixed matters for a shared Redis: without a namespace, two
// services would silently read each other's values.
func TestRedisKeysArePrefixed(t *testing.T) {
	c := redisCache(t)
	ctx := context.Background()
	c.Set(ctx, "ns", []byte("v"), time.Minute)

	other := NewRedisWithClient(c.client, "different-prefix:", 3*time.Second)
	if _, ok := other.Get(ctx, "ns"); ok {
		t.Error("a different prefix read our key")
	}
}

// TestRedisAndMemoryAgree runs the same sequence against both implementations,
// because two implementations of one interface that disagree are worse than one.
func TestRedisAndMemoryAgree(t *testing.T) {
	impls := map[string]Cache{
		"memory": NewMemory(),
		"redis":  redisCache(t),
	}
	for name, c := range impls {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if _, ok := c.Get(ctx, "nope"); ok {
				t.Error("hit on an absent key")
			}
			c.Set(ctx, "a", []byte("1"), time.Minute)
			if got, ok := c.Get(ctx, "a"); !ok || string(got) != "1" {
				t.Errorf("Get = %q %v", got, ok)
			}
			c.Set(ctx, "a", []byte("2"), time.Minute)
			if got, _ := c.Get(ctx, "a"); string(got) != "2" {
				t.Errorf("overwrite failed: %q", got)
			}
			c.Delete(ctx, "a")
			if _, ok := c.Get(ctx, "a"); ok {
				t.Error("key survived Delete")
			}
			c.Set(ctx, "z", []byte("v"), 0)
			if _, ok := c.Get(ctx, "z"); ok {
				t.Error("a zero TTL stored a value")
			}
		})
	}
}

func TestRedisPing(t *testing.T) {
	c := redisCache(t)
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

// TestRedisUnreachableDegradesToMiss is the availability property: a broken
// cache must make lookups slower, not make them fail.
func TestRedisUnreachableDegradesToMiss(t *testing.T) {
	// Point at a port nothing listens on rather than skipping: this case needs
	// no working Redis, so it runs everywhere.
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond})
	defer client.Close()
	c := NewRedisWithClient(client, "unreachable:", 200*time.Millisecond)
	ctx := context.Background()

	if _, ok := c.Get(ctx, "k"); ok {
		t.Error("Get reported a hit from an unreachable Redis")
	}
	// Set and Delete must not panic or block either.
	c.Set(ctx, "k", []byte("v"), time.Minute)
	c.Delete(ctx, "k")
	if err := c.Ping(ctx); err == nil {
		t.Error("Ping succeeded against an unreachable Redis; /readyz would lie")
	}
}
