package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryGetSetDelete(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()

	if _, ok := c.Get(ctx, "missing"); ok {
		t.Fatal("expected miss on empty cache")
	}

	c.Set(ctx, "k", []byte("v"), time.Minute)
	got, ok := c.Get(ctx, "k")
	if !ok || string(got) != "v" {
		t.Fatalf("got %q, %v; want \"v\", true", got, ok)
	}

	c.Delete(ctx, "k")
	if _, ok := c.Get(ctx, "k"); ok {
		t.Fatal("expected miss after delete")
	}
}

func TestMemoryExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	c := NewMemory()
	c.now = func() time.Time { return now }

	c.Set(ctx, "k", []byte("v"), 30*time.Second)
	if _, ok := c.Get(ctx, "k"); !ok {
		t.Fatal("expected hit before expiry")
	}

	now = now.Add(31 * time.Second)
	if _, ok := c.Get(ctx, "k"); ok {
		t.Fatal("expected miss after expiry")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry should be evicted lazily on read; len=%d", c.Len())
	}
}

func TestMemoryNonPositiveTTLIsNoOp(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()
	c.Set(ctx, "k", []byte("v"), 0)
	if _, ok := c.Get(ctx, "k"); ok {
		t.Fatal("ttl<=0 must not store")
	}
}

func TestMemorySweep(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	c := NewMemory()
	c.now = func() time.Time { return now }

	c.Set(ctx, "short", []byte("a"), time.Second)
	c.Set(ctx, "long", []byte("b"), time.Hour)
	now = now.Add(2 * time.Second)

	c.Sweep()
	if c.Len() != 1 {
		t.Fatalf("len=%d; want 1 after sweep", c.Len())
	}
	if _, ok := c.Get(ctx, "long"); !ok {
		t.Fatal("unexpired entry was swept")
	}
}

func TestMemoryConcurrent(t *testing.T) {
	ctx := context.Background()
	c := NewMemory()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				c.Set(ctx, "k", []byte("v"), time.Minute)
				c.Get(ctx, "k")
				c.Delete(ctx, "k")
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
