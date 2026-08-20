package auth

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisStore connects to a real Redis, or skips.
//
// Opt-in by env var rather than always-on: the suite must stay hermetic (no test
// may require the network), and a developer without Redis should still be able
// to run everything else. `make test-redis` and the compose stack set it.
func redisStore(t *testing.T) *RedisStore {
	t.Helper()
	url := os.Getenv("WHOIS_MCP_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set WHOIS_MCP_TEST_REDIS_URL to run the Redis session-store tests")
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
	t.Cleanup(func() { _ = client.Close() })

	// A per-test prefix keeps parallel runs and reruns from colliding, and means
	// no test has to flush a database it does not own.
	prefix := "test:" + t.Name() + ":" + time.Now().Format("150405.000000000") + ":"
	store := NewRedisStore(client, RedisStoreOptions{Prefix: prefix, Timeout: 3 * time.Second})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		iter := client.Scan(ctx, 0, prefix+"*", 0).Iterator()
		for iter.Next(ctx) {
			_ = client.Del(ctx, iter.Val()).Err()
		}
	})
	return store
}

func TestRedisCreateGetList(t *testing.T) {
	st := redisStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	sess, rt := newSession(t, now)
	if err := st.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.IssueRefresh(ctx, sess.ID, rt, now); err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}

	got, err := st.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != sess.ID || got.Label != sess.Label {
		t.Errorf("got %+v", got)
	}
	if !got.Active(now) {
		t.Error("fresh session is not active")
	}

	// Creating the same session twice must fail, or a replayed enrollment could
	// overwrite a live session.
	if err := st.Create(ctx, sess); err == nil {
		t.Error("creating an existing session succeeded")
	}
	if _, err := st.Get(ctx, "sess_nope"); !errors.Is(err, ErrNoSession) {
		t.Errorf("Get(unknown) = %v; want ErrNoSession", err)
	}

	list, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != sess.ID {
		t.Errorf("List = %+v", list)
	}
}

func TestRedisRotateSlidesWindow(t *testing.T) {
	st := redisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	sess, rt1 := newSession(t, now)
	if err := st.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.IssueRefresh(ctx, sess.ID, rt1, now); err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}

	later := now.Add(time.Hour)
	rt2, _ := NewRefreshToken()
	rotated, err := st.Rotate(ctx, rt1, rt2, later)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.Rotations != 1 {
		t.Errorf("Rotations = %d; want 1", rotated.Rotations)
	}
	if got := rotated.ExpiresAt.Sub(later); got < RefreshTTL-time.Minute || got > RefreshTTL+time.Minute {
		t.Errorf("expiry moved by %v; want ~%v from the rotation", got, RefreshTTL)
	}
	// The successor works and the predecessor does not.
	rt3, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt2, rt3, later); err != nil {
		t.Fatalf("rotating the successor: %v", err)
	}
}

// TestRedisRotateReuseRevokesFamily is the property the Lua script exists for.
func TestRedisRotateReuseRevokesFamily(t *testing.T) {
	st := redisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	sess, rt1 := newSession(t, now)
	if err := st.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.IssueRefresh(ctx, sess.ID, rt1, now); err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}
	rt2, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt1, rt2, now); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	stolen, _ := NewRefreshToken()
	_, err := st.Rotate(ctx, rt1, stolen, now)
	var reuse *ReuseError
	if !errors.As(err, &reuse) {
		t.Fatalf("replay = %v; want *ReuseError", err)
	}
	if reuse.SID != sess.ID {
		t.Errorf("ReuseError.SID = %q; want %q", reuse.SID, sess.ID)
	}

	got, err := st.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Revoked {
		t.Error("session not revoked after replay")
	}
	// The current token is dead too.
	rt3, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt2, rt3, now); err == nil {
		t.Error("the current token still works after the family was revoked")
	}
}

// TestRedisRotateIsAtomic is the whole reason rotation is a Lua script: a
// read-modify-write from Go would let two replicas both observe used=false.
func TestRedisRotateIsAtomic(t *testing.T) {
	st := redisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	sess, rt1 := newSession(t, now)
	if err := st.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.IssueRefresh(ctx, sess.ID, rt1, now); err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}

	const racers = 12
	var wg sync.WaitGroup
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			next, _ := NewRefreshToken()
			<-start
			_, errs[i] = st.Rotate(ctx, rt1, next, now)
		}(i)
	}
	close(start)
	wg.Wait()

	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("%d of %d concurrent rotations succeeded; want exactly 1", successes, racers)
	}
}

func TestRedisRevokeAndTouch(t *testing.T) {
	st := redisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	sess, rt := newSession(t, now)
	if err := st.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.IssueRefresh(ctx, sess.ID, rt, now); err != nil {
		t.Fatalf("IssueRefresh: %v", err)
	}

	later := now.Add(time.Minute)
	if err := st.Touch(ctx, sess.ID, later); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, _ := st.Get(ctx, sess.ID)
	if got.LastSeen.Before(later.Add(-time.Second)) {
		t.Errorf("LastSeen = %s; want ~%s", got.LastSeen, later)
	}

	if err := st.Revoke(ctx, sess.ID, later); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ = st.Get(ctx, sess.ID)
	if !got.Revoked {
		t.Error("session not marked revoked")
	}
	// A revoked session must still be visible to session_list, so an operator
	// can see what happened rather than finding it vanished.
	list, err := st.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d; want the revoked session still listed", len(list))
	}
	next, _ := NewRefreshToken()
	if _, err := st.Rotate(ctx, rt, next, later); err == nil {
		t.Error("refresh works after revocation")
	}
	if err := st.Revoke(ctx, "sess_nope", later); !errors.Is(err, ErrNoSession) {
		t.Errorf("Revoke(unknown) = %v; want ErrNoSession", err)
	}
}

func TestRedisActiveCount(t *testing.T) {
	st := redisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for range 3 {
		s, rt := newSession(t, now)
		if err := st.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := st.IssueRefresh(ctx, s.ID, rt, now); err != nil {
			t.Fatalf("IssueRefresh: %v", err)
		}
	}
	n, err := st.ActiveCount(ctx, now)
	if err != nil {
		t.Fatalf("ActiveCount: %v", err)
	}
	if n != 3 {
		t.Errorf("ActiveCount = %d; want 3", n)
	}

	// Revoking one drops the count, which is what the gauge should show.
	list, _ := st.List(ctx)
	if err := st.Revoke(ctx, list[0].ID, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	n, _ = st.ActiveCount(ctx, now)
	if n != 2 {
		t.Errorf("ActiveCount after one revocation = %d; want 2", n)
	}
}

func TestRedisRotateUnknownToken(t *testing.T) {
	st := redisStore(t)
	next, _ := NewRefreshToken()
	if _, err := st.Rotate(context.Background(), "never-issued", next, time.Now()); !errors.Is(err, ErrRefreshUnknown) {
		t.Errorf("err = %v; want ErrRefreshUnknown", err)
	}
}

// TestRedisAndMemoryStoresAgree runs the same sequence against both, because two
// implementations of one interface that disagree are worse than one.
func TestRedisAndMemoryStoresAgree(t *testing.T) {
	stores := map[string]SessionStore{
		"memory": NewMemoryStore(),
		"redis":  redisStore(t), // skips the whole test if Redis is absent
	}
	for name, st := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			sess, rt := newSession(t, now)

			if err := st.Create(ctx, sess); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if err := st.IssueRefresh(ctx, sess.ID, rt, now); err != nil {
				t.Fatalf("IssueRefresh: %v", err)
			}
			rt2, _ := NewRefreshToken()
			if _, err := st.Rotate(ctx, rt, rt2, now); err != nil {
				t.Fatalf("Rotate: %v", err)
			}
			// Replay of the spent token is a ReuseError naming the session.
			stolen, _ := NewRefreshToken()
			var reuse *ReuseError
			if err := mustRotateErr(st, ctx, rt, stolen, now); !errors.As(err, &reuse) {
				t.Fatalf("replay = %v; want *ReuseError", err)
			} else if reuse.SID != sess.ID {
				t.Errorf("ReuseError.SID = %q; want %q", reuse.SID, sess.ID)
			}
			got, err := st.Get(ctx, sess.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if !got.Revoked {
				t.Error("session not revoked after replay")
			}
		})
	}
}

func mustRotateErr(st SessionStore, ctx context.Context, oldTok, newTok string, now time.Time) error {
	_, err := st.Rotate(ctx, oldTok, newTok, now)
	return err
}
