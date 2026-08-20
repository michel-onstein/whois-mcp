package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore is a SessionStore backed by Redis, so sessions and refresh-token
// families are shared across replicas.
//
// Without it, a client that enrolls against replica A cannot refresh against
// replica B, and revoking a session only binds on whichever replica received the
// request. Access tokens still verify locally — that is what keeps replicas
// stateless on the hot path — so this is consulted only for refresh, revocation
// and listing.
type RedisStore struct {
	client  redis.UniversalClient
	prefix  string
	timeout time.Duration
	// ttlSlack keeps a session record alive slightly longer than its refresh
	// window, so an expired-but-recent session can still be *reported* as
	// expired rather than vanishing into "no such session" — which reads to an
	// operator like the session never existed.
	ttlSlack time.Duration
}

// RedisStoreOptions configures the store.
type RedisStoreOptions struct {
	Prefix  string
	Timeout time.Duration
}

// NewRedisStore wraps a Redis client.
func NewRedisStore(client redis.UniversalClient, opt RedisStoreOptions) *RedisStore {
	prefix := opt.Prefix
	if prefix == "" {
		prefix = "whois-mcp:auth:"
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	return &RedisStore{client: client, prefix: prefix, timeout: timeout, ttlSlack: time.Hour}
}

func (s *RedisStore) sessionKey(sid string) string { return s.prefix + "session:" + sid }
func (s *RedisStore) refreshKey(tok string) string { return s.prefix + "refresh:" + tok }
func (s *RedisStore) indexKey() string             { return s.prefix + "sessions" }

// storedRefresh is a refresh-token record.
type storedRefresh struct {
	SID       string    `json:"sid"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

// rotateScript performs the whole rotation in one atomic step.
//
// This has to be a script. The theft detection rests on exactly one of two
// concurrent uses of a token succeeding, and a read-modify-write from Go cannot
// guarantee that across replicas — two processes would both read `used=false`
// and both proceed, which is precisely the case the detection exists to catch.
// Redis executes a script atomically, so the compare-and-set is real.
//
// KEYS[1] old refresh record, KEYS[2] new refresh record, KEYS[3] session record
// ARGV[1] now (RFC3339), ARGV[2] new refresh TTL seconds, ARGV[3] new expiry (RFC3339)
//
// Returns: {code, payload}. code is "ok", "unknown", "reused", "expired",
// "revoked" or "nosession".
const rotateScript = `
local oldRaw = redis.call('GET', KEYS[1])
if not oldRaw then return {'unknown', ''} end
local old = cjson.decode(oldRaw)

local sessRaw = redis.call('GET', KEYS[3])
if not sessRaw then return {'nosession', ''} end
local sess = cjson.decode(sessRaw)

if old.used then
  -- Replay. Revoke the session and report it, so the caller can denylist and
  -- alert. The whole family dies with the session.
  sess.revoked = true
  sess.revoked_at = ARGV[1]
  redis.call('SET', KEYS[3], cjson.encode(sess), 'KEEPTTL')
  return {'reused', cjson.encode(sess)}
end

if sess.revoked then return {'revoked', ''} end

local ttl = tonumber(ARGV[2])
old.used = true
old.used_at = ARGV[1]
-- Keep the spent record so a later replay is still recognisable as a replay
-- rather than as an unknown token; the two mean very different things.
redis.call('SET', KEYS[1], cjson.encode(old), 'EX', ttl)

sess.last_seen = ARGV[1]
sess.expires_at = ARGV[3]
sess.rotations = (sess.rotations or 0) + 1
redis.call('SET', KEYS[3], cjson.encode(sess), 'EX', ttl + 3600)

local newRec = {sid = old.sid, expires_at = ARGV[3], used = false}
redis.call('SET', KEYS[2], cjson.encode(newRec), 'EX', ttl)

return {'ok', cjson.encode(sess)}
`

var rotate = redis.NewScript(rotateScript)

func (s *RedisStore) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.timeout)
}

func (s *RedisStore) Create(ctx context.Context, sess *Session) error {
	if sess == nil || sess.ID == "" {
		return errors.New("session id is required")
	}
	ctx, cancel := s.ctx(ctx)
	defer cancel()

	body, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}
	ttl := time.Until(sess.ExpiresAt) + s.ttlSlack
	if ttl <= 0 {
		return errors.New("session already expired")
	}
	// NX so a replayed enrollment cannot overwrite a live session.
	ok, err := s.client.SetNX(ctx, s.sessionKey(sess.ID), body, ttl).Result()
	if err != nil {
		return fmt.Errorf("storing session: %w", err)
	}
	if !ok {
		return fmt.Errorf("session %s already exists", sess.ID)
	}
	if err := s.client.SAdd(ctx, s.indexKey(), sess.ID).Err(); err != nil {
		return fmt.Errorf("indexing session: %w", err)
	}
	return nil
}

func (s *RedisStore) IssueRefresh(ctx context.Context, sid, token string, now time.Time) error {
	if token == "" {
		return errors.New("refresh token is required")
	}
	ctx, cancel := s.ctx(ctx)
	defer cancel()

	sess, err := s.get(ctx, sid)
	if err != nil {
		return err
	}
	if sess.Revoked {
		return fmt.Errorf("%w: %s", ErrSessionRevoked, sid)
	}
	rec, err := json.Marshal(storedRefresh{SID: sid, ExpiresAt: sess.ExpiresAt})
	if err != nil {
		return fmt.Errorf("encoding refresh record: %w", err)
	}
	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		return ErrRefreshExpired
	}
	ok, err := s.client.SetNX(ctx, s.refreshKey(token), rec, ttl).Result()
	if err != nil {
		return fmt.Errorf("storing refresh token: %w", err)
	}
	if !ok {
		return errors.New("refresh token already issued")
	}
	return nil
}

func (s *RedisStore) Get(ctx context.Context, sid string) (*Session, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()
	return s.get(ctx, sid)
}

func (s *RedisStore) get(ctx context.Context, sid string) (*Session, error) {
	raw, err := s.client.Get(ctx, s.sessionKey(sid)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("%w: %s", ErrNoSession, sid)
	}
	if err != nil {
		return nil, fmt.Errorf("reading session: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, fmt.Errorf("decoding session %s: %w", sid, err)
	}
	return &sess, nil
}

func (s *RedisStore) List(ctx context.Context) ([]*Session, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()

	ids, err := s.client.SMembers(ctx, s.indexKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	out := make([]*Session, 0, len(ids))
	var stale []string
	for _, id := range ids {
		sess, err := s.get(ctx, id)
		if err != nil {
			if errors.Is(err, ErrNoSession) {
				// The record expired out from under the index. Collect it and
				// prune, so the index does not grow forever with ghosts.
				stale = append(stale, id)
				continue
			}
			return nil, err
		}
		out = append(out, sess)
	}
	if len(stale) > 0 {
		args := make([]any, len(stale))
		for i, id := range stale {
			args[i] = id
		}
		_ = s.client.SRem(ctx, s.indexKey(), args...).Err()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *RedisStore) Rotate(ctx context.Context, oldToken, newToken string, now time.Time) (*Session, error) {
	ctx, cancel := s.ctx(ctx)
	defer cancel()

	// The session id is inside the old record, which the script reads — but the
	// script needs the session key up front, so resolve it first. A concurrent
	// rotation cannot change which session a token belongs to, so this read is
	// safe to do outside the atomic step.
	raw, err := s.client.Get(ctx, s.refreshKey(oldToken)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrRefreshUnknown
	}
	if err != nil {
		return nil, fmt.Errorf("reading refresh token: %w", err)
	}
	var rec storedRefresh
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("decoding refresh record: %w", err)
	}
	if !rec.Used && now.After(rec.ExpiresAt) {
		return nil, fmt.Errorf("%w at %s", ErrRefreshExpired, rec.ExpiresAt.Format(time.RFC3339))
	}

	newExpiry := now.UTC().Add(RefreshTTL)
	res, err := rotate.Run(ctx, s.client,
		[]string{s.refreshKey(oldToken), s.refreshKey(newToken), s.sessionKey(rec.SID)},
		now.UTC().Format(time.RFC3339Nano),
		int(RefreshTTL.Seconds()),
		newExpiry.Format(time.RFC3339Nano),
	).Slice()
	if err != nil {
		return nil, fmt.Errorf("rotating refresh token: %w", err)
	}
	if len(res) != 2 {
		return nil, fmt.Errorf("rotate script returned %d values; want 2", len(res))
	}
	code, _ := res[0].(string)
	payload, _ := res[1].(string)

	switch code {
	case "ok":
		var sess Session
		if err := json.Unmarshal([]byte(payload), &sess); err != nil {
			return nil, fmt.Errorf("decoding rotated session: %w", err)
		}
		return &sess, nil
	case "reused":
		sid := rec.SID
		if payload != "" {
			var sess Session
			if json.Unmarshal([]byte(payload), &sess) == nil && sess.ID != "" {
				sid = sess.ID
			}
		}
		return nil, &ReuseError{SID: sid}
	case "expired":
		return nil, ErrRefreshExpired
	case "revoked":
		return nil, fmt.Errorf("%w: %s", ErrSessionRevoked, rec.SID)
	case "nosession":
		return nil, fmt.Errorf("%w: %s", ErrNoSession, rec.SID)
	default:
		return nil, ErrRefreshUnknown
	}
}

func (s *RedisStore) Revoke(ctx context.Context, sid string, now time.Time) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()

	sess, err := s.get(ctx, sid)
	if err != nil {
		return err
	}
	sess.Revoked = true
	sess.RevokedAt = now.UTC()
	body, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}
	// KEEPTTL so revoking does not extend the record's life, and does not cut it
	// short either — session_list should still show it as revoked.
	if err := s.client.Set(ctx, s.sessionKey(sid), body, redis.KeepTTL).Err(); err != nil {
		return fmt.Errorf("revoking session: %w", err)
	}
	return nil
}

func (s *RedisStore) Touch(ctx context.Context, sid string, now time.Time) error {
	ctx, cancel := s.ctx(ctx)
	defer cancel()

	sess, err := s.get(ctx, sid)
	if err != nil {
		return err
	}
	sess.LastSeen = now.UTC()
	body, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("encoding session: %w", err)
	}
	return s.client.Set(ctx, s.sessionKey(sid), body, redis.KeepTTL).Err()
}

// ActiveCount reports sessions that are neither revoked nor expired, for the
// whois_mcp_active_sessions gauge.
func (s *RedisStore) ActiveCount(ctx context.Context, now time.Time) (int, error) {
	sessions, err := s.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, sess := range sessions {
		if sess.Active(now) {
			n++
		}
	}
	return n, nil
}

var _ SessionStore = (*RedisStore)(nil)
