#!/usr/bin/env bash
# End-to-end check against a running compose stack (plan task 3.10).
#
# What this proves that no unit test can: two replicas sharing one Redis behave
# as one server. A session enrolled against replica A must refresh against
# replica B, and that only works if the session store is shared and the signing
# key is identical. With per-replica memory stores the flow breaks silently —
# the client simply gets a 401 from whichever replica the load balancer picked.
set -euo pipefail

A="${A:-http://localhost:8080}"
B="${B:-http://localhost:8081}"
TOKEN="${WHOIS_MCP_ENROLLMENT_TOKEN:?WHOIS_MCP_ENROLLMENT_TOKEN must be set}"

# A fixed PKCE pair. Fine for a test: the verifier is not a secret here, and
# hard-coding it keeps the script readable.
VERIFIER="e2e-verifier-0123456789012345678901234567890123456"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=\n')"
REDIRECT="http://127.0.0.1:9/cb"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

echo "== metadata discovery =="
curl -fsS "$A/.well-known/oauth-protected-resource" | grep -q '"resource"' \
  || fail "protected resource metadata missing"
curl -fsS "$A/.well-known/oauth-authorization-server" | grep -q '"token_endpoint"' \
  || fail "authorization server metadata missing"
curl -fsS "$A/.well-known/jwks.json" | grep -q '"EdDSA"' \
  || fail "JWKS missing or not EdDSA"
pass "metadata documents served"

echo "== unauthenticated /mcp is refused =="
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$A/mcp" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
[ "$code" = "401" ] || fail "unauthenticated /mcp returned $code, want 401"
pass "unauthenticated request refused"

echo "== enrollment against replica A =="
location="$(curl -sS -o /dev/null -D - -X POST "$A/oauth/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=e2e" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "scope=whois:read" \
  --data-urlencode "enrollment_token=$TOKEN" \
  --data-urlencode "label=e2e" \
  | tr -d '\r' | awk '/^[Ll]ocation:/ {print $2}')"
[ -n "$location" ] || fail "no redirect from the authorize endpoint"
code_param="$(printf '%s' "$location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[ -n "$code_param" ] || fail "no authorization code in $location"
printf '%s' "$location" | grep -q 'iss=' || fail "no iss in the redirect (RFC 9207)"
pass "enrolled, code issued with iss"

echo "== code exchange against replica A =="
tokens="$(curl -fsS -X POST "$A/oauth/token" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$code_param" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "client_id=e2e")"
access="$(printf '%s' "$tokens" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
refresh="$(printf '%s' "$tokens" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')"
[ -n "$access" ] || fail "no access token in $tokens"
[ -n "$refresh" ] || fail "no refresh token"
pass "tokens issued"

echo "== the token works on replica B (shared signing key) =="
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/mcp" \
  -H "Authorization: Bearer $access" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"
[ "$code" = "200" ] || fail "replica B rejected replica A's token ($code); the signing key is not shared"
pass "replica B accepted replica A's token"

echo "== step-up: a raw tool needs whois:raw =="
resp="$(curl -s -D - -o /dev/null -X POST "$B/mcp" \
  -H "Authorization: Bearer $access" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rdap_raw","arguments":{"domain":"example.com"}}}' \
  | tr -d '\r')"
printf '%s' "$resp" | grep -qi '^HTTP/[0-9.]* 403' || fail "rdap_raw with whois:read was not refused"
printf '%s' "$resp" | grep -qi 'insufficient_scope' || fail "no insufficient_scope challenge"
pass "step-up challenge returned"

echo "== cross-replica refresh: enrolled on A, refreshed on B =="
refreshed="$(curl -fsS -X POST "$B/oauth/token" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$refresh")"
new_access="$(printf '%s' "$refreshed" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
new_refresh="$(printf '%s' "$refreshed" | sed -n 's/.*"refresh_token":"\([^"]*\)".*/\1/p')"
[ -n "$new_access" ] || fail "replica B could not refresh a session enrolled on A; Redis is not shared"
[ "$new_refresh" != "$refresh" ] || fail "the refresh token did not rotate"
pass "cross-replica refresh rotated the token"

echo "== replaying the spent refresh token kills the family =="
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$A/oauth/token" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$refresh")"
[ "$code" = "400" ] || fail "replaying a spent refresh token returned $code, want 400"
# And the successor is dead too, on both replicas.
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/oauth/token" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$new_refresh")"
[ "$code" = "400" ] || fail "the family survived a replay ($code); reuse detection is not shared"
pass "replay revoked the whole family across replicas"

echo "== metrics are exposed =="
curl -fsS "$A/metrics" | grep -q 'whois_mcp_' || fail "no whois_mcp_ metrics exposed"
pass "metrics exposed"

echo
echo "all end-to-end checks passed"
