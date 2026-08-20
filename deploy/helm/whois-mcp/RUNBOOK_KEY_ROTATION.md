# Runbook: rotating the JWKS signing key

| | |
|---|---|
| **Status** | Current — matches the M2 keyring implementation |
| **Applies to** | `whois-mcp` chart 0.1.x |
| **Plan task** | 4.7 |

Rotating the Ed25519 signing key without invalidating live tokens.

## Why there is a procedure at all

An access token names the key that signed it, by `kid`. A replica verifies a
token by looking that `kid` up in its keyring. So the failure mode of a careless
rotation is precise: **every token minted before the switch stops verifying the
moment the old key stops being published.** Access tokens live 10 minutes, so a
rotation that drops the old key immediately logs out every client that refreshed
in the previous 10 minutes, and they cannot recover by refreshing — the refresh
endpoint is fine, but the access token they are holding is not.

Hence publish-then-retire, with a wait in between that is at least one
access-token lifetime.

`kid` is the RFC 7638 thumbprint of the public key, so it is derived rather than
assigned: the same key always produces the same `kid` on every replica and every
build. You never choose a `kid`, and two replicas cannot disagree about one.

## Before you start

- Know the access-token TTL. It is 10 minutes (`auth.AccessTokenTTL`); the wait
  below is that plus a margin.
- Confirm every replica currently shares one key. If they do not, you have a
  different problem and rotating will not fix it:

  ```sh
  # Every replica must return the same kid.
  for p in $(kubectl -n NS get pods -l app.kubernetes.io/name=whois-mcp -o name); do
    kubectl -n NS exec "$p" -- true 2>/dev/null   # no shell in the image; use the endpoint instead
  done
  curl -fsS https://whois.example/.well-known/jwks.json | jq -r '.keys[].kid'
  ```

  The image is distroless and has no shell, so inspect through the endpoint
  rather than by exec-ing into pods.

## Procedure

### 1. Generate the new key

```sh
NEW_KEY="$(openssl rand -base64 32)"      # a 32-byte Ed25519 seed
```

Keep it out of shell history if your shell records it (`HISTCONTROL=ignorespace`
and a leading space, or write it straight into your secret manager).

### 2. Publish the new key alongside the old

The chart passes exactly one key today, so a true two-key overlap needs the
server to load both. Two ways, depending on how much overlap you need:

**Option A — accept a short overlap gap (simplest).**

Roll the new key in, and accept that tokens minted in the previous 10 minutes
will fail until their holders refresh. Clients that follow the spec refresh on a
401, so most recover automatically; the visible symptom is a brief burst of 401s.

```sh
kubectl -n NS patch secret RELEASE-whois-mcp \
  --type merge -p "{\"stringData\":{\"signing-key\":\"$NEW_KEY\"}}"
kubectl -n NS rollout restart deploy/RELEASE-whois-mcp
kubectl -n NS rollout status deploy/RELEASE-whois-mcp --timeout=5m
```

**Option B — zero-gap rotation (preferred for anything user-facing).**

Run one extra replica set with the new key while the old one still serves, so
both keys are published and both verify. Concretely: install a second release
pointing at the same Redis and the same ingress host, with the new key, then
scale the old one down after the wait. The signing key differs between the two
releases; everything else — Redis, enrollment token, `publicURL` — must be
identical, because the audience must not change.

```sh
helm upgrade --install whois-mcp-next deploy/helm/whois-mcp \
  --namespace NS \
  --set publicURL=https://whois.example \
  --set secrets.signingKey="$NEW_KEY" \
  --set secrets.enrollmentToken="$(kubectl -n NS get secret RELEASE-whois-mcp \
        -o jsonpath='{.data.enrollment-token}' | base64 -d)" \
  --set redis.url=redis://redis:6379/0 \
  --set ingress.host=whois.example
```

### 3. Wait one access-token lifetime, plus margin

```sh
sleep 900   # 10 minute TTL + 5 minutes of margin
```

This is the step people skip. Skipping it is the whole failure this runbook
exists to prevent.

### 4. Verify the new key is live

```sh
curl -fsS https://whois.example/.well-known/jwks.json | jq '.keys[] | {kid, alg}'
```

Expect `alg: "EdDSA"` and the new `kid` present. Under option B both `kid`s
appear while both releases are up.

Then confirm a real client still works — a token minted now must verify:

```sh
curl -fsS -o /dev/null -w '%{http_code}\n' -X POST https://whois.example/mcp \
  -H "Authorization: Bearer $A_FRESH_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

`200` means the rotation took. `401` means stop and read step 5.

### 5. Retire the old key

Under option A this already happened. Under option B, scale the old release down
and then uninstall it:

```sh
kubectl -n NS scale deploy/RELEASE-whois-mcp --replicas=0
# Watch for 401s for a few minutes before removing it, so a rollback is cheap.
helm uninstall RELEASE --namespace NS
```

## Rolling back

Put the old key back and restart. It is a safe operation: the old key was valid
the whole time, so restoring it cannot invalidate anything that currently works.

```sh
kubectl -n NS patch secret RELEASE-whois-mcp \
  --type merge -p "{\"stringData\":{\"signing-key\":\"$OLD_KEY\"}}"
kubectl -n NS rollout restart deploy/RELEASE-whois-mcp
```

This is the reason to keep the old key until you are confident, rather than
destroying it at step 5.

## What rotation does *not* do

Rotating the signing key does **not** invalidate sessions. Refresh tokens are
opaque and live in Redis; they are unaffected. If you are rotating because you
believe a key leaked, you almost certainly also want to end the sessions:

```sh
# List sessions, then revoke individually (needs the whois:admin scope).
# session_list / session_revoke over MCP, or clear the store wholesale:
redis-cli --scan --pattern 'whois-mcp:auth:*' | xargs -r redis-cli del
```

Clearing the store logs every client out and each must re-enroll with the
enrollment token — which you should also rotate if the leak might have included
it, since in a single-tenant deployment that token is the only real security
boundary.

## Common failures

| Symptom | Cause |
|---|---|
| Every request 401s immediately after rotating | The old key was retired without the wait. Restore it, wait, retry. |
| 401s that correlate with nothing, some requests fine | Replicas hold different keys. Check JWKS returns a consistent set; the chart prevents this by sourcing the key from one Secret, so suspect a hand-edited Deployment. |
| JWKS shows the new key but tokens still fail | The audience changed. `publicURL` must be byte-identical across the rotation, since it is the `aud` value. |
| `kid` changed without you generating a key | The key was re-encoded in a way that altered the bytes. `kid` is derived from the public key; a differing `kid` means a differing key. |
