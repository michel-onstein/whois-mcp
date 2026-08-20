# whois-mcp

An MCP server that answers domain registration questions — is this domain
registered, who is the registrar, when was it created, when does it expire —
over RDAP, with a WHOIS fallback for the ccTLDs that publish no RDAP service.

- Design: [`docs/MCP_DESIGN.md`](docs/MCP_DESIGN.md)
- Build order: [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)

## Status: M4

**Any TLD resolves.** RDAP covers the gTLDs (~1,200 TLDs); the port-43 WHOIS
fallback covers the ccTLDs that publish no RDAP service, and also rescues a
lookup whose RDAP endpoint answered ambiguously.

Tools: `domain_lookup`, `domain_availability` (batch of up to 50), `tld_info`.
Resource: `whois://bootstrap/tlds`.

WHOIS text is parsed in two tiers — a per-host template for the ~40 registries
that serve most traffic, then a heuristic fallback — and every report carries a
`parse_confidence` so you can tell a structured RDAP answer (always 1.0) from
free text that was interpreted. The raw response is always retained.

`registered` is tri-state and never guesses. A rate-limit notice, an HTML error
page, an empty reply or a contradictory record all yield `unknown`, never `no`:
telling you a taken domain is free is this server's worst failure mode.

## Authentication

OAuth 2.1. The fixed enrollment token your operator holds is an *enrollment
secret*, not a request credential: it is entered once in a browser form and
exchanged for tokens scoped to a single named session.

- Access tokens are EdDSA JWTs with a 10-minute TTL, verified locally by any
  replica with no store lookup — which is what keeps replicas interchangeable.
- Refresh tokens are opaque, rotating, one-time-use, on a sliding 30-day window.
  Replaying a spent one is treated as theft: the whole family is revoked.
- Scopes: `whois:read` for lookups, `whois:raw` for the unredacted raw responses,
  `whois:admin` for `session_list` / `session_revoke`. Only `whois:read` is
  advertised; the others come through step-up, so a read-only client never holds
  a raw-capable credential.
- Sessions are individually labelled and individually revocable. Revocation is
  immediate for refresh tokens and takes effect within 10 minutes for access
  tokens.

```bash
export WHOIS_MCP_ENROLLMENT_TOKEN=$(openssl rand -base64 32)
export WHOIS_MCP_SIGNING_KEY=...        # Ed25519 seed; generated if unset
export WHOIS_MCP_PUBLIC_URL=https://whois.example   # required off loopback
```

`WHOIS_MCP_PUBLIC_URL` is the token audience, so a wrong value rejects every
token. `WHOIS_MCP_DEV_STATIC_BEARER=true` lets `curl` present the enrollment
token directly, and refuses to start off loopback because it turns that secret
into a request credential.

**Without an enrollment token the server still refuses to bind off-host.** An
unauthenticated instance reachable from a network is an open proxy that queries
registries from your egress IP, and the resulting block presents as a total
outage for the affected TLD.

Not yet implemented: M5 (`ip_lookup` / ASN lookups via the RIRs), which the plan
marks explicitly deferrable.

## Kubernetes

```bash
helm install whois-mcp deploy/helm/whois-mcp \
  --set publicURL=https://whois.example \
  --set ingress.host=whois.example \
  --set secrets.existingSecret=whois-mcp-secrets \
  --set redis.url=redis://redis:6379/0
```

Two replicas, no persistent volumes, `/healthz` and `/readyz` probes, HPA, PDB,
and a NetworkPolicy. The chart **refuses to render** configurations that would
deploy cleanly and then misbehave — a cleartext or trailing-slash `publicURL`
(it is the token audience), several replicas with per-replica sessions, or a
NetworkPolicy without egress on **port 43**. That last one is worth repeating:
without port 43 every ccTLD that publishes no RDAP service becomes unresolvable,
and the symptom reads like a parser bug rather than a firewall rule.

The signing key comes from a single Secret, so replicas necessarily share it. A
per-replica key makes each replica reject the others' tokens, which surfaces as
random 401s. To rotate it, see
[`RUNBOOK_KEY_ROTATION.md`](deploy/helm/whois-mcp/RUNBOOK_KEY_ROTATION.md) —
publish, wait one access-token lifetime, then retire.

## Running in a container

```bash
export WHOIS_MCP_ENROLLMENT_TOKEN=$(openssl rand -base64 32)
export WHOIS_MCP_SIGNING_KEY=$(openssl rand -base64 32)
cd deploy/docker && docker compose up
```

That brings up two replicas behind one Redis, which is the configuration worth
testing: it is the only way to see whether a session enrolled against one replica
works against the other. `scripts/e2e.sh` walks that flow, and CI runs it.

The image is `distroless/static:nonroot` — no shell, no package manager. It can
afford to be, because the IANA bootstrap snapshot and the enrollment UI are
compiled in with `go:embed`, so the binary has no runtime file dependencies.

## Being a well-behaved client

There is no agreement with any registry. This server queries them as an anonymous
client with no negotiated quota and no contractual protection, so it is
deliberately conservative:

- Per-upstream-host token buckets, keyed by host because several TLDs share one
  registry endpoint.
- `Retry-After` honoured exactly, in both permitted forms.
- Exponential backoff with full jitter, so several replicas that saw the same
  failure do not retry in unison.
- A circuit breaker per host, so one dead registry fails fast instead of holding
  requests open and starving every other TLD.
- Concurrent identical lookups collapsed into one upstream call.

Cache hit rate is the main lever keeping query volume off registry radar, so it
is a primary metric rather than a nicety. `/metrics` exposes it alongside lookup
duration, upstream status counts, parse confidence, rate-limiting, auth failures,
active sessions and breaker state. No metric or trace ever carries the domain
being looked up — a query stream is itself sensitive.

Set `WHOIS_MCP_OTEL_ENDPOINT` for OTLP tracing. W3C trace-context is propagated
from the MCP `_meta` fields either way, so an agent's trace links through to the
registry call that was slow.

## Run

```bash
make run            # 127.0.0.1:8080
```

Point an MCP client at `POST http://127.0.0.1:8080/mcp`, or call it directly:

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"domain_lookup","arguments":{"domain":"example.com"}}}'
```

## Develop

```bash
make check    # gofmt + go vet + go test -race
make test
make build
```

No test requires network access: registry responses are captured in
`testdata/rdap/` and served by in-process fakes, so the suite runs offline and
never depends on a third party being up.

## Two behaviours worth knowing

**`registered` is tri-state.** `"yes"`, `"no"`, or `"unknown"`. An RDAP 404
usually means "not registered", but it also happens when a server is
misconfigured or blocking us, so an ambiguous signal reports `"unknown"` rather
than guessing. Never treat `"unknown"` as "available".

**Redaction is data, not absence.** Post-GDPR most gTLD contacts are withheld.
Those come back as `{"redacted": true, ...}` with the placeholder text stripped,
which is a different fact from "there is no registrant".

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `WHOIS_MCP_LISTEN` | `127.0.0.1:8080` | Listen address; must be loopback until M2 |
| `WHOIS_MCP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `WHOIS_MCP_RDAP_BOOTSTRAP_URL` | IANA | Override for a mirror |

The IANA bootstrap registry is embedded in the binary, so a cold start with no
egress still resolves every major TLD; it refreshes from IANA on start and
daily thereafter, and a failed refresh keeps the previous data.
