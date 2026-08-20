# WHOIS/RDAP MCP Server — Design Document

**Status:** Draft v1
**Date:** 2026-08-19
**Scope:** An MCP (Model Context Protocol) server that lets agents query domain registration data (WHOIS/RDAP) for any domain in any TLD, with token-based authentication, a small web interface for token issuance, and a deployment path from native dev → Docker → Kubernetes (Helm).

---

## 1. Goals

1. **MCP server** exposing domain-lookup tools to any MCP client (Claude, Cursor, custom agents).
2. **Query any domain in any TLD** and report:
   - whether the domain is registered,
   - registrant / admin / technical / abuse contacts (owners),
   - registration, expiry, and last-change dates,
   - status codes, nameservers.
3. **Authentication:**
   - A **fixed bootstrap token** that a user enters in a **web interface**.
   - From that point on, **per-session tokens** are issued and used for all MCP access.
4. **Deployment:**
   - Development: run natively on the host (`go run`).
   - Production: Docker container now, Kubernetes via Helm later.

### Non-goals (v1)

- Multi-tenancy / per-user quotas and billing.
- Zone-file / DNSSEC validation, DNS lookups beyond nameserver *names*.
- Historical WHOIS archives (Wayback-style).
- Writing/mutating registration data (read-only).

---

## 2. Language Choice: Go

**Recommendation: Go (1.25+).**

### Reasoning

| Criterion | Why Go fits |
|---|---|
| **MCP SDK maturity** | The official Go SDK (`github.com/modelcontextprotocol/go-sdk`, maintained in collaboration with Google) implements the current MCP spec and ships `mcp.NewStreamableHTTPHandler` — a ready-made HTTP handler for serving MCP over the *streamable HTTP* transport. That is exactly the transport a remote (containerized) MCP server needs; we mount it on a mux behind our own auth middleware. |
| **RDAP is trivial in Go** | RDAP (RFC 7483) is plain HTTP + JSON. Go's standard library (`net/http`, `encoding/json`) covers the entire RDAP client with **zero dependencies**. |
| **WHOIS fallback is trivial in Go** | Legacy WHOIS is a raw TCP connection to port 43: send the domain, read until EOF. Standard library `net` handles it; no client library needed. |
| **Container/K8s fit** | Single static binary → ~10–15 MB distroless image, near-instant startup, low steady memory. Ideal for Helm-managed deployments and horizontal scaling. |
| **Concurrency model** | One goroutine per MCP connection and per outbound lookup; timeouts and cancellation are first-class (`context`). Parallelizing IANA bootstrap + registry queries is idiomatic. |
| **State storage** | Pure-Go SQLite driver (`modernc.org/sqlite`) — no CGO, so the Docker build is a plain `go build` with no toolchain surprises. |
| **Ops maturity** | `slog` structured logging, `go test`/`vet`/`golangci-lint`, trivial CI, easy cross-compilation. |

### Alternatives considered

- **TypeScript/Node** — the MCP reference SDK is the most feature-complete, and a good choice if the team is JS-centric. But: heavier runtime image, GC pauses, and a weaker RDAP/WHOIS library ecosystem. For a network-I/O service that will live in k8s, Go is the better fit.
- **Python** — official MCP SDK and decent `whois`/`rdap` libraries, but heavier images, slower startup, and dependency management inside containers is a recurring operational tax.
- **Rust** — excellent runtime characteristics, but the MCP SDK is younger, development velocity is slower, and the performance headroom is irrelevant for an I/O-bound lookup service. Overkill.

**Decision: Go.** The two hard requirements — a maintained MCP SDK with HTTP transport, and dead-simple HTTP/TCP/JSON I/O — both point the same direction.

---

## 3. Architecture Overview

```
  Agent (MCP client)                Web browser
  Claude / Cursor / ...             (operator)
        │  Bearer <session token>          │  fixed bootstrap token
        ▼                                  ▼
 ┌─────────────────────────────────────────────────────────────┐
 │              whois-mcp server  (single Go binary)           │
 │                                                             │
 │  ┌───────────────┐    ┌──────────────────────────────────┐  │
 │  │ Auth          │    │  MCP endpoint  POST /mcp         │  │
 │  │ middleware    │───▶│  (mcp.NewStreamableHTTPHandler)  │  │
 │  │ (Bearer)      │    │   tools: lookup_domain,          │  │
 │  └──────┬────────┘    │         domain_status, tld_support│ │
 │         │             └───────────────┬──────────────────┘  │
 │         ▼                             ▼                     │
 │  ┌───────────────┐    ┌──────────────────────────────────┐  │
 │  │ Web UI + API  │    │  Lookup pipeline                 │  │
 │  │  GET /        │    │   1. normalize domain (IDN→Puny) │  │
 │  │  POST /api/.. │    │   2. IANA bootstrap (cached)     │  │
 │  │  (issue/list/ │    │   3. RDAP  GET {base}domain/{d}  │  │
 │  │   revoke)     │    │   4. WHOIS fallback (TCP 43)     │  │
 │  └──────┬────────┘    │   5. normalize → common JSON     │  │
 │         ▼             └──────────────────────────────────┘  │
 │  ┌───────────────┐                                          │
 │  │ Session store │   SQLite (modernc.org/sqlite)            │
 │  │ (hashed toks) │   + in-memory result cache + rate limit  │
 │  └───────────────┘                                          │
 └─────────────────────────────────────────────────────────────┘
        │ outbound: HTTPS to registry RDAP, TCP 43 to WHOIS
        ▼
  IANA bootstrap (data.iana.org/rdap/dns.json) → registries
```

One binary serves everything: the MCP endpoint, the web UI, the session API, health checks, and metrics. No sidecars, no external broker.

### Repository layout (proposed)

```
cmd/whois-mcp/          main.go — config, wiring, HTTP server
internal/
  config/               env-based configuration
  auth/                 bootstrap token check, session tokens, middleware
  sessions/             SQLite-backed session store
  mcpserver/            MCP server + tool handlers (go-sdk)
  webui/                HTML templates + session API handlers
  lookup/               pipeline: normalize → bootstrap → rdap → whois
  rdap/                 RDAP client + RFC 7483 parsing
  whois/                WHOIS client (TCP 43) + text parsing
  normalize/            common result schema + mapping from both sources
  cache/                TTL result cache
  ratelimit/            per-token token bucket
  metrics/              Prometheus counters/histograms
web/                    static assets for the web UI
deploy/
  docker/Dockerfile
  docker-compose.yml
  helm/whois-mcp/       Chart.yaml, values.yaml, templates/
testdata/               RDAP + WHOIS fixtures
docs/                   this document
```

---

## 4. Authentication & Sessions

### 4.1 Token model

| Token | Format | Lifetime | Where used |
|---|---|---|---|
| **Bootstrap token** | operator-chosen string (≥ 32 chars recommended) | until rotated | Web UI only (issues sessions). Optional direct MCP use, disabled by default. |
| **Session token** | 256-bit `crypto/rand`, base64url | `SESSION_TTL` (default 24 h) | MCP `Authorization: Bearer` header; session API. |

- Session tokens are stored **hashed (SHA-256)** in SQLite — the plaintext is shown to the operator exactly once, at issuance.
- Each session token is **revocable** and **expiring**; expiry is enforced on every request.
- **Per-session semantics:** the server tracks active MCP connections per token and enforces `MAX_CONNECTIONS_PER_TOKEN` (default **1**). The operator issues one token per agent session; a second concurrent connection with the same token is rejected. This makes "per-session token" a hard guarantee, not a convention.

### 4.2 Flow

```
1. Server starts with BOOTSTRAP_TOKEN (env var or file).
2. Operator opens http://<host>:8080/  →  single-page form.
3. Operator pastes the bootstrap token.
4. Browser POSTs /api/v1/sessions {"bootstrap_token": "..."}
   → server verifies (constant-time compare)
   → creates session row (hashed token, created_at, expires_at, label)
   → responds {"session_id", "token", "expires_at"}
   → UI displays the token once, with a copy button.
5. Agent is configured with:
     url: http://<host>:8080/mcp
     headers: { Authorization: "Bearer <session token>" }
6. Every MCP request passes the auth middleware:
     Bearer token → SHA-256 → lookup in session store
     → valid & unexpired & connection slot free → proceed
     → else 401 (MCP) / 401 JSON (API).
```

### 4.3 Session API

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/v1/sessions` | bootstrap token in body | Issue a new session token. Body: `{"bootstrap_token", "label"?}`. |
| `GET /api/v1/sessions` | bootstrap **or** valid session token | List sessions (id, label, created, expires, active connections). |
| `DELETE /api/v1/sessions/{id}` | bootstrap token | Revoke a session (immediately severs its MCP connections). |
| `GET /healthz` | none | Liveness. |
| `GET /readyz` | none | Readiness (DB open, bootstrap token configured). |
| `GET /metrics` | none (bind to internal interface in prod) | Prometheus metrics. |

### 4.4 Web UI

Deliberately minimal — server-rendered HTML + a few lines of vanilla JS, no framework, no build step (served from the Go binary):

- **`/`** — bootstrap-token form; on success shows the new session token, its expiry, and the exact MCP client config snippet (URL + header) to copy.
- **`/sessions`** — table of sessions with a revoke button (requires re-entering the bootstrap token in the browser session; the token is kept in JS memory only, never persisted).

---

## 5. MCP Tools

Transport: **streamable HTTP** at `POST /mcp` (MCP spec 2025-03-26+), served by `mcp.NewStreamableHTTPHandler` from the official Go SDK, mounted behind the Bearer auth middleware. (The SDK's legacy SSE handler is available if an older client requires it; not enabled by default.)

### 5.1 `lookup_domain` — full registration record

**Input**

```json
{ "domain": "example.com", "include_raw": false }
```

- `domain` (required): FQDN, any TLD. IDN accepted (converted to Punycode).
- `include_raw` (optional, default `false`): include the truncated raw source document for debugging.

**Output** (normalized, source-agnostic)

```json
{
  "domain": "example.com",
  "registered": true,
  "source": "rdap",
  "registry": "VeriSign Inc.",
  "status": ["ok"],
  "events": {
    "registration": "1995-09-14T04:00:00Z",
    "expiration": "2026-09-13T04:00:00Z",
    "last_changed": "2025-06-01T12:00:00Z"
  },
  "entities": {
    "registrant": { "handle": "REDACTED", "name": "REDACTED", "organization": "REDACTED", "country": "US" },
    "admin":      [],
    "technical":  [{ "handle": "...", "name": "...", "organization": "..." }],
    "abuse":      [{ "name": "...", "email": "..." }]
  },
  "nameservers": ["ns1.example-dns.com", "ns2.example-dns.com"],
  "raw": null
}
```

Notes:

- `registered: false` is the explicit answer to "is this domain taken?" — produced when RDAP returns **404** or WHOIS returns a "not found" pattern.
- `source` tells the agent how much to trust the fields: `rdap` (structured, authoritative) vs `whois` (heuristic text parsing — some fields may be `null`).
- GDPR-redacted fields come back as `"REDACTED"` (that is what registries return post-GDPR); the schema preserves the shape so agents can reason about it.
- Errors (registry timeout, malformed response, unsupported domain) return a structured MCP error with `code` (`registry_error`, `timeout`, `invalid_domain`, …) so agents can retry or fall back gracefully.

### 5.2 `domain_status` — lightweight availability check

**Input:** `{ "domain": "example.com" }`
**Output:** `{ "domain": "example.com", "registered": true, "source": "rdap" }`

Same pipeline but stops after the status determination (no full parse). Intended for agents checking many candidate names; cheaper and faster.

### 5.3 `tld_support` — data-quality introspection

**Input:** `{ "tld": "com" }` or `{}` (all)
**Output:** `{ "com": { "rdap": "https://rdap.verisign.com/com/v1/", "whois": "whois.verisign.com" }, ... }`

Lets an agent know *beforehand* whether a TLD is RDAP-covered (structured data) or WHOIS-only (heuristic), and which registry serves it.

---

## 6. Lookup Pipeline

```
domain ─▶ normalize ─▶ TLD extract ─▶ IANA bootstrap (cache 24 h)
                                      │
                     ┌────────────────┴─────────────┐
                     │ RDAP base URL present?       │
                     ▼                              ▼
        GET {base}domain/{domain}        WHOIS: TCP 43 → registry server
        (RFC 7483, timeout 10 s)         (timeout 10 s, 64 KB cap)
                     │                              │
        200 → parse RFC 7483 JSON      parse text (per-TLD heuristics)
        404 → registered=false         "not found" patterns → registered=false
        403/5xx/timeout → fall back ───▶ WHOIS
                     │                              │
                     └────────────┬─────────────────┘
                                  ▼
                     normalize → common schema (section 5.1)
                                  ▼
                     result cache (TTL 300 s, key = domain+source)
```

Details:

1. **Normalization** — lowercase, trim, IDN → Punycode (`golang.org/x/net/idna`), RFC 1035 label validation. Rejects anything that isn't a plausible FQDN before any network I/O.
2. **TLD extraction** — last label. IANA's bootstrap file is keyed by last label, and ccTLDs with delegated subdomains (e.g. `co.uk`) are listed under the parent (`uk`), so last-label lookup is correct for the bootstrap.
3. **IANA bootstrap** — `GET https://data.iana.org/rdap/dns.json` (structure: `services: [[tlds], [rdapBaseUrls]]`). Cached in memory, TTL 24 h, refreshed on failure with stale-while-error.
4. **RDAP** — `GET {base}domain/{domain}` per RFC 7483. Parse `ldhName`, `status[]`, `events[]` (eventAction → registration/expiration/last changed), `entities[]` (roles: registrant, administrative, technical, abusive contact), `nameservers[]`.
5. **WHOIS fallback** — registry WHOIS server resolved from IANA's root database (`https://www.iana.org/domains/rootdb`, parsed for `tld → whois server` lines, cached 24 h). Send `<domain>\r\n`, read to EOF. Parsing is regex/heuristic per TLD family (Verisign `.com/.net`, DENIC `.de`, Nominet `.uk`, …) with a generic fallback; "not found" detection uses a pattern list (`No match for`, `NOT FOUND`, `No Data Found`, `No entries found`, …).
6. **Normalization** — both sources map into the single schema of §5.1; fields a source can't provide are `null` (never guessed).
7. **Caching** — result cache TTL 300 s (configurable) keyed by `domain+source`. Registration state can change; 5 minutes is the right balance for agent retry patterns and registry load.
8. **Rate limiting** — token bucket per session token, default 10 req/min, to protect registries and the server from agent loops.
9. **SSRF safety** — the server only ever connects to hosts obtained from IANA-published data (RDAP base URLs, WHOIS servers), never to user-supplied URLs. Outbound is HTTPS (RDAP) and TCP 43 (WHOIS) only.

---

## 7. Configuration

12-factor, all via environment (or a single `CONFIG_FILE` with the same keys):

| Variable | Default | Description |
|---|---|---|
| `BOOTSTRAP_TOKEN` | — (required) | Fixed token for the web UI. |
| `BOOTSTRAP_TOKEN_FILE` | — | Alternative: path to a file containing the token (preferred in k8s). |
| `LISTEN_ADDR` | `0.0.0.0:8080` | HTTP listen address. |
| `SESSION_TTL` | `24h` | Session token lifetime. |
| `MAX_CONNECTIONS_PER_TOKEN` | `1` | Concurrent MCP connections per session token. |
| `ALLOW_BOOTSTRAP_MCP` | `false` | If `true`, the bootstrap token also authenticates MCP directly (dev convenience; keep `false` in prod). |
| `RESULT_CACHE_TTL` | `300s` | Lookup result cache lifetime. |
| `RATE_LIMIT_RPM` | `10` | Queries per minute per session token. |
| `DB_PATH` | `/data/sessions.db` | SQLite path (`:memory:` for ephemeral). |
| `LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error`. |

---

## 8. Security Considerations

- **Bootstrap token:** constant-time comparison; never logged (redacted in all log lines); rotation = change env/secret + restart (sessions survive rotation; the old bootstrap token simply stops issuing new ones).
- **Session tokens:** 256-bit random, hashed at rest, expiring, revocable; plaintext shown once.
- **TLS:** terminated at the edge (ingress in k8s, reverse proxy in dev). The server itself speaks plaintext HTTP internally; `LISTEN_ADDR` should not be exposed unencrypted in production.
- **Abuse resistance:** per-token rate limiting, 10 s outbound timeouts, 64 KB WHOIS response cap, 4 MiB MCP request cap (SDK default), input validation before any network I/O.
- **Audit:** every query emits a structured log line: `session_id, domain, source, registered, latency_ms, cache_hit`.
- **Data handling:** WHOIS/RDAP data may contain personal data (pre-GDPR records). The server is read-only, caches briefly, and logs only the queried domain — never the returned personal data.

---

## 9. Deployment

### 9.1 Development (native)

```bash
BOOTSTRAP_TOKEN=dev-token-... go run ./cmd/whois-mcp
# → MCP at http://localhost:8080/mcp, web UI at http://localhost:8080/
```

No CGO, no external services — the only runtime dependency is outbound internet access for IANA/registry lookups.

### 9.2 Docker

Multi-stage build:

```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -out /whois-mcp ./cmd/whois-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /whois-mcp /whois-mcp
EXPOSE 8080
ENTRYPOINT ["/whois-mcp"]
```

- `CGO_ENABLED=0` (pure-Go SQLite) → static binary → distroless, non-root, ~10 MB.
- `HEALTHCHECK` against `/healthz`.
- `docker-compose.yml` for local container testing: one service, `BOOTSTRAP_TOKEN` from `.env`, volume for `/data` (SQLite), port 8080.

### 9.3 Kubernetes (Helm)

Chart `deploy/helm/whois-mcp/`:

| Resource | Notes |
|---|---|
| `Secret` | `bootstrapToken` from `values.bootstrapToken` (or `existingSecret`). |
| `Deployment` | 1 replica to start (stateless except SQLite); `livenessProbe`/`readinessProbe` on `/healthz`/`readyz`; non-root, read-only rootfs; resources from values. |
| `Service` | ClusterIP, port 8080. |
| `PersistentVolumeClaim` | for `/data` (SQLite) — or `emptyDir`/`:memory:` if sessions may be ephemeral (see open questions). |
| `Ingress` | TLS termination; path `/` → server. Restrict to internal network / add auth at the edge if the cluster is exposed. |

`values.yaml` highlights: `image.{repository,tag}`, `replicaCount`, `bootstrapToken`, `sessionTTL`, `resultCacheTTL`, `rateLimitRPM`, `persistence.{enabled,size}`, `ingress.{enabled,host,tls}`, `resources`.

`NOTES.txt` prints the bootstrap-token retrieval command and the two-step "open web UI → create session → configure agent" flow.

Scaling note: the design is horizontally scalable — session store and result cache are the only state. If >1 replica is needed, move sessions to a shared store (e.g. Postgres) or pin replicas to the PVC; this is a v2 concern.

---

## 10. Observability

- **Logging:** `slog`, JSON, one line per request/query (see audit fields in §8).
- **Metrics** (`/metrics`, Prometheus client):
  - `whois_mcp_queries_total{source,registered,code}`
  - `whois_mcp_query_duration_seconds` (histogram)
  - `whois_mcp_cache_hits_total` / `whois_mcp_cache_misses_total`
  - `whois_mcp_active_sessions` (gauge)
  - `whois_mcp_auth_failures_total`
- **Health:** `/healthz` (process alive), `/readyz` (DB open, bootstrap configured, IANA bootstrap cache warm or fetchable).

---

## 11. Testing Strategy

| Layer | Approach |
|---|---|
| **Unit** | RDAP parser against captured fixtures (Verisign `.com`, PIR `.org`, DENIC `.de`, Nominet `.uk`); WHOIS text parser against fixture files incl. "not found" variants; normalization mapping; token store (expiry, revocation, connection slots); rate limiter; domain normalization (IDN, case, invalid inputs). |
| **Integration** | Full pipeline against a mock RDAP server (`httptest`) and a mock WHOIS server (local TCP listener): 200/404/403/timeout paths, RDAP→WHOIS fallback, caching, rate limiting. |
| **E2E** | Docker build → run container → issue session via API → connect with an MCP client (go-sdk `mcp.Client` over streamable HTTP) → call `lookup_domain` on a real domain → assert normalized output. Runs in CI. |
| **CI** | GitHub Actions: `golangci-lint`, `go test ./...` (with race detector), Docker build, E2E job. |

Fixture policy: captured registry responses are committed to `testdata/` (they are public data); tests must not require live network access.

---

## 12. Milestones

| # | Deliverable | Exit criteria |
|---|---|---|
| **M1 — Core** | Go module; MCP server (`lookup_domain` via RDAP); bootstrap + session auth; web UI; runs natively. | Agent queries a `.com` domain end-to-end with a session token; unauthenticated requests rejected. |
| **M2 — Coverage** | WHOIS fallback; `domain_status`, `tld_support`; normalization hardening; caching; rate limiting; metrics. | `.de`/`.uk`/no-RDAP TLDs resolve via WHOIS; 404 → `registered:false`; rate limit enforced. |
| **M3 — Container** | Dockerfile, compose, E2E in CI. | `docker compose up` → full flow works against the container. |
| **M4 — Kubernetes** | Helm chart, ingress, persistence, probes. | `helm install` on a test cluster → agent queries through the ingress URL. |

---

## 13. Open Questions

1. **Session persistence across restarts** — SQLite default keeps sessions alive; `:memory:` loses them. Confirm the desired prod behavior (recommendation: keep SQLite + PVC).
2. **Token refresh** — v1 has no refresh flow; an expired session means re-entering the bootstrap token in the web UI. Acceptable? (Alternative: session tokens can extend their own expiry via an API call.)
3. **WHOIS server map** — fetch from IANA at runtime (always current, one extra dependency on IANA availability) vs. bundle a static map updated by a cron job (offline-resilient). Recommendation: runtime fetch with a bundled fallback snapshot.
4. **Metrics exposure** — bind `/metrics` to the same port (simplest) or a separate internal port (cleaner in k8s). Recommendation: separate port, enabled by default.
5. **Multi-replica state** — deferred to v2 (shared session store) unless the deployment requires >1 replica early.
