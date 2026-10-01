# Decisions

Architectural Decision Records for `whois-mcp`. The design document
([`../MCP_DESIGN.md`](../MCP_DESIGN.md)) carries the original decisions in its
§16 table; records here are the ones taken after it was accepted, with the
context the design doc's one-line table cannot hold.

## ADR-001 — One replica, in-process state, no Redis

| | |
|---|---|
| **Date** | 2026-10-01 |
| **Status** | Accepted |
| **Design** | §11.3, decision 7 |

### Context

The accepted design ran two or more replicas behind a shared Redis holding the
cache and the sessions. That brought an HPA, a PodDisruptionBudget, topology
spread constraints, a shared Ed25519 signing key that every replica had to agree
on, a key-rotation runbook, a two-replica compose stack, a cross-replica
end-to-end check and a Redis CI job. The operator asked whether a single replica
could make it simpler, having decided one replica will always do.

### Decision

Run exactly one replica. The cache and the session store are in-process. Redis,
its client library, the Redis-backed implementations, the store-selection
configuration and every chart and CI artefact that existed to make several
processes behave as one are removed. The replica count is fixed in the
Deployment template, not exposed as a value, and the strategy is `Recreate`.

### Consequences

- **A restart forgets every session.** Each client gets a 401 on its next
  request and enrolls again through the browser. Accepted: the service is
  single-tenant, access tokens live 10 minutes, and the re-login is one click.
- **The signing key is optional.** Generated at start when unset; since the
  sessions behind the tokens die with the process, a key that does too loses
  nothing. The chart reads it from the Secret as `optional: true`.
- **Rotation is a restart.** No publish-then-retire dance for the key; the
  enrollment token is rotated by changing the Secret and restarting.
- **Availability is one pod's.** An upgrade is a few seconds of downtime under
  `Recreate`. A rolling update was rejected because two pods with different
  generated keys would each refuse the other's tokens during the overlap.

### Alternatives rejected

- **File-backed sessions on a PersistentVolumeClaim** — roughly 150 lines plus
  a PVC in the chart, to save a browser click after a deploy.
- **Redis as a sidecar** — keeps every moving part this decision removes.
