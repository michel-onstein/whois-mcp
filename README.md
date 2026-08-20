# whois-mcp

An MCP server that answers domain registration questions — is this domain
registered, who is the registrar, when was it created, when does it expire —
over RDAP, with a WHOIS fallback for the ccTLDs that publish no RDAP service.

- Design: [`docs/MCP_DESIGN.md`](docs/MCP_DESIGN.md)
- Build order: [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md)

## Status: M1

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

**There is no authentication yet.** It arrives at M2. Until then the server
refuses to bind to anything but loopback and will not start otherwise — an
unauthenticated instance reachable from a network is an open proxy that queries
registries from your egress IP, and the resulting block presents as a total
outage for the affected TLD.

Not yet implemented: auth (M2), Docker and rate limiting (M3), Helm (M4).

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
