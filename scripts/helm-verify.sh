#!/usr/bin/env bash
# Verify the chart: it renders for a realistic install, and it refuses the
# configurations that would deploy but not work.
#
# The negative cases are the point. Every one of them produces a deployment that
# comes up healthy and then behaves inexplicably — every token refused,
# unresolvable ccTLDs — and each is far cheaper to catch at template time than
# in production.
set -euo pipefail

CHART="${CHART:-deploy/helm/whois-mcp}"

BASE=(
  --set publicURL=https://whois.example
  --set secrets.enrollmentToken=test-token
  --set ingress.host=whois.example
)

pass() { echo "ok: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# renders <description> [extra args...]
renders() {
  local desc="$1"; shift
  helm template t "$CHART" "${BASE[@]}" "$@" >/dev/null 2>&1 \
    || fail "$desc should render but did not"
  pass "renders: $desc"
}

# refuses <description> <expected message fragment> [extra args...]
refuses() {
  local desc="$1" want="$2"; shift 2
  local out
  if out="$(helm template t "$CHART" "${BASE[@]}" "$@" 2>&1)"; then
    fail "$desc was accepted; it should be refused"
  fi
  grep -q -- "$want" <<<"$out" \
    || fail "$desc was refused, but the message did not mention '$want': $out"
  pass "refuses: $desc"
}

echo "== lint =="
helm lint "$CHART" "${BASE[@]}" >/dev/null || fail "helm lint failed"
pass "lint clean"

echo
echo "== renders =="
renders "a realistic install"
renders "no ingress" --set ingress.enabled=false
renders "an explicit signing key" --set secrets.signingKey=test-key
renders "an externally managed secret" \
  --set secrets.existingSecret=my-secret --set secrets.enrollmentToken=""
renders "localhost publicURL for a dev cluster" --set publicURL=http://localhost:8080
renders "publicURL derived from the ingress host" --set publicURL=""
renders "an explicit publicURL under a wildcard ingress host" \
  --set 'ingress.host=*.example' --set publicURL=https://whois.example
renders "an explicit publicURL with a port" --set publicURL=https://whois.example:8443

echo
echo "== refuses what would deploy but not work =="
refuses "no publicURL and no ingress to derive one from" "publicURL is required" \
  --set publicURL="" --set ingress.enabled=false
refuses "no publicURL with a non-root ingress path" "ingress.path" \
  --set publicURL="" --set ingress.path=/whois
refuses "no publicURL with a wildcard ingress host" "is a wildcard" \
  --set publicURL="" --set 'ingress.host=*.example'
refuses "a publicURL naming a host the ingress does not route" "ingress.host is" \
  --set publicURL=https://elsewhere.example
refuses "cleartext publicURL" "must be https" --set publicURL=http://whois.example
refuses "publicURL with a trailing slash" "trailing slash" --set publicURL=https://whois.example/
refuses "no enrollment token" "secrets.enrollmentToken is required" --set secrets.enrollmentToken=""
refuses "ingress with no host" "ingress.host is required" --set ingress.host=""
refuses "NetworkPolicy without port 43" "must include 43" \
  --set "networkPolicy.egressPorts={443}"

echo
echo "== the manifests say what they should =="
out="$(helm template t "$CHART" "${BASE[@]}")"

grep -q 'port: 43' <<<"$out" || fail "no egress rule for port 43"
grep -q 'port: 443' <<<"$out" || fail "no egress rule for port 443"
pass "NetworkPolicy allows both 43 and 443"

# The derived URL must reach the container, not just render somewhere: it is the
# token audience, and an empty one rejects every token.
derived="$(helm template t "$CHART" "${BASE[@]}" --set publicURL="")"
grep -A1 'name: WHOIS_MCP_PUBLIC_URL' <<<"$derived" | grep -q 'value: "https://whois.example"' \
  || fail "publicURL was not derived from ingress.host into WHOIS_MCP_PUBLIC_URL"
pass "publicURL derives from ingress.host"

grep -q 'path: /healthz' <<<"$out" || fail "no liveness probe on /healthz"
grep -q 'path: /readyz' <<<"$out" || fail "no readiness probe on /readyz"
pass "probes point at healthz and readyz"

grep -q 'readOnlyRootFilesystem: true' <<<"$out" || fail "root filesystem is writable"
grep -q 'runAsNonRoot: true' <<<"$out" || fail "not running as non-root"
grep -q 'allowPrivilegeEscalation: false' <<<"$out" || fail "privilege escalation allowed"
pass "pod security context is locked down"

grep -q 'kind: PersistentVolumeClaim' <<<"$out" && fail "chart creates a PVC; nothing here is a source of truth"
pass "no persistent volumes"

# One replica, recreated rather than rolled: sessions and the signing key are
# in-process, so two pods would refuse each other's tokens.
grep -q '^  replicas: 1$' <<<"$out" || fail "the Deployment does not pin exactly one replica"
grep -q 'type: Recreate' <<<"$out" || fail "the Deployment strategy is not Recreate"
grep -q 'kind: HorizontalPodAutoscaler' <<<"$out" && fail "an HPA rendered; it would scale past one replica"
grep -q 'kind: PodDisruptionBudget' <<<"$out" && fail "a PDB rendered; with one replica it can only block drains"
pass "exactly one replica, Recreate strategy, no HPA or PDB"

# The signing key is optional: absent from the Secret, the server generates one.
grep -A5 'name: WHOIS_MCP_SIGNING_KEY' <<<"$out" | grep -q 'optional: true' \
  || fail "signing key secretKeyRef is not optional; an existing Secret without it would fail the pod"
grep -q 'signing-key:' <<<"$out" && fail "an empty signing key was rendered into the Secret"
pass "signing key is optional"

# Nothing else is talked to: no Redis env, no port 6379 in the egress rules.
grep -q 'WHOIS_MCP_REDIS_URL\|WHOIS_MCP_SESSION_STORE\|WHOIS_MCP_CACHE' <<<"$out" \
  && fail "a store-selection env var rendered; the server has no such setting"
grep -q 'port: 6379' <<<"$out" && fail "an egress rule for Redis rendered"
pass "no external store wired in"

# ServiceMonitor must not render without the operator CRD, or install fails on
# a cluster that does not have it.
grep -q 'kind: ServiceMonitor' <<<"$out" \
  && fail "ServiceMonitor rendered without the Prometheus operator CRD present"
pass "ServiceMonitor is gated on the operator CRD"

echo
echo "all chart checks passed"
