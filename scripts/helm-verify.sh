#!/usr/bin/env bash
# Verify the chart: it renders for a realistic install, and it refuses the
# configurations that would deploy but not work.
#
# The negative cases are the point. Every one of them produces a deployment that
# comes up healthy and then behaves inexplicably — random 401s, unresolvable
# ccTLDs, clients logged out by the load balancer — and each is far cheaper to
# catch at template time than in production.
set -euo pipefail

CHART="${CHART:-deploy/helm/whois-mcp}"

BASE=(
  --set publicURL=https://whois.example
  --set secrets.enrollmentToken=test-token
  --set secrets.signingKey=test-key
  --set redis.url=redis://redis:6379/0
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
renders "single replica with memory stores" \
  --set replicaCount=1 --set autoscaling.enabled=false \
  --set cache=memory --set sessionStore=memory --set redis.url=""
renders "an externally managed secret" \
  --set secrets.existingSecret=my-secret --set secrets.enrollmentToken="" --set secrets.signingKey=""
renders "autoscaling off" --set autoscaling.enabled=false
renders "in-flight HPA metric enabled" --set autoscaling.inFlightRequests.enabled=true
renders "localhost publicURL for a dev cluster" --set publicURL=http://localhost:8080

echo
echo "== refuses what would deploy but not work =="
refuses "no publicURL" "publicURL is required" --set publicURL=""
refuses "cleartext publicURL" "must be https" --set publicURL=http://whois.example
refuses "publicURL with a trailing slash" "trailing slash" --set publicURL=https://whois.example/
refuses "no enrollment token" "secrets.enrollmentToken is required" --set secrets.enrollmentToken=""
refuses "no signing key" "secrets.signingKey is required" --set secrets.signingKey=""
refuses "redis selected with no URL" "redis.url or redis.existingSecret is required" \
  --set redis.url="" --set redis.existingSecret=""
refuses "multiple replicas with per-replica sessions" "per-replica" \
  --set sessionStore=memory --set autoscaling.enabled=false --set replicaCount=3
refuses "ingress with no host" "ingress.host is required" --set ingress.host=""
refuses "NetworkPolicy without port 43" "must include 43" \
  --set "networkPolicy.egressPorts={443}"

echo
echo "== the manifests say what they should =="
out="$(helm template t "$CHART" "${BASE[@]}")"

grep -q 'port: 43' <<<"$out" || fail "no egress rule for port 43"
grep -q 'port: 443' <<<"$out" || fail "no egress rule for port 443"
pass "NetworkPolicy allows both 43 and 443"

grep -q 'path: /healthz' <<<"$out" || fail "no liveness probe on /healthz"
grep -q 'path: /readyz' <<<"$out" || fail "no readiness probe on /readyz"
pass "probes point at healthz and readyz"

grep -q 'readOnlyRootFilesystem: true' <<<"$out" || fail "root filesystem is writable"
grep -q 'runAsNonRoot: true' <<<"$out" || fail "not running as non-root"
grep -q 'allowPrivilegeEscalation: false' <<<"$out" || fail "privilege escalation allowed"
pass "pod security context is locked down"

grep -q 'kind: PersistentVolumeClaim' <<<"$out" && fail "chart creates a PVC; the request path is stateless"
pass "no persistent volumes"

# The signing key must come from one Secret so every replica shares it.
grep -q 'name: WHOIS_MCP_SIGNING_KEY' <<<"$out" || fail "signing key not passed to the container"
grep -A3 'name: WHOIS_MCP_SIGNING_KEY' <<<"$out" | grep -q 'secretKeyRef' \
  || fail "signing key is not read from a Secret"
pass "signing key comes from a Secret, so replicas share it"

grep -q 'kind: PodDisruptionBudget' <<<"$out" || fail "no PodDisruptionBudget"
grep -q 'kind: HorizontalPodAutoscaler' <<<"$out" || fail "no HPA"
pass "PDB and HPA present"

# ServiceMonitor must not render without the operator CRD, or install fails on
# a cluster that does not have it.
grep -q 'kind: ServiceMonitor' <<<"$out" \
  && fail "ServiceMonitor rendered without the Prometheus operator CRD present"
pass "ServiceMonitor is gated on the operator CRD"

echo
echo "all chart checks passed"
