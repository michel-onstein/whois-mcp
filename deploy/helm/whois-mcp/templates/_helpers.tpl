{{/*
Name helpers, the standard chart boilerplate.
*/}}
{{- define "whois-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "whois-mcp.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "whois-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "whois-mcp.labels" -}}
helm.sh/chart: {{ include "whois-mcp.chart" . }}
{{ include "whois-mcp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "whois-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "whois-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "whois-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "whois-mcp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
secretName resolves to the caller's Secret when they manage one, otherwise the
one this chart creates.
*/}}
{{- define "whois-mcp.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "whois-mcp.fullname" . -}}
{{- end -}}
{{- end -}}

{{/*
publicURL resolves the canonical URI clients reach this server on.

An explicit publicURL wins. Otherwise it is derived from the ingress host,
because the two naming the same server is the normal case and setting only one
of them was a mistake this chart used to accept: the ingress routes correctly,
every token is then rejected on an audience mismatch, and the symptom looks
nothing like the cause.

https is asserted rather than read from ingress.tls, because the server refuses
cleartext for anything but loopback — a http audience is one no client could
have reached in the first place. TLS terminated upstream of the controller is
the reason ingress.tls is not consulted.

Derivation is skipped when ingress.path is not "/", because the public URI then
depends on whether the controller rewrites that prefix, which is in an
annotation this chart cannot read — and when the host is a wildcard, which the
controller routes but which is not a name any client can be sent to. validate
says so in both cases rather than guessing.
*/}}
{{- define "whois-mcp.publicURL" -}}
{{- if .Values.publicURL -}}
{{- .Values.publicURL -}}
{{- else if and .Values.ingress.enabled .Values.ingress.host (eq .Values.ingress.path "/") (not (contains "*" .Values.ingress.host)) -}}
{{- printf "https://%s" .Values.ingress.host -}}
{{- end -}}
{{- end -}}

{{/*
publicURLHost is the hostname out of a publicURL, with any scheme, port and path
removed, for comparison against ingress.host.
*/}}
{{- define "whois-mcp.publicURLHost" -}}
{{- $u := include "whois-mcp.publicURL" . | trimPrefix "https://" | trimPrefix "http://" -}}
{{- $u | splitList "/" | first | splitList ":" | first -}}
{{- end -}}

{{/*
validate fails rendering on configurations that would deploy but not work.

Failing at template time is the whole point: every check below produces a
deployment that comes up healthy and then behaves inexplicably, which is far
more expensive to diagnose than a refused install.
*/}}
{{- define "whois-mcp.validate" -}}
{{- $publicURL := include "whois-mcp.publicURL" . -}}
{{- if not $publicURL -}}
{{- if and .Values.ingress.enabled .Values.ingress.host -}}
{{- if contains "*" .Values.ingress.host -}}
{{- fail (printf "publicURL is required here: ingress.host %q is a wildcard, which the controller routes but which is not a name a client can be sent to, so it cannot be derived from. Set publicURL to the concrete hostname clients use" .Values.ingress.host) -}}
{{- end -}}
{{- fail (printf "publicURL is required here: it would be derived from ingress.host, but ingress.path is %q rather than \"/\", so the canonical URI depends on whether your controller rewrites that prefix — which this chart cannot see. Set publicURL explicitly to the URI clients use" .Values.ingress.path) -}}
{{- end -}}
{{- fail "publicURL is required: it is the OAuth issuer and the token audience, and an unset or wrong value rejects every token. Either set it, or set ingress.host with ingress.enabled and it is derived as https://<host>" -}}
{{- end -}}
{{- if not (or (hasPrefix "https://" $publicURL) (hasPrefix "http://localhost" $publicURL)) -}}
{{- fail (printf "publicURL %q must be https: the enrollment token is submitted to it" $publicURL) -}}
{{- end -}}
{{- if hasSuffix "/" $publicURL -}}
{{- fail (printf "publicURL %q must not end in a slash: the audience is publicURL + /mcp, and a trailing slash produces a double slash that no token will match" $publicURL) -}}
{{- end -}}

{{/*
An explicit publicURL naming a host the ingress does not route is the other half
of the same failure: the controller matches on Host, so one of the two names is
not the one clients use, and whichever it is the deployment comes up healthy.
The http://localhost escape hatch is exempt — that is a port-forward, and
deliberately not the ingress.
*/}}
{{- if and .Values.publicURL .Values.ingress.enabled .Values.ingress.host (not (hasPrefix "http://localhost" .Values.publicURL)) -}}
{{- $host := include "whois-mcp.publicURLHost" . -}}
{{- $want := .Values.ingress.host -}}
{{- $ok := eq $host $want -}}
{{- if hasPrefix "*." $want -}}
{{- $ok = hasSuffix (trimPrefix "*" $want) $host -}}
{{- end -}}
{{- if not $ok -}}
{{- fail (printf "publicURL %q names host %q but ingress.host is %q: the controller matches on Host, so requests to the publicURL never reach this release. Leave publicURL unset to derive it from ingress.host, or make the two agree" $publicURL $host $want) -}}
{{- end -}}
{{- end -}}

{{- if not .Values.secrets.existingSecret -}}
{{- if not .Values.secrets.enrollmentToken -}}
{{- fail "secrets.enrollmentToken is required unless secrets.existingSecret is set" -}}
{{- end -}}
{{- if not .Values.secrets.signingKey -}}
{{- fail "secrets.signingKey is required unless secrets.existingSecret is set. It must be the SAME key on every replica, or replicas reject each other's tokens" -}}
{{- end -}}
{{- end -}}

{{- if or (eq .Values.cache "redis") (eq .Values.sessionStore "redis") -}}
{{- if and (not .Values.redis.url) (not .Values.redis.existingSecret) -}}
{{- fail "redis.url or redis.existingSecret is required when cache or sessionStore is \"redis\"" -}}
{{- end -}}
{{- end -}}

{{/* More than one replica with per-replica state is the silent-failure case. */}}
{{- $replicas := .Values.replicaCount | int -}}
{{- if .Values.autoscaling.enabled -}}
{{- $replicas = .Values.autoscaling.minReplicas | int -}}
{{- end -}}
{{- if gt $replicas 1 -}}
{{- if ne .Values.sessionStore "redis" -}}
{{- fail (printf "sessionStore is %q with %d replicas: sessions would be per-replica, so a client that enrolls against one replica is logged out by the next request the load balancer routes elsewhere. Set sessionStore=redis or replicaCount=1" .Values.sessionStore $replicas) -}}
{{- end -}}
{{- end -}}

{{- if .Values.ingress.enabled -}}
{{- if not .Values.ingress.host -}}
{{- fail "ingress.host is required when ingress.enabled is true" -}}
{{- end -}}
{{- end -}}

{{- if .Values.networkPolicy.enabled -}}
{{/*
Compared as ints rather than with `has 43`, because YAML numbers arrive as
float64 and `has` would never match the literal — the guard would then fire on a
perfectly correct config, which is a worse failure than the one it guards.
*/}}
{{- $has43 := false -}}
{{- range .Values.networkPolicy.egressPorts -}}
{{- if eq (int .) 43 -}}{{- $has43 = true -}}{{- end -}}
{{- end -}}
{{- if not $has43 -}}
{{- fail "networkPolicy.egressPorts must include 43. Without it every ccTLD that publishes no RDAP service becomes unresolvable, and the symptom looks like a parser bug rather than a firewall rule. Set it explicitly to acknowledge dropping WHOIS support" -}}
{{- end -}}
{{- end -}}
{{- end -}}
