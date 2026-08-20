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
validate fails rendering on configurations that would deploy but not work.

Failing at template time is the whole point: every check below produces a
deployment that comes up healthy and then behaves inexplicably, which is far
more expensive to diagnose than a refused install.
*/}}
{{- define "whois-mcp.validate" -}}
{{- if not .Values.publicURL -}}
{{- fail "publicURL is required: it is the OAuth issuer and the token audience, and an unset or wrong value rejects every token" -}}
{{- end -}}
{{- if not (or (hasPrefix "https://" .Values.publicURL) (hasPrefix "http://localhost" .Values.publicURL)) -}}
{{- fail (printf "publicURL %q must be https: the enrollment token is submitted to it" .Values.publicURL) -}}
{{- end -}}
{{- if hasSuffix "/" .Values.publicURL -}}
{{- fail (printf "publicURL %q must not end in a slash: the audience is publicURL + /mcp, and a trailing slash produces a double slash that no token will match" .Values.publicURL) -}}
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
