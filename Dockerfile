# Multi-stage build for whois-mcp (design §11.2).
#
# The final image is distroless/static:nonroot: no shell, no package manager,
# nothing to exec into. That is affordable here because the binary genuinely has
# no runtime file dependencies — the IANA bootstrap snapshot and the enrollment
# UI templates are compiled in with go:embed, so there is nothing to mount and
# nothing to read from disk.

# ---------------------------------------------------------------- builder
FROM golang:1.26-alpine AS builder

# git is needed only if a dependency resolves via VCS; ca-certificates so the
# module proxy is verifiable.
RUN apk add --no-cache ca-certificates git

WORKDIR /src

# Dependencies first, as their own layer: they change far less often than the
# source, so a code-only edit reuses the download.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
# CGO off so the result is a genuinely static binary — distroless/static has no
# libc to link against. -trimpath keeps build paths out of the binary, and
# -w -s drop DWARF and the symbol table, which is most of the size saving.
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-w -s -X github.com/qjam/whois-mcp/internal/mcpsrv.Version=${VERSION}" \
      -o /out/whois-mcp ./cmd/whois-mcp

# Verify the binary is static before shipping it into an image with no dynamic
# loader, where the failure would otherwise be an exec format error at runtime.
RUN ! ldd /out/whois-mcp 2>/dev/null | grep -q "=>" || (echo "binary is dynamically linked" && exit 1)

# ---------------------------------------------------------------- runtime
FROM gcr.io/distroless/static:nonroot

# TLS roots for RDAP over https. Port 43 needs none, being cleartext by protocol.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/whois-mcp /usr/local/bin/whois-mcp

# 65532 is distroless' "nonroot". Named numerically so a read-only root
# filesystem and a restrictive PodSecurityContext both work without lookups.
USER 65532:65532

# Bind all interfaces inside the container: the network boundary is the
# container and the k8s NetworkPolicy, not the process. The startup guard still
# refuses this unless an enrollment token is configured.
ENV WHOIS_MCP_LISTEN=:8080
EXPOSE 8080

# No HEALTHCHECK: there is no shell or curl in the image to run one with, and
# Kubernetes probes /healthz and /readyz over HTTP instead. A HEALTHCHECK here
# would be a directive nothing can execute.

ENTRYPOINT ["/usr/local/bin/whois-mcp"]
