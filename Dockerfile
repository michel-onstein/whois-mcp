# Multi-stage build for whois-mcp (design §11.2).
#
# The final image is distroless/static:nonroot: no shell, no package manager,
# nothing to exec into. That is affordable here because the binary genuinely has
# no runtime file dependencies — the IANA bootstrap snapshot and the enrollment
# UI templates are compiled in with go:embed, so there is nothing to mount and
# nothing to read from disk.

# ---------------------------------------------------------------- builder
#
# --platform=$BUILDPLATFORM pins the builder to the machine doing the building
# and lets Go cross-compile to $TARGETARCH below. The alternative — letting
# buildx emulate the target — runs the entire Go toolchain under QEMU, which
# turns a 20-second build into minutes for no benefit: this binary is CGO-free,
# so cross-compiling is exact.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

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
# Supplied by buildx for every platform in a multi-platform build; defaulted so
# a plain `docker build` still works.
ARG TARGETOS=linux
ARG TARGETARCH
# CGO off so the result is a genuinely static binary — distroless/static has no
# libc to link against. -trimpath keeps build paths out of the binary, and
# -w -s drop DWARF and the symbol table, which is most of the size saving.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
      -trimpath \
      -ldflags="-w -s -X github.com/qjam/whois-mcp/internal/mcpsrv.Version=${VERSION}" \
      -o /out/whois-mcp ./cmd/whois-mcp

# Verify the binary is static before shipping it into an image with no dynamic
# loader, where the failure would otherwise be an exec format error at runtime.
#
# For a cross-compiled target ldd cannot read the binary at all and the check
# passes trivially; it still earns its place on native builds, and CGO_ENABLED=0
# is what actually guarantees the property.
RUN ! ldd /out/whois-mcp 2>/dev/null | grep -q "=>" || (echo "binary is dynamically linked" && exit 1)

# ---------------------------------------------------------------- runtime
FROM gcr.io/distroless/static:nonroot

# ARGs do not cross stage boundaries, so the two the labels need are re-declared
# here rather than inherited from the builder.
ARG VERSION=dev
ARG REVISION=unknown
# SOURCE is the repository this image was built from, and it is load-bearing
# rather than decorative: GHCR attaches a published package to a repository by
# matching org.opencontainers.image.source against it. A wrong value publishes
# an orphaned package that inherits none of the repository's permissions, so CI
# passes the real value and asserts it after building.
ARG SOURCE=https://github.com/michel-onstein/whois-mcp

LABEL org.opencontainers.image.title="whois-mcp" \
      org.opencontainers.image.description="MCP server answering domain registration questions over RDAP, with a port-43 WHOIS fallback." \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.url="${SOURCE}" \
      org.opencontainers.image.documentation="${SOURCE}/blob/main/README.md" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

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
