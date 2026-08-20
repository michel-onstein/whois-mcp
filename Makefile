BIN      := bin/whois-mcp
PKG      := ./...
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X github.com/qjam/whois-mcp/internal/mcpsrv.Version=$(VERSION)

.PHONY: all build run test race vet fmt fmtcheck lint tidy clean check

all: check build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/whois-mcp

## run: start the server on loopback. It refuses any other bind until auth lands (M2).
run:
	WHOIS_MCP_LISTEN=127.0.0.1:8080 go run ./cmd/whois-mcp

test:
	go test $(PKG)

race:
	go test -race $(PKG)

vet:
	go vet $(PKG)

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

fmtcheck:
	@out="$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*'))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run

tidy:
	go mod tidy

## check: everything CI runs, minus the linter binary.
check: fmtcheck vet race

clean:
	rm -rf bin
