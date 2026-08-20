BIN      := bin/whois-mcp
PKG      := ./...
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X github.com/qjam/whois-mcp/internal/mcpsrv.Version=$(VERSION)

.PHONY: all build run test race vet fmt fmtcheck lint tidy clean check check-all

all: check build

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/whois-mcp

## ADDRESS/PORT override the listener: `make run PORT=9000`.
ADDRESS ?= 127.0.0.1
PORT ?= 8080

## run: start the server on loopback. Binding anything else needs an enrollment
## token; the startup guard refuses otherwise.
run:
	go run ./cmd/whois-mcp --address $(ADDRESS) --port $(PORT)

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

## check: the fast gate — everything CI runs except the linter binary.
check: fmtcheck vet race

## check-all: check plus the linter, i.e. everything CI actually gates on.
##
## Split from `check` because golangci-lint is a separate install; use this
## before pushing. The lint config is version "2", so it needs golangci-lint v2:
##   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
check-all: check lint

clean:
	rm -rf bin
