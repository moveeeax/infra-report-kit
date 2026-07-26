BINARY  := infra-report
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test cover lint fmt example clean

all: fmt test build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/infra-report

test:
	go test ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...

fmt:
	gofmt -w .

# Renders the shipped example into out/. This is the command the README claims
# works, so it is also what CI runs.
example: build
	./bin/$(BINARY) gen -config examples/acme/acme-2026-06.json -out out

clean:
	rm -rf bin out coverage.out
