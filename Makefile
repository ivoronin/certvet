VERSION ?= $(shell date +v%Y.%m.%d)
LDFLAGS := -X main.Version=$(VERSION)

.PHONY: build test test-unit test-integration test-coverage test-all lint release update clean generate dev

build:
	go build -ldflags "$(LDFLAGS)" -o certvet ./cmd/certvet

# Default test target - runs unit tests only (no network required)
test: test-unit

# Unit tests only - no network, no subprocess tests
test-unit:
	go test ./...

# Integration tests - require network access and built binary
test-integration: build
	go test -tags=integration ./...

# Test with coverage report
test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Run all tests including integration
test-all: lint build
	go test -tags=integration ./...

lint:
	golangci-lint run

release:
	goreleaser release --clean

update:
	go run ./tools/generate/cmd

clean:
	rm -f certvet coverage.out coverage.html

# Regenerate all trust stores from upstream sources
generate:
	go run ./tools/generate/cmd

# Development: regenerate stores + build
dev: generate build
