# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

certvet is a CLI tool that validates SSL/TLS certificates against real Apple and Android trust stores across different OS versions. It tells you whether a certificate will be trusted by iOS, iPadOS, macOS, tvOS, visionOS, watchOS, and Android devices.

## Build Commands

```bash
make build      # Build binary (auto-compresses CSV data first)
make test       # Run test suite
make lint       # Run go vet + golangci-lint
make generate   # Regenerate trust stores from upstream sources
make dev        # Regenerate + build (development workflow)
make clean      # Remove binary and compressed files
```

Single test: `go test ./internal/validator -run TestValidateChain -v`

## Architecture

### Data Flow

```
TLS Endpoint → fetcher.FetchCertChain() → CertChain
                                              ↓
truststore.Stores (embedded) → filter.Match() → filtered stores
                                              ↓
                         validator.ValidateChain(chain, stores)
                                              ↓
                              output.Format(TrustResult[])
```

### Package Responsibilities

| Package | Purpose |
|---------|---------|
| `cmd/certvet` | CLI commands (validate, list, version) using Cobra |
| `internal/truststore` | Domain types, embedded data loading, fingerprint handling |
| `internal/validator` | Certificate chain validation with constraint checking |
| `internal/filter` | DSL parser (Participle) and matching for platform/version filters |
| `internal/fetcher` | TLS connection, chain extraction, SCT parsing |
| `internal/output` | Text table and JSON formatters |
| `internal/version` | Semver comparison with "current" support |
| `tools/generate` | Upstream scraping (Apple, Android, Chrome, Windows, CCADB) |

### Key Types

- `Store`: Platform + version + fingerprints + constraints
- `CertChain`: Endpoint + certificates + SCTs from TLS
- `TrustResult`: Validation outcome per platform/version
- `Fingerprint`: SHA-256 as `[32]byte` with hex parsing/formatting
- `Constraints`: Date-based trust rules (NotBeforeMax, DistrustDate, SCTNotAfter)

### Data Embedding

Trust store data lives in `internal/truststore/data/`:
- `certificates.csv` - Root CA fingerprints and PEM data
- `stores.csv` - Platform/version/fingerprint mappings with constraints

CSV files are zstd-compressed before embedding via `//go:embed`. The `make build` target handles compression automatically.

### Filter Expression DSL

Uses Participle parser for expressions like `ios>=15,android>=10`:
- Operators: `=`, `>`, `<`, `>=`, `<=`
- Platforms: `ios`, `ipados`, `macos`, `tvos`, `visionos`, `watchos`, `android`, `chrome`, `windows`
- Logic: OR across platforms, AND within same platform
- Special version: `current` for rolling releases

### Exit Codes

- `0` - All platforms trust the certificate
- `1` - Trust failure or connection error
- `2` - Invalid input (bad endpoint, filter syntax, no matching platforms)

## Code Conventions

- Errors wrapped with `fmt.Errorf` and `%w` for context
- Table-driven tests throughout
- Concurrent validation using `sync.WaitGroup`
- Panic on critical init failures (trust store loading)

## Linting

Configured in `.golangci.yml`:
- `errcheck` (with blank check)
- `govet`, `staticcheck`, `unused`, `ineffassign`
- Excludes `tools/generate/testdata/`

## Trust Store Generation

The `tools/generate/` package scrapes upstream sources:
- Apple: Support docs for iOS/macOS/etc trust lists
- Android: AOSP ca-certificates repository
- Chrome: Source code for CT requirements
- Windows: Certificate store dumps
- CCADB: Root CA certificate database

Run `make generate` to refresh, then `make build` to embed new data.
