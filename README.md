# certvet

Validate certificate chains against platform trust stores before deployment

[![Build](https://img.shields.io/github/actions/workflow/status/ivoronin/certvet/release.yml?style=flat-square)](https://github.com/ivoronin/certvet/actions)
[![Release](https://img.shields.io/github/v/release/ivoronin/certvet?style=flat-square)](https://github.com/ivoronin/certvet/releases)

[Overview](#overview) · [Features](#features) · [Installation](#installation) · [Usage](#usage) · [Configuration](#configuration) · [Requirements](#requirements) · [License](#license)

```bash
certvet validate google.com
```

```
PLATFORM   VERSION   VALIDATION   STATUS
android    7         PASS         GlobalSign Root CA
ios        14.0      PASS         GTS Root R1
windows    current   PASS         GTS Root R1
...
```

Sites using recently-added CAs show compatibility issues on older platforms:

```bash
certvet validate navercloudtrust.com
```

```
PLATFORM   VERSION   VALIDATION   STATUS
android    11        FAIL         certificate signed by unknown authority
android    12        PASS         NAVER Global Root Certification Authority
ios        15        FAIL         certificate signed by unknown authority
ios        16        PASS         NAVER Global Root Certification Authority
...
```

## Overview

certvet fetches the TLS certificate chain from an endpoint and validates it against embedded trust stores from iOS, Android, Chrome, macOS, Windows, and other platforms. Each platform version has its own trust store snapshot, allowing detection of compatibility issues with older devices that lack recently-added root CAs. The tool also enforces platform-specific constraints such as Chrome's Certificate Transparency deadlines and Windows' CA distrust timelines.

## Features

- Validates against embedded trust stores from Apple (iOS 12+, iPadOS 13+, macOS 10.14+, tvOS 12+, visionOS 1+, watchOS 5+), Android (7-16), Chrome Root Store, and Windows
- Single binary with embedded trust stores, works offline without external dependencies
- Enforces SCTNotAfter (Chrome CT deadlines), NotBeforeMax (date restrictions), and DistrustDate (CA phaseout timelines) constraints
- JSON output and semantic exit codes (0=pass, 1=fail, 2=error) for CI/CD integration
- Filter syntax to target specific platforms and version ranges
- Trust stores updated weekly via automated builds; CalVer releases when stores change
- No telemetry or external network calls except to the target endpoint

### Limitations

- Uses only the certificate chain sent by the server; does not fetch missing intermediates via AIA
- Validates against root CA trust stores only; does not check certificate revocation (OCSP/CRL)
- Trust stores reflect state at build time; update to latest release for current data

## Installation

### Docker

```bash
docker run --rm ghcr.io/ivoronin/certvet:latest validate example.com
```

The `:latest` tag points to the most recent release with up-to-date trust stores.

### Homebrew

```bash
brew install ivoronin/ivoronin/certvet
```

### GitHub Releases

Download pre-built binaries from [Releases](https://github.com/ivoronin/certvet/releases):

```bash
curl -LO https://github.com/ivoronin/certvet/releases/latest/download/certvet_linux_amd64.tar.gz
tar xzf certvet_linux_amd64.tar.gz
./certvet version
```

### Build from Source

```bash
git clone https://github.com/ivoronin/certvet.git
cd certvet
make build
./certvet version
```

## Usage

### validate

Fetch certificate chain from endpoint and validate against trust stores.

```bash
certvet validate <endpoint> [flags]
```

Flags:

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --filter` | Filter expression (e.g., `ios>=15,android>=10`) | all platforms |
| `-j, --json` | Output in JSON format | false |
| `--timeout` | Connection timeout | 10s |

Examples:

```bash
certvet validate api.example.com
certvet validate api.example.com:8443           # Specific port
certvet validate -f "ios>=15,android>=12" api.example.com
certvet validate -f "ios,macos,ipados" api.example.com   # All Apple platforms
certvet validate -f "android=14" api.example.com         # Specific version
certvet validate -j api.example.com             # JSON output
```

Supported platforms: `ios`, `ipados`, `macos`, `tvos`, `visionos`, `watchos`, `android`, `chrome`, `windows`

Filter operators: `=`, `>`, `<`, `>=`, `<=`

JSON output format:

```json
{
  "endpoint": "api.example.com",
  "timestamp": "2025-01-15T10:30:00Z",
  "tool_version": "v2025.01.15",
  "certificate": {
    "subject": "api.example.com",
    "issuer": "R11",
    "expires": "2025-04-15T12:00:00Z",
    "fingerprint_sha256": "01:72:D6:..."
  },
  "results": [
    {"platform": "ios", "version": "18", "trusted": true, "matched_ca": "ISRG Root X1"},
    {"platform": "ios", "version": "17", "trusted": true, "matched_ca": "ISRG Root X1"}
  ],
  "all_passed": true
}
```

### list

Display all root CA certificates in the embedded trust stores.

```bash
certvet list [flags]
```

Flags:

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --filter` | Filter expression | all platforms |
| `-j, --json` | Output in JSON format | false |
| `-w, --wide` | Display full fingerprints | false |

Examples:

```bash
certvet list
certvet list -f "ios>=17"
certvet list -j
certvet list -w
```

### version

Display certvet version.

```bash
certvet version [flags]
```

Flags:

| Flag | Description | Default |
|------|-------------|---------|
| `-j, --json` | Output in JSON format | false |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All validations passed |
| 1 | One or more validations failed |
| 2 | Input or runtime error |

## Configuration

certvet has no configuration file or environment variables. All options are passed via command-line flags.

## Requirements

- Go 1.24+ (build from source only)
- Network access to target endpoint

## License

[Elastic License 2.0](LICENSE)
