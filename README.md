# certvet 🩺

**Pre-flight checks for SSL/TLS certificates against real platform trust stores.**

> 💡 **testssl.sh** tests if your config is secure. **certvet** tells you if iOS 15 users can connect.

[![Build](https://img.shields.io/github/actions/workflow/status/ivoronin/certvet/release.yml?style=flat-square)](https://github.com/ivoronin/certvet/actions)
[![Version](https://img.shields.io/github/v/release/ivoronin/certvet?style=flat-square)](https://github.com/ivoronin/certvet/releases)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?style=flat-square&logo=docker)](https://github.com/ivoronin/certvet/pkgs/container/certvet)
[![License](https://img.shields.io/badge/license-ELv2-blue?style=flat-square)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-brightgreen?style=flat-square)](#supported-platforms)

---

- 🔒 **Zero Dependencies** · Single binary, embedded trust stores, works offline
- 📱 **Multi-Platform** · iOS, Android, Chrome, macOS, Windows — all versions
- 🔄 **CI/CD Native** · JSON output, semantic exit codes, pipeline-ready
- 🛡️ **Privacy-First** · No telemetry, no external calls except your endpoint
- 📅 **Fresh Data** · Trust stores updated weekly, CalVer releases
- ⚡ **Fast** · Parallel validation, results in seconds

---

## 🚀 Quick Start

```bash
docker run --rm ghcr.io/ivoronin/certvet:latest validate google.com
```

```
PLATFORM   VERSION   VALIDATION   STATUS
android    7         PASS         GlobalSign Root CA
ios        14.0      PASS         GTS Root R1
windows    current   PASS         GTS Root R1
...
```

Sites using recently-added CAs will show compatibility issues:

```bash
docker run --rm ghcr.io/ivoronin/certvet:latest validate navercloudtrust.com
```

```
PLATFORM   VERSION   VALIDATION   STATUS
android    11        FAIL         certificate signed by unknown authority
android    12        PASS         NAVER Global Root Certification Authority
ios        15        FAIL         certificate signed by unknown authority
ios        16        PASS         NAVER Global Root Certification Authority
...
```

---

## 🔍 The Problem

SSL/TLS certificates that work on new devices often fail on older ones:

- **Older platforms** are missing recently-added root CAs
- **Chrome** enforces Certificate Transparency (SCT) deadlines for specific CAs
- **Windows** distrusts Symantec CAs with specific date constraints
- **Misconfigured servers** don't send required intermediate certificates

**Existing tools don't help** — testssl.sh, SSL Labs, and sslyze focus on security configuration, not trust store compatibility.

| Tool | Primary Focus | Per-Platform Trust |
|------|---------------|-------------------|
| **certvet** | Trust compatibility | ✅ Yes |
| testssl.sh | Security configuration | ❌ No |
| SSL Labs | Security grading | ❌ No |
| sslyze | Security scanning | ❌ No |

**certvet fills this gap** by validating the complete certificate chain against actual embedded trust stores from each platform version. If validation fails on *all* platforms, it's likely a server misconfiguration; if it fails on *some*, it's a trust store compatibility issue.

💡 **Use together:** Run `testssl.sh` for security configuration, then `certvet` for platform compatibility.

---

## ✨ Features

### Multi-Platform Trust Validation

Tests against actual embedded trust stores from:

- **Apple** (iOS 12+, iPadOS 13+, macOS 10.14+, tvOS 12+, visionOS 1+, watchOS 5+): [Trust store docs](https://support.apple.com/en-us/103272)
- **Android** (7–16, API 24+): [AOSP ca-certificates](https://android.googlesource.com/platform/system/ca-certificates/)
- **Chrome** (Root Store): [Chrome Root Store](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/)
- **Windows**: [Windows Update CTL](http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab)

Trust stores are checked weekly. New releases are published only when certificates or constraints change (CalVer versioning).

### Trust Constraint Enforcement

Validates platform-specific constraints that affect certificate trust:

- **SCTNotAfter** — Chrome's Certificate Transparency deadlines
- **NotBeforeMax** — Date-based restrictions on certificate validity
- **DistrustDate** — CA distrust timelines (e.g., Symantec phaseout)

### Production-Ready Output

- Optional JSON output for easy integration with other tools
- Semantic exit codes (0=pass, 1=fail, 2=error)
- Flexible filter syntax for targeting specific platforms

---

## 📥 Installation

### Docker (Recommended)

The easiest way to run certvet — no installation required:

```bash
docker run --rm ghcr.io/ivoronin/certvet:latest validate example.com
```

The `:latest` tag always points to the most recent release with up-to-date trust stores.

### Binary Download

Download pre-built binaries from [GitHub Releases](https://github.com/ivoronin/certvet/releases):

```bash
# Linux/macOS
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

Requires Go 1.24+.

---

## 📖 Usage

```
certvet validate <endpoint> [flags]

Flags:
  -f, --filter string      Filter expression (e.g., ios>=15,android>=10)
  -j, --json               Output in JSON format
      --timeout duration   Connection timeout (default 10s)
  -h, --help               Help for validate
```

### Basic Validation

```bash
# Using Docker
docker run --rm ghcr.io/ivoronin/certvet:latest validate api.example.com

# Using binary
./certvet validate api.example.com

# Check a specific port
docker run --rm ghcr.io/ivoronin/certvet:latest validate api.example.com:8443
```

### Filter Syntax

```bash
# Only check iOS 15+ and Android 12+
docker run --rm ghcr.io/ivoronin/certvet:latest validate -f "ios>=15,android>=12" example.com

# Check all Apple platforms
docker run --rm ghcr.io/ivoronin/certvet:latest validate -f "ios,macos,ipados" example.com

# Check specific version
docker run --rm ghcr.io/ivoronin/certvet:latest validate -f "android=14" example.com
```

**Supported platforms:** `ios`, `ipados`, `macos`, `tvos`, `visionos`, `watchos`, `android`, `chrome`, `windows`

**Operators:** `=`, `>`, `<`, `>=`, `<=`

### JSON Output

```bash
docker run --rm ghcr.io/ivoronin/certvet:latest validate -j api.example.com
```

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

---

## ⚠️ Limitations

- **Server-provided chain only**: Uses the certificate chain sent by the server. Does not fetch missing intermediates via AIA — browsers do this, but most HTTP clients (OkHttp, URLSession) don't.
- **Root trust only**: Validates against root CA trust stores. Does not check certificate revocation (OCSP/CRL).
- **Point-in-time**: Trust stores reflect the state at build time. Update to the latest release for current data.

---

## 📜 License

[Elastic License 2.0](LICENSE) — free for most use cases, but cannot be offered as a hosted service.
