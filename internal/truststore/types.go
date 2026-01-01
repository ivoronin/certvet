// Package truststore provides trust store data and validation types.
package truststore

import (
	"crypto/x509"
	"time"
)

// Platform represents a supported platform.
type Platform string

const (
	// Apple platforms
	PlatformIOS      Platform = "ios"
	PlatformIPadOS   Platform = "ipados"
	PlatformMacOS    Platform = "macos"
	PlatformTVOS     Platform = "tvos"
	PlatformVisionOS Platform = "visionos"
	PlatformWatchOS  Platform = "watchos"

	// Other platforms
	PlatformAndroid Platform = "android"
	PlatformChrome  Platform = "chrome"
	PlatformWindows Platform = "windows"
)

func (p Platform) String() string { return string(p) }

// PlatformVersion represents a specific OS version.
type PlatformVersion struct {
	Platform Platform
	Version  string // Semver string (e.g., "17.4", "18", "10")
}

// Store represents a platform version's trusted root CAs.
type Store struct {
	Platform     Platform
	Version      string                      // Semver string (e.g., "17.4", "18", "10")
	Fingerprints []Fingerprint               // SHA-256 fingerprints
	Constraints  map[Fingerprint]Constraints // Per-CA date constraints (nil if none)
}

// ConstraintFor returns constraints for a fingerprint (empty if none).
func (s Store) ConstraintFor(fp Fingerprint) Constraints {
	if s.Constraints == nil {
		return Constraints{}
	}
	return s.Constraints[fp]
}

// Constraints holds date-based trust constraints for a CA.
type Constraints struct {
	NotBeforeMax *time.Time // Windows: cert.NotBefore must be <= this
	DistrustDate *time.Time // Windows: CA distrusted after this date
	SCTNotAfter  *time.Time // Chrome: SCT timestamp must be <= this
}

// IsEmpty returns true if no constraints are set.
func (c Constraints) IsEmpty() bool {
	return c.NotBeforeMax == nil && c.DistrustDate == nil && c.SCTNotAfter == nil
}

// SCTSource indicates where an SCT was obtained.
type SCTSource int

const (
	SCTSourceTLS      SCTSource = iota // TLS extension
	SCTSourceEmbedded                  // Embedded in certificate
)

// DateFormat is the ISO 8601 date format used for displaying constraint dates.
const DateFormat = "2006-01-02"

// SCT represents a Signed Certificate Timestamp (RFC 6962).
type SCT struct {
	Timestamp time.Time // When the certificate was logged
	LogID     [32]byte  // CT log identifier
	Source    SCTSource // Where the SCT came from
}

// CertChain represents a server's certificate chain.
type CertChain struct {
	Endpoint      string
	ServerCert    *x509.Certificate
	Intermediates []*x509.Certificate
	SCTs          []SCT // Signed Certificate Timestamps (from TLS + embedded)
}

// TrustResult represents validation result for one platform version.
type TrustResult struct {
	Platform      PlatformVersion
	Trusted       bool
	MatchedCA     string              // Root CA name that anchored the chain
	VerifiedChain []*x509.Certificate // Full validated chain (if trusted)
	FailureReason string              // Why it failed (if not trusted)
}

// ValidationReport is the complete output.
type ValidationReport struct {
	Endpoint    string
	Timestamp   time.Time
	ToolVersion string
	Chain       CertChain
	Results     []TrustResult
	AllPassed   bool
}
