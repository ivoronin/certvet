// Package generate provides trust store data generation tools.
package generate

import (
	"strings"
	"time"

	"github.com/ivoronin/certvet/internal/truststore"
)

// Certificate represents a root CA certificate from CCADB.
type Certificate struct {
	Fingerprint truststore.Fingerprint // SHA-256 fingerprint
	PEM         string                 // PEM-encoded certificate data
}

// TrustEntry represents a single trust relationship: platform+version trusts fingerprint.
type TrustEntry struct {
	Platform    string                 // Platform identifier (e.g., "ios", "android", "chrome")
	Version     string                 // Version string (e.g., "18", "10.14", "current")
	Fingerprint truststore.Fingerprint // SHA-256 fingerprint of trusted CA

	// Date constraints (nil = no constraint)
	NotBeforeMax *time.Time // Windows: cert.NotBefore must be <= this
	DistrustDate *time.Time // Windows: CA distrusted after this date
	SCTNotAfter  *time.Time // Chrome: SCT timestamp must be <= this
}

// HasConstraints returns true if any constraint is set.
func (e *TrustEntry) HasConstraints() bool {
	return e.NotBeforeMax != nil || e.DistrustDate != nil || e.SCTNotAfter != nil
}

// FormatConstraints returns constraint string for display.
// Returns "-" if no constraints, otherwise "notbefore<DATE, distrust<DATE, sct<DATE"
func (e *TrustEntry) FormatConstraints(wide bool) string {
	var parts []string
	format := "2006-01-02"
	if wide {
		format = time.RFC3339
	}
	if e.NotBeforeMax != nil {
		parts = append(parts, "notbefore<"+e.NotBeforeMax.Format(format))
	}
	if e.DistrustDate != nil {
		parts = append(parts, "distrust<"+e.DistrustDate.Format(format))
	}
	if e.SCTNotAfter != nil {
		parts = append(parts, "sct<"+e.SCTNotAfter.Format(format))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}
