package output

import (
	"encoding/json"
	"sort"

	"github.com/ivoronin/certvet/internal/version"
)

// ListEntry represents a single trust store certificate entry.
// It contains the platform, version, fingerprint, and issuer information.
type ListEntry struct {
	Platform    string `json:"platform"`
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
	Issuer      string `json:"issuer"`
	Constraints string `json:"constraints,omitempty"`
}

// StoreList implements Formatter for trust store listings.
// It outputs a table of trust store entries in text or JSON format.
type StoreList struct {
	Entries []ListEntry
	sorted  bool
}

// sort sorts entries by platform ASC, version ASC (semver), issuer ASC.
func (l *StoreList) sort() {
	if l.sorted {
		return
	}
	sort.Slice(l.Entries, func(i, j int) bool {
		if l.Entries[i].Platform != l.Entries[j].Platform {
			return l.Entries[i].Platform < l.Entries[j].Platform
		}
		if l.Entries[i].Version != l.Entries[j].Version {
			return version.CompareAsc(l.Entries[i].Version, l.Entries[j].Version)
		}
		return l.Entries[i].Issuer < l.Entries[j].Issuer
	})
	l.sorted = true
}

// FormatText returns kubectl-style table output with aligned columns.
// Header: PLATFORM, VERSION, FINGERPRINT, CONSTRAINTS, ISSUER
// Fingerprints in entries should already be truncated for text display.
func (l *StoreList) FormatText() string {
	if len(l.Entries) == 0 {
		return ""
	}
	l.sort()

	tw := NewTableWriter()
	tw.Header("PLATFORM", "VERSION", "FINGERPRINT", "CONSTRAINTS", "ISSUER")

	for _, e := range l.Entries {
		constraints := e.Constraints
		if constraints == "" {
			constraints = "-"
		}
		tw.Row(e.Platform, e.Version, e.Fingerprint, constraints, e.Issuer)
	}

	return tw.String()
}

// FormatJSON returns JSON array output.
// Fingerprints are expected to be full (not truncated) for JSON output.
func (l *StoreList) FormatJSON() ([]byte, error) {
	if len(l.Entries) == 0 {
		return []byte("[]"), nil
	}
	l.sort()
	return json.MarshalIndent(l.Entries, "", "  ")
}
