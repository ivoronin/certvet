package output

import (
	"crypto/sha256"
	"encoding/json"
	"sort"

	"github.com/ivoronin/certvet/internal/truststore"
	"github.com/ivoronin/certvet/internal/version"
)

// jsonTimeFormat is the ISO 8601 UTC timestamp format for JSON output.
// Uses literal 'Z' suffix since all times are UTC (via .UTC() call).
const jsonTimeFormat = "2006-01-02T15:04:05Z"

// ValidationOutput implements Formatter for validation reports.
type ValidationOutput struct {
	Report *truststore.ValidationReport
}

// NewValidationOutput creates a new ValidationOutput formatter.
// Results are sorted by platform (alphabetically) then version (ascending).
func NewValidationOutput(report *truststore.ValidationReport) *ValidationOutput {
	// Sort results for consistent output
	sort.Slice(report.Results, func(i, j int) bool {
		ri, rj := report.Results[i].Platform, report.Results[j].Platform
		if ri.Platform != rj.Platform {
			return ri.Platform < rj.Platform
		}
		return version.CompareAsc(ri.Version, rj.Version)
	})
	return &ValidationOutput{Report: report}
}

// FormatText formats the validation report as a human-readable table.
func (v *ValidationOutput) FormatText() string {
	report := v.Report

	tw := NewTableWriter()
	tw.Header("PLATFORM", "VERSION", "VALIDATION", "STATUS")

	for _, r := range report.Results {
		validation := "FAIL"
		status := r.FailureReason
		if r.Trusted {
			validation = "PASS"
			status = r.MatchedCA
		}
		tw.Row(string(r.Platform.Platform), r.Platform.Version, validation, status)
	}

	return tw.String()
}

// FormatJSON formats the validation report as JSON.
func (v *ValidationOutput) FormatJSON() ([]byte, error) {
	report := v.Report

	jr := jsonReport{
		Endpoint:    report.Endpoint,
		Timestamp:   report.Timestamp.UTC().Format(jsonTimeFormat),
		ToolVersion: report.ToolVersion,
		AllPassed:   report.AllPassed,
		Results:     make([]jsonResult, len(report.Results)),
	}

	// Certificate info
	if report.Chain.ServerCert != nil {
		cert := report.Chain.ServerCert
		fp := truststore.Fingerprint(sha256.Sum256(cert.Raw))
		jr.Certificate = &jsonCert{
			Subject:           cert.Subject.CommonName,
			Issuer:            cert.Issuer.CommonName,
			Expires:           cert.NotAfter.UTC().Format(jsonTimeFormat),
			FingerprintSHA256: fp.String(),
		}
	}

	// Flat results array
	for i, r := range report.Results {
		jr.Results[i] = jsonResult{
			Platform:      string(r.Platform.Platform),
			Version:       r.Platform.Version,
			Trusted:       r.Trusted,
			MatchedCA:     r.MatchedCA,
			FailureReason: r.FailureReason,
		}
	}

	return json.MarshalIndent(jr, "", "  ")
}

// jsonReport is the JSON output structure.
type jsonReport struct {
	Endpoint    string       `json:"endpoint"`
	Timestamp   string       `json:"timestamp"`
	ToolVersion string       `json:"tool_version"`
	Certificate *jsonCert    `json:"certificate,omitempty"`
	Results     []jsonResult `json:"results"`
	AllPassed   bool         `json:"all_passed"`
}

type jsonCert struct {
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	Expires           string `json:"expires"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
}

type jsonResult struct {
	Platform      string `json:"platform"`
	Version       string `json:"version"`
	Trusted       bool   `json:"trusted"`
	MatchedCA     string `json:"matched_ca,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
}
