package output

import (
	"strings"
	"testing"
	"time"

	"github.com/ivoronin/certvet/internal/truststore"
)

func TestFormatTextBasic(t *testing.T) {
	report := &truststore.ValidationReport{
		Endpoint:    "example.com",
		Timestamp:   time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		ToolVersion: "v2025.01.15",
		Results: []truststore.TrustResult{
			{
				Platform:  truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"},
				Trusted:   true,
				MatchedCA: "DigiCert Global Root G2",
			},
			{
				Platform:      truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "12"},
				Trusted:       false,
				FailureReason: "certificate signed by unknown authority",
			},
		},
		AllPassed: false,
	}

	vo := NewValidationOutput(report)
	out := vo.FormatText()

	// Check table content
	if !strings.Contains(out, "PASS") {
		t.Error("missing PASS status for trusted")
	}
	if !strings.Contains(out, "FAIL") {
		t.Error("missing FAIL status for untrusted")
	}
	if !strings.Contains(out, "ios") {
		t.Error("missing ios platform")
	}
	if !strings.Contains(out, "18") {
		t.Error("missing version 18")
	}
	if !strings.Contains(out, "12") {
		t.Error("missing version 12")
	}
	if !strings.Contains(out, "DigiCert Global Root G2") {
		t.Error("missing matched CA in comment")
	}
	if !strings.Contains(out, "certificate signed by unknown authority") {
		t.Error("missing failure reason in comment")
	}
}

func TestFormatTextAllPassed(t *testing.T) {
	report := &truststore.ValidationReport{
		Endpoint:  "example.com",
		AllPassed: true,
		Results: []truststore.TrustResult{
			{
				Platform:  truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"},
				Trusted:   true,
				MatchedCA: "Test CA",
			},
		},
	}

	vo := NewValidationOutput(report)
	out := vo.FormatText()

	// Verify table has PASS status
	if !strings.Contains(out, "PASS") {
		t.Error("expected PASS in output")
	}
	if !strings.Contains(out, "Test CA") {
		t.Error("expected matched CA in output")
	}
}

func TestFormatTextMixedResults(t *testing.T) {
	report := &truststore.ValidationReport{
		Endpoint:  "example.com",
		AllPassed: false,
		Results: []truststore.TrustResult{
			{Platform: truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"}, Trusted: true, MatchedCA: "CA"},
			{Platform: truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "17"}, Trusted: false, FailureReason: "no root"},
			{Platform: truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "35"}, Trusted: false, FailureReason: "no root"},
		},
	}

	vo := NewValidationOutput(report)
	out := vo.FormatText()

	// Count PASS and FAIL occurrences
	passCount := strings.Count(out, "PASS")
	failCount := strings.Count(out, "FAIL")

	if passCount != 1 {
		t.Errorf("expected 1 PASS, got %d", passCount)
	}
	if failCount != 2 {
		t.Errorf("expected 2 FAILs, got %d", failCount)
	}
}
