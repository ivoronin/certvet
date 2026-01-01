package output

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ivoronin/certvet/internal/truststore"
)

func TestFormatJSON(t *testing.T) {
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
				Platform:      truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "35"},
				Trusted:       false,
				FailureReason: "certificate signed by unknown authority",
			},
		},
		AllPassed: false,
	}

	vo := NewValidationOutput(report)
	data, err := vo.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON error: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Check key fields
	if parsed["endpoint"] != "example.com" {
		t.Errorf("endpoint = %v, want example.com", parsed["endpoint"])
	}
	if parsed["all_passed"] != false {
		t.Errorf("all_passed = %v, want false", parsed["all_passed"])
	}

	results, ok := parsed["results"].([]interface{})
	if !ok {
		t.Fatal("results is not an array")
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2", len(results))
	}
}

func TestFormatJSONFlatStructure(t *testing.T) {
	report := &truststore.ValidationReport{
		Endpoint: "example.com",
		Results: []truststore.TrustResult{
			{Platform: truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"}, Trusted: true},
			{Platform: truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "17"}, Trusted: true},
			{Platform: truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "35"}, Trusted: true},
		},
	}

	vo := NewValidationOutput(report)
	data, err := vo.FormatJSON()
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	// Results should be flat array, not grouped by platform
	results := parsed["results"].([]interface{})
	if len(results) != 3 {
		t.Errorf("expected flat array with 3 items, got %d", len(results))
	}

	// Each result should have platform and version as separate fields
	first := results[0].(map[string]interface{})
	if _, ok := first["platform"]; !ok {
		t.Error("result missing platform field")
	}
	if _, ok := first["version"]; !ok {
		t.Error("result missing version field")
	}
}

