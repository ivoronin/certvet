//go:build integration

package main

import (
	"strings"
	"testing"

	"github.com/ivoronin/certvet/internal/testutil"
)

// Integration tests - require network access
// Run with: go test -tags=integration ./cmd/certvet

func TestValidateRealEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		args         []string
		wantExitCode int
		wantSubstrs  []string
	}{
		{
			name:         "google.com text",
			args:         []string{"validate", "google.com"},
			wantExitCode: ExitSuccess,
			wantSubstrs:  []string{"PLATFORM", "PASS"}, // Header and result
		},
		{
			name:         "google.com json",
			args:         []string{"validate", "-j", "google.com"},
			wantExitCode: ExitSuccess,
			wantSubstrs:  []string{`"endpoint":`, `google.com`},
		},
		{
			name:         "with filter ios",
			args:         []string{"validate", "-f", "ios>=15", "google.com"},
			wantExitCode: ExitSuccess,
			wantSubstrs:  []string{"ios"},
		},
		{
			name:         "with filter android",
			args:         []string{"validate", "-f", "android>=10", "google.com"},
			wantExitCode: ExitSuccess,
			wantSubstrs:  []string{"android"},
		},
		{
			name:         "cloudflare.com",
			args:         []string{"validate", "cloudflare.com"},
			wantExitCode: ExitSuccess,
			wantSubstrs:  []string{"PASS"}, // Text output shows PASS status
		},
		{
			name:         "with explicit port",
			args:         []string{"validate", "google.com:443"},
			wantExitCode: ExitSuccess,
			wantSubstrs:  []string{"PASS"},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := testutil.RunCLI(t, tt.args...)

			if result.ExitCode != tt.wantExitCode {
				t.Errorf("exit code = %d, want %d\nstderr: %s\nstdout: %s",
					result.ExitCode, tt.wantExitCode, result.Stderr, result.Stdout)
			}

			for _, substr := range tt.wantSubstrs {
				if !strings.Contains(result.Stdout, substr) {
					t.Errorf("stdout should contain %q, got:\n%s", substr, result.Stdout)
				}
			}
		})
	}
}

func TestValidateWithTimeout(t *testing.T) {
	t.Parallel()

	// Short timeout that should still work for a fast site
	result := testutil.RunCLI(t, "validate", "--timeout", "30s", "google.com")

	if result.ExitCode != ExitSuccess {
		t.Errorf("exit code = %d, want %d\nstderr: %s", result.ExitCode, ExitSuccess, result.Stderr)
	}
}

func TestValidateMultiplePlatforms(t *testing.T) {
	t.Parallel()

	result := testutil.RunCLI(t, "validate", "-f", "ios>=17,android>=14", "google.com")

	if result.ExitCode != ExitSuccess {
		t.Errorf("exit code = %d, want %d\nstderr: %s", result.ExitCode, ExitSuccess, result.Stderr)
	}

	// Should show both platforms
	if !strings.Contains(result.Stdout, "ios") {
		t.Error("output should contain ios platform")
	}
	if !strings.Contains(result.Stdout, "android") {
		t.Error("output should contain android platform")
	}
}

func TestValidateJSONOutput(t *testing.T) {
	t.Parallel()

	result := testutil.RunCLI(t, "validate", "-j", "google.com")

	if result.ExitCode != ExitSuccess {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", result.ExitCode, ExitSuccess, result.Stderr)
	}

	// Verify it's valid JSON structure
	output := strings.TrimSpace(result.Stdout)
	if !strings.HasPrefix(output, "{") {
		t.Errorf("expected JSON object output, got:\n%s", output)
	}

	// Should contain expected fields
	expectedFields := []string{
		`"endpoint":`,
		`"results":`,
		`"all_passed":`,
	}
	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("JSON should contain %s, got:\n%s", field, output)
		}
	}
}
