package main

import (
	"strings"
	"testing"

	"github.com/ivoronin/certvet/internal/testutil"
)

func TestListCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		args         []string
		wantSubstrs  []string
		wantExitCode int
	}{
		{
			name: "default output",
			args: []string{"list"},
			wantSubstrs: []string{
				"PLATFORM", "VERSION", "FINGERPRINT", // Header columns
			},
			wantExitCode: ExitSuccess,
		},
		{
			name: "json output",
			args: []string{"list", "-j"},
			wantSubstrs: []string{
				`"platform":`,
				`"version":`,
				`"fingerprint":`,
			},
			wantExitCode: ExitSuccess,
		},
		{
			name: "filter ios",
			args: []string{"list", "-f", "ios>=17"},
			wantSubstrs: []string{
				"ios",
			},
			wantExitCode: ExitSuccess,
		},
		{
			name: "filter android",
			args: []string{"list", "-f", "android>=14"},
			wantSubstrs: []string{
				"android",
			},
			wantExitCode: ExitSuccess,
		},
		{
			name: "wide output",
			args: []string{"list", "-w", "-f", "ios=18"},
			// Wide mode shows full fingerprints (64 hex chars with colons)
			// Fingerprint format: XX:XX:XX:... (32 bytes = 64 hex chars + 31 colons = 95 chars)
			wantSubstrs: []string{
				"ios",
			},
			wantExitCode: ExitSuccess,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := testutil.RunCLI(t, tt.args...)

			if result.ExitCode != tt.wantExitCode {
				t.Errorf("exit code = %d, want %d\nstderr: %s", result.ExitCode, tt.wantExitCode, result.Stderr)
			}

			for _, substr := range tt.wantSubstrs {
				if !strings.Contains(result.Stdout, substr) {
					t.Errorf("stdout should contain %q, got:\n%s", substr, result.Stdout)
				}
			}
		})
	}
}

func TestListCommandFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		filter         string
		wantPlatform   string
		unwantPlatform string
	}{
		{
			name:           "ios only",
			filter:         "ios>=15",
			wantPlatform:   "ios",
			unwantPlatform: "android",
		},
		{
			name:           "android only",
			filter:         "android>=10",
			wantPlatform:   "android",
			unwantPlatform: "ios",
		},
		{
			name:           "macos only",
			filter:         "macos>=13",
			wantPlatform:   "macos",
			unwantPlatform: "android",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := testutil.RunCLI(t, "list", "-f", tt.filter)

			if result.ExitCode != ExitSuccess {
				t.Fatalf("exit code = %d, want %d\nstderr: %s", result.ExitCode, ExitSuccess, result.Stderr)
			}

			// Check for wanted platform (skip header check, look in data rows)
			lines := strings.Split(result.Stdout, "\n")
			foundWanted := false
			foundUnwanted := false

			for i, line := range lines {
				if i < 2 { // Skip header and separator
					continue
				}
				if strings.Contains(line, tt.wantPlatform) {
					foundWanted = true
				}
				if strings.Contains(line, tt.unwantPlatform) {
					foundUnwanted = true
				}
			}

			if !foundWanted {
				t.Errorf("expected to find platform %q in output", tt.wantPlatform)
			}
			if foundUnwanted {
				t.Errorf("unexpected platform %q found in output", tt.unwantPlatform)
			}
		})
	}
}

