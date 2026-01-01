package main

import (
	"strings"
	"testing"

	"github.com/ivoronin/certvet/internal/testutil"
)

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantJSON   bool
	}{
		{
			name:       "text output",
			args:       []string{"version"},
			wantSubstr: "certvet",
		},
		{
			name:       "json output",
			args:       []string{"version", "-j"},
			wantSubstr: `"version":`,
			wantJSON:   true,
		},
		{
			name:       "json long flag",
			args:       []string{"version", "--json"},
			wantSubstr: `"version":`,
			wantJSON:   true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := testutil.RunCLI(t, tt.args...)

			if result.ExitCode != 0 {
				t.Errorf("exit code = %d, want 0", result.ExitCode)
			}

			if !strings.Contains(result.Stdout, tt.wantSubstr) {
				t.Errorf("stdout should contain %q, got:\n%s", tt.wantSubstr, result.Stdout)
			}

			if tt.wantJSON {
				if !strings.HasPrefix(strings.TrimSpace(result.Stdout), "{") {
					t.Errorf("expected JSON output starting with '{', got:\n%s", result.Stdout)
				}
			}
		})
	}
}

