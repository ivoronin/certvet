//go:build integration

package main

import (
	"strings"
	"testing"

	"github.com/ivoronin/certvet/internal/testutil"
)

// Unit tests - test error handling without network access

func TestValidateCommandMissingEndpoint(t *testing.T) {
	t.Parallel()

	result := testutil.RunCLI(t, "validate")

	if result.ExitCode != ExitInputError {
		t.Errorf("exit code = %d, want %d for missing endpoint", result.ExitCode, ExitInputError)
	}
}

func TestValidateCommandInvalidFilter(t *testing.T) {
	t.Parallel()

	result := testutil.RunCLI(t, "validate", "-f", "invalid!!!", "example.com")

	if result.ExitCode != ExitInputError {
		t.Errorf("exit code = %d, want %d for invalid filter", result.ExitCode, ExitInputError)
	}

	if !strings.Contains(result.Stderr, "invalid filter") {
		t.Errorf("stderr should mention invalid filter, got:\n%s", result.Stderr)
	}
}

func TestValidateCommandInvalidEndpoint(t *testing.T) {
	t.Parallel()

	// Invalid hostname that won't resolve
	result := testutil.RunCLI(t, "validate", "this-host-does-not-exist-12345.invalid")

	if result.ExitCode == ExitSuccess {
		t.Errorf("expected non-zero exit code for invalid endpoint")
	}
}

