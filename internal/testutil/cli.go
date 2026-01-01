package testutil

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// ExecResult holds the result of a CLI command execution.
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// RunCLI executes the certvet binary with the given arguments and returns the result.
// The binary must be built before running tests (use make build).
// This is for integration/E2E testing of exit codes and full CLI behavior.
func RunCLI(t testing.TB, args ...string) ExecResult {
	t.Helper()

	// Find the binary - first try the project root, then current directory
	binary := "./certvet"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		// Try from test directory (two levels up from cmd/certvet)
		binary = "../../certvet"
		if _, err := os.Stat(binary); os.IsNotExist(err) {
			t.Fatalf("certvet binary not found - run 'make build' first")
		}
	}

	cmd := exec.Command(binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("failed to run certvet: %v", err)
	}

	return ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
	}
}
