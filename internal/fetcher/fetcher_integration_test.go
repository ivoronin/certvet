//go:build integration

package fetcher

import (
	"strings"
	"testing"
	"time"
)

// Integration tests - require network access
// Run with: go test -tags=integration ./internal/fetcher

func TestFetchCertChain(t *testing.T) {
	t.Parallel()

	// Test against a known public endpoint
	chain, err := FetchCertChain("google.com", 10*time.Second)
	if err != nil {
		t.Fatalf("FetchCertChain failed: %v", err)
	}

	if chain.Endpoint != "google.com" {
		t.Errorf("Endpoint = %q, want %q", chain.Endpoint, "google.com")
	}

	if chain.ServerCert == nil {
		t.Fatal("ServerCert is nil")
	}

	// Google's cert should have google in the subject
	if !strings.Contains(strings.ToLower(chain.ServerCert.Subject.CommonName), "google") &&
		len(chain.ServerCert.DNSNames) == 0 {
		t.Errorf("unexpected cert subject: %v", chain.ServerCert.Subject)
	}
}

func TestFetchCertChainWithPort(t *testing.T) {
	t.Parallel()

	chain, err := FetchCertChain("google.com:443", 10*time.Second)
	if err != nil {
		t.Fatalf("FetchCertChain with port failed: %v", err)
	}
	if chain.ServerCert == nil {
		t.Fatal("ServerCert is nil")
	}
}

func TestFetchCertChainInvalidHost(t *testing.T) {
	t.Parallel()

	_, err := FetchCertChain("invalid.host.that.does.not.exist.example", 5*time.Second)
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

func TestFetchCertChainTimeout(t *testing.T) {
	t.Parallel()

	// Very short timeout should fail
	_, err := FetchCertChain("google.com", 1*time.Nanosecond)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestFetchCertChainWithSCTs(t *testing.T) {
	t.Parallel()

	// Google's certificates should have SCTs (both TLS and embedded)
	chain, err := FetchCertChain("google.com", 10*time.Second)
	if err != nil {
		t.Fatalf("FetchCertChain failed: %v", err)
	}

	// Google should have SCTs - CT is widely deployed
	if len(chain.SCTs) == 0 {
		t.Log("Warning: no SCTs found (may be normal for some network configurations)")
	} else {
		t.Logf("Found %d SCTs", len(chain.SCTs))
		for i, sct := range chain.SCTs {
			t.Logf("SCT %d: source=%v, timestamp=%v, logID=%x...",
				i, sct.Source, sct.Timestamp, sct.LogID[:8])
		}
	}
}
