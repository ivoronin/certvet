package validator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ivoronin/certvet/internal/truststore"
)

// Test infrastructure for injecting mock certificates
var (
	testCerts   = make(map[truststore.Fingerprint]*x509.Certificate)
	testCertsMu sync.RWMutex
)

func init() {
	// Override cert lookup to check test certs first
	originalLookup := getCertByFingerprint
	getCertByFingerprint = func(fp truststore.Fingerprint) *x509.Certificate {
		testCertsMu.RLock()
		cert, ok := testCerts[fp]
		testCertsMu.RUnlock()
		if ok {
			return cert
		}
		return originalLookup(fp)
	}
}

func registerTestCert(fp truststore.Fingerprint, cert *x509.Certificate) {
	testCertsMu.Lock()
	testCerts[fp] = cert
	testCertsMu.Unlock()
}

func unregisterTestCert(fp truststore.Fingerprint) {
	testCertsMu.Lock()
	delete(testCerts, fp)
	testCertsMu.Unlock()
}

// generateTestCert creates a self-signed test certificate
func generateTestCert(t *testing.T, isCA bool, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}

	signerCert := template
	signerKey := key
	if parent != nil {
		signerCert = parent
		signerKey = parentKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key
}

func TestValidateChainTrusted(t *testing.T) {
	t.Parallel()

	// Create a CA and a server cert signed by that CA
	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	chain := &truststore.CertChain{
		Endpoint:      "test.example.com",
		ServerCert:    serverCert,
		Intermediates: []*x509.Certificate{}, // CA is root, no intermediates
	}

	// Create a trust store with the CA's fingerprint
	fp := truststore.FingerprintFromCert(caCert)
	stores := []truststore.Store{
		{Platform: truststore.PlatformIOS, Version: "18", Fingerprints: []truststore.Fingerprint{fp}},
	}

	// Register the CA cert for lookup
	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Trusted {
		t.Errorf("expected trusted, got failure: %s", r.FailureReason)
	}
	if r.MatchedCA == "" {
		t.Error("MatchedCA should be set for trusted chain")
	}
}

func TestValidateChainUntrusted(t *testing.T) {
	t.Parallel()

	// Create a server cert signed by an unknown CA
	unknownCA, unknownKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, unknownCA, unknownKey)

	chain := &truststore.CertChain{
		Endpoint:      "test.example.com",
		ServerCert:    serverCert,
		Intermediates: []*x509.Certificate{},
	}

	// Create a trust store with a DIFFERENT CA (not the one that signed our cert)
	otherCA, _ := generateTestCert(t, true, nil, nil)
	fp := truststore.FingerprintFromCert(otherCA)
	stores := []truststore.Store{
		{Platform: truststore.PlatformIOS, Version: "18", Fingerprints: []truststore.Fingerprint{fp}},
	}

	registerTestCert(fp, otherCA)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Trusted {
		t.Error("expected untrusted")
	}
	if r.FailureReason == "" {
		t.Error("FailureReason should be set for untrusted chain")
	}
}

func TestValidateChainMultipleStores(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
	}

	fp := truststore.FingerprintFromCert(caCert)
	stores := []truststore.Store{
		{Platform: truststore.PlatformIOS, Version: "18", Fingerprints: []truststore.Fingerprint{fp}},
		{Platform: truststore.PlatformIOS, Version: "17", Fingerprints: []truststore.Fingerprint{fp}},
		{Platform: truststore.PlatformAndroid, Version: "35", Fingerprints: []truststore.Fingerprint{fp}},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for _, r := range results {
		if !r.Trusted {
			t.Errorf("expected all trusted, got failure for %v: %s", r.Platform, r.FailureReason)
		}
	}
}

func TestValidateChainChrome(t *testing.T) {
	t.Parallel()

	// Chrome store - should trust normally (no special constraint handling)
	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
	}

	fp := truststore.FingerprintFromCert(caCert)
	stores := []truststore.Store{
		{Platform: truststore.PlatformChrome, Version: "139", Fingerprints: []truststore.Fingerprint{fp}},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)
	// No constraints registered - should pass

	results := ValidateChain(chain, stores)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if !r.Trusted {
		t.Errorf("expected trusted, got failure: %s", r.FailureReason)
	}
}

func TestValidateChainKnownMissingRoot(t *testing.T) {
	t.Parallel()

	// Create a CA (the "known but missing" root) and a server cert
	missingRootCA, caKey := generateTestCert(t, true, nil, nil)
	missingRootCA.Subject.CommonName = "Apple Platform Root CA - G1"
	serverCert, _ := generateTestCert(t, false, missingRootCA, caKey)

	// Simulate server sending full chain including root
	chain := &truststore.CertChain{
		Endpoint:      "apple-service.example.com",
		ServerCert:    serverCert,
		Intermediates: []*x509.Certificate{missingRootCA}, // Server sends root
	}

	// Trust store has the fingerprint but NO cert data registered
	missingFP := truststore.FingerprintFromCert(missingRootCA)
	// Also add a different CA that IS available (so store isn't empty)
	availableCA, _ := generateTestCert(t, true, nil, nil)
	availableFP := truststore.FingerprintFromCert(availableCA)

	stores := []truststore.Store{
		{
			Platform: truststore.PlatformIOS,
			Version:  "26",
			Fingerprints: []truststore.Fingerprint{
				missingFP,   // Known but no cert data
				availableFP, // Available
			},
		},
	}

	// Only register the available CA, NOT the missing one
	registerTestCert(availableFP, availableCA)
	defer unregisterTestCert(availableFP)
	// missingFP is NOT registered - simulates Apple Platform root

	results := ValidateChain(chain, stores)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Trusted {
		t.Error("expected untrusted (missing cert data)")
	}

	// Should detect it's a known-but-missing root
	expectedMsg := "chain roots at known CA (fingerprint " + missingFP.String() + ") but certificate data unavailable"
	if r.FailureReason != expectedMsg {
		t.Errorf("expected %q, got %q", expectedMsg, r.FailureReason)
	}
}

func TestConstraintNotBeforeMax(t *testing.T) {
	t.Parallel()

	// Create CA and server cert issued TODAY
	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
	}

	fp := truststore.FingerprintFromCert(caCert)

	// Set NotBeforeMax to YESTERDAY - cert issued after this should fail
	yesterday := time.Now().Add(-24 * time.Hour)
	stores := []truststore.Store{
		{
			Platform:     truststore.PlatformWindows,
			Version:      "current",
			Fingerprints: []truststore.Fingerprint{fp},
			Constraints: map[truststore.Fingerprint]truststore.Constraints{
				fp: {NotBeforeMax: &yesterday},
			},
		},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	r := results[0]
	if r.Trusted {
		t.Error("expected untrusted due to NotBeforeMax constraint")
	}
	if r.FailureReason == "" {
		t.Error("FailureReason should explain the constraint violation")
	}
	t.Logf("FailureReason: %s", r.FailureReason)
}

func TestConstraintNotBeforeMaxPasses(t *testing.T) {
	t.Parallel()

	// Create CA and server cert issued TODAY
	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
	}

	fp := truststore.FingerprintFromCert(caCert)

	// Set NotBeforeMax to TOMORROW - cert issued before this should pass
	tomorrow := time.Now().Add(24 * time.Hour)
	stores := []truststore.Store{
		{
			Platform:     truststore.PlatformWindows,
			Version:      "current",
			Fingerprints: []truststore.Fingerprint{fp},
			Constraints: map[truststore.Fingerprint]truststore.Constraints{
				fp: {NotBeforeMax: &tomorrow},
			},
		},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	r := results[0]
	if !r.Trusted {
		t.Errorf("expected trusted, got failure: %s", r.FailureReason)
	}
}

func TestConstraintDistrustDate(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
	}

	fp := truststore.FingerprintFromCert(caCert)

	// Set DistrustDate to YESTERDAY - CA should be distrusted
	yesterday := time.Now().Add(-24 * time.Hour)
	stores := []truststore.Store{
		{
			Platform:     truststore.PlatformWindows,
			Version:      "current",
			Fingerprints: []truststore.Fingerprint{fp},
			Constraints: map[truststore.Fingerprint]truststore.Constraints{
				fp: {DistrustDate: &yesterday},
			},
		},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	r := results[0]
	if r.Trusted {
		t.Error("expected untrusted due to DistrustDate constraint")
	}
	if r.FailureReason == "" {
		t.Error("FailureReason should explain the distrust")
	}
	t.Logf("FailureReason: %s", r.FailureReason)
}

func TestConstraintSCTNotAfter(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	// Create chain with SCT issued TODAY
	now := time.Now()
	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
		SCTs: []truststore.SCT{
			{Timestamp: now, Source: truststore.SCTSourceTLS},
		},
	}

	fp := truststore.FingerprintFromCert(caCert)

	// Set SCTNotAfter to YESTERDAY - SCT issued after this should fail
	yesterday := time.Now().Add(-24 * time.Hour)
	stores := []truststore.Store{
		{
			Platform:     truststore.PlatformChrome,
			Version:      "current",
			Fingerprints: []truststore.Fingerprint{fp},
			Constraints: map[truststore.Fingerprint]truststore.Constraints{
				fp: {SCTNotAfter: &yesterday},
			},
		},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	r := results[0]
	if r.Trusted {
		t.Error("expected untrusted due to SCTNotAfter constraint")
	}
	if r.FailureReason == "" {
		t.Error("FailureReason should explain the SCT violation")
	}
	t.Logf("FailureReason: %s", r.FailureReason)
}

func TestConstraintSCTNotAfterNoSCTs(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	// Chain without any SCTs
	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
		SCTs:       nil, // No SCTs
	}

	fp := truststore.FingerprintFromCert(caCert)

	// Set SCTNotAfter - requires SCT but none provided
	deadline := time.Now().Add(24 * time.Hour)
	stores := []truststore.Store{
		{
			Platform:     truststore.PlatformChrome,
			Version:      "current",
			Fingerprints: []truststore.Fingerprint{fp},
			Constraints: map[truststore.Fingerprint]truststore.Constraints{
				fp: {SCTNotAfter: &deadline},
			},
		},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	r := results[0]
	if r.Trusted {
		t.Error("expected untrusted due to missing SCT")
	}
	t.Logf("FailureReason: %s", r.FailureReason)
}

func TestConstraintSCTNotAfterPasses(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCert(t, true, nil, nil)
	serverCert, _ := generateTestCert(t, false, caCert, caKey)

	// SCT issued YESTERDAY
	yesterday := time.Now().Add(-24 * time.Hour)
	chain := &truststore.CertChain{
		Endpoint:   "test.example.com",
		ServerCert: serverCert,
		SCTs: []truststore.SCT{
			{Timestamp: yesterday, Source: truststore.SCTSourceEmbedded},
		},
	}

	fp := truststore.FingerprintFromCert(caCert)

	// SCTNotAfter is TOMORROW - SCT issued before this should pass
	tomorrow := time.Now().Add(24 * time.Hour)
	stores := []truststore.Store{
		{
			Platform:     truststore.PlatformChrome,
			Version:      "current",
			Fingerprints: []truststore.Fingerprint{fp},
			Constraints: map[truststore.Fingerprint]truststore.Constraints{
				fp: {SCTNotAfter: &tomorrow},
			},
		},
	}

	registerTestCert(fp, caCert)
	defer unregisterTestCert(fp)

	results := ValidateChain(chain, stores)
	r := results[0]
	if !r.Trusted {
		t.Errorf("expected trusted, got failure: %s", r.FailureReason)
	}
}
