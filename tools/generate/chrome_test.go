package generate

import (
	"fmt"
	"testing"
	"time"

	"github.com/ivoronin/certvet/internal/truststore"
)

// Sample proto schema for testing
const sampleChromeProto = `
syntax = "proto3";
package chrome_root_store;

message RootStore {
    int32 version_major = 1;
    repeated TrustAnchor trust_anchors = 2;
}

message TrustAnchor {
    optional string sha256_hex = 2;
    repeated string ev_policy_oids = 3;
    repeated ConstraintSet constraints = 4;
    optional bool eutl = 6;
}

message ConstraintSet {
    optional int64 sct_not_after_sec = 1;
    optional string min_version = 3;
    optional string max_version_exclusive = 4;
}
`

// Sample textproto data matching Chrome Root Store format
const sampleChromeTextproto = `# Chrome Root Store
version_major: 28

# CN=Actalis Authentication Root CA
trust_anchors {
  sha256_hex: "55926084ec963a64b96e2abe01ce0ba86a64fbfebcc7aab5afc155b37fd76066"
  ev_policy_oids: "2.23.140.1.1"
  eutl: true
}

# CN=Amazon Root CA 1 - No constraints
trust_anchors {
  sha256_hex: "8ecde6884f3d87b1125ba31ac3fcb13d7016de7f57cc904fe1cb97c6ae98196e"
  ev_policy_oids: "2.23.140.1.1"
}

# CN=Buypass Class 2 Root CA - SCT constraint only
trust_anchors {
  sha256_hex: "9a114025197c5bb95d94e63d55cd43790847b646b23cdf11ada4a00eff15fb48"
  constraints: {
    sct_not_after_sec: 1761955199
  }
}

# CN=Chunghwa Telecom - Multiple constraint blocks (AND logic)
trust_anchors {
  sha256_hex: "c0a6f4dc63a24bfdcf54ef2a6a082a0a72de35803e2ff5ff527ae5d87206dfd5"
  constraints: {
    sct_not_after_sec: 1754006399
    min_version: "139"
  }
  constraints: {
    max_version_exclusive: "139"
  }
}

# CN=Entrust Root CA - SCT constraint (Entrust distrust example)
trust_anchors {
  sha256_hex: "db3517d1f6732a2d5ab97c533ec70779ee3270a62fb4ac4238372460e6f01e88"
  constraints: {
    sct_not_after_sec: 1731283199
  }
}
`

func TestParseChromeTextproto(t *testing.T) {
	t.Parallel()

	version, anchors, err := ParseChromeTextproto([]byte(sampleChromeProto), []byte(sampleChromeTextproto))
	if err != nil {
		t.Fatalf("ParseChromeTextproto failed: %v", err)
	}

	// Check version
	if version != 28 {
		t.Errorf("version = %d, want 28", version)
	}

	// Check number of anchors
	if len(anchors) != 5 {
		t.Fatalf("got %d anchors, want 5", len(anchors))
	}

	// Verify first anchor (Actalis) - fingerprint normalized
	actalis := anchors[0]
	wantFP, _ := truststore.ParseFingerprint("55:92:60:84:EC:96:3A:64:B9:6E:2A:BE:01:CE:0B:A8:6A:64:FB:FE:BC:C7:AA:B5:AF:C1:55:B3:7F:D7:60:66")
	if actalis.Fingerprint != wantFP {
		t.Errorf("Actalis fingerprint = %q, want %q", actalis.Fingerprint.String(), wantFP.String())
	}
	if !actalis.EUTL {
		t.Error("Actalis should have EUTL=true")
	}
	if len(actalis.EVPolicyOIDs) != 1 || actalis.EVPolicyOIDs[0] != "2.23.140.1.1" {
		t.Errorf("Actalis EVPolicyOIDs = %v, want [2.23.140.1.1]", actalis.EVPolicyOIDs)
	}

	// Verify Amazon (no constraints)
	amazon := anchors[1]
	if len(amazon.Constraints) != 0 {
		t.Errorf("Amazon should have 0 constraints, got %d", len(amazon.Constraints))
	}

	// Verify Buypass (SCT constraint only)
	buypass := anchors[2]
	if len(buypass.Constraints) != 1 {
		t.Fatalf("Buypass should have 1 constraint, got %d", len(buypass.Constraints))
	}
	if buypass.Constraints[0].SCTNotAfterSec != 1761955199 {
		t.Errorf("Buypass SCTNotAfterSec = %d, want 1761955199", buypass.Constraints[0].SCTNotAfterSec)
	}

	// Verify Chunghwa (multiple constraints - AND logic)
	chunghwa := anchors[3]
	if len(chunghwa.Constraints) != 2 {
		t.Fatalf("Chunghwa should have 2 constraints, got %d", len(chunghwa.Constraints))
	}
	// First constraint: sct_not_after + min_version
	if chunghwa.Constraints[0].SCTNotAfterSec != 1754006399 {
		t.Errorf("Chunghwa first constraint SCTNotAfterSec = %d, want 1754006399", chunghwa.Constraints[0].SCTNotAfterSec)
	}
	if chunghwa.Constraints[0].MinVersion != "139" {
		t.Errorf("Chunghwa first constraint MinVersion = %q, want \"139\"", chunghwa.Constraints[0].MinVersion)
	}
	// Second constraint: max_version_exclusive
	if chunghwa.Constraints[1].MaxVersionExcl != "139" {
		t.Errorf("Chunghwa second constraint MaxVersionExcl = %q, want \"139\"", chunghwa.Constraints[1].MaxVersionExcl)
	}
}

func TestParseChromeTextproto_InvalidFormat(t *testing.T) {
	t.Parallel()

	_, _, err := ParseChromeTextproto([]byte(sampleChromeProto), []byte("this is not valid textproto"))
	if err == nil {
		t.Error("expected error for invalid textproto, got nil")
	}
}

func TestParseChromeTextproto_EmptyInput(t *testing.T) {
	t.Parallel()

	_, _, err := ParseChromeTextproto([]byte(sampleChromeProto), []byte(""))
	if err == nil {
		t.Error("expected error for empty input, got nil")
	}
}

// testFP creates a fingerprint from a short hex pattern (for tests only).
// Pads the pattern to 32 bytes for valid fingerprint.
func testFP(pattern string) truststore.Fingerprint {
	// Create a 32-byte fingerprint from pattern (e.g., "AA" -> AA:AA:AA:...:AA)
	var fp truststore.Fingerprint
	if len(pattern) >= 2 {
		b := byte(0)
		_, _ = fmt.Sscanf(pattern[:2], "%02X", &b)
		for i := range fp {
			fp[i] = b
		}
	}
	return fp
}

func TestSynthesizeVersions(t *testing.T) {
	t.Parallel()

	anchors := []ChromeTrustAnchor{
		{
			Fingerprint: testFP("AA"),
			// No constraints
		},
		{
			Fingerprint: testFP("BB"),
			Constraints: []ChromeConstraint{
				{MinVersion: "139"},
			},
		},
		{
			Fingerprint: testFP("CC"),
			Constraints: []ChromeConstraint{
				{MaxVersionExcl: "140"},
			},
		},
		{
			Fingerprint: testFP("DD"),
			Constraints: []ChromeConstraint{
				{MinVersion: "138"},
				{MaxVersionExcl: "141"},
			},
		},
	}

	versions := SynthesizeVersions(anchors)

	// Expected: boundary versions derived from constraints + "current"
	// min_version 139 → add 138, 139
	// min_version 138 → add 137, 138
	// max_version_exclusive 140 → add 139, 140
	// max_version_exclusive 141 → add 140, 141
	// Deduplicated and sorted: [137, 138, 139, 140, 141, current]
	// But we only care about the boundaries, so: [137, 138, 139, 140, 141, current]

	if len(versions) == 0 {
		t.Fatal("SynthesizeVersions returned empty slice")
	}

	// Check "current" is last
	if versions[len(versions)-1] != "current" {
		t.Errorf("last version = %q, want \"current\"", versions[len(versions)-1])
	}

	// Check contains expected boundary versions
	versionSet := make(map[string]bool)
	for _, v := range versions {
		versionSet[v] = true
	}

	expectedVersions := []string{"138", "139", "current"}
	for _, expected := range expectedVersions {
		if !versionSet[expected] {
			t.Errorf("expected version %q not found in %v", expected, versions)
		}
	}
}

// TestIsTrustedInVersion_NoConstraints tests that a cert without constraints is trusted in all versions
func TestIsTrustedInVersion_NoConstraints(t *testing.T) {
	t.Parallel()

	anchor := ChromeTrustAnchor{
		Fingerprint: testFP("AA"),
		// No constraints - unconditionally trusted
	}

	// Should be trusted in any version
	for _, version := range []string{"100", "138", "139", "200", "current"} {
		if !isTrustedInVersion(&anchor, version) {
			t.Errorf("anchor with no constraints should be trusted in version %q", version)
		}
	}
}

// TestIsTrustedInVersion_MinVersion tests MinVersion constraint evaluation
func TestIsTrustedInVersion_MinVersion(t *testing.T) {
	t.Parallel()

	anchor := ChromeTrustAnchor{
		Fingerprint: testFP("AA"),
		Constraints: []ChromeConstraint{
			{MinVersion: "139"}, // Trusted only in version >= 139
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"138", false},    // Below min version
		{"139", true},     // Equal to min version
		{"140", true},     // Above min version
		{"current", true}, // "current" is always >= any numeric version
	}

	for _, tt := range tests {
		got := isTrustedInVersion(&anchor, tt.version)
		if got != tt.want {
			t.Errorf("isTrustedInVersion(MinVersion=139, %q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

// TestIsTrustedInVersion_MaxVersionExcl tests MaxVersionExcl constraint evaluation
func TestIsTrustedInVersion_MaxVersionExcl(t *testing.T) {
	t.Parallel()

	anchor := ChromeTrustAnchor{
		Fingerprint: testFP("AA"),
		Constraints: []ChromeConstraint{
			{MaxVersionExcl: "140"}, // Trusted only in version < 140
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"138", true},      // Below max version
		{"139", true},      // Still below max version
		{"140", false},     // Equal to max version (exclusive)
		{"141", false},     // Above max version
		{"current", false}, // "current" is never < any MaxVersionExcl
	}

	for _, tt := range tests {
		got := isTrustedInVersion(&anchor, tt.version)
		if got != tt.want {
			t.Errorf("isTrustedInVersion(MaxVersionExcl=140, %q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

// TestIsTrustedInVersion_SCTOnly tests that SCT-only constraints are ignored (cert is trusted)
func TestIsTrustedInVersion_SCTOnly(t *testing.T) {
	t.Parallel()

	anchor := ChromeTrustAnchor{
		Fingerprint: testFP("AA"),
		Constraints: []ChromeConstraint{
			{SCTNotAfterSec: 1761955199}, // SCT constraint only, no version constraints
		},
	}

	// Per ADR-2: SCT constraints are ignored, so cert should be trusted in all versions
	for _, version := range []string{"100", "138", "139", "200", "current"} {
		if !isTrustedInVersion(&anchor, version) {
			t.Errorf("anchor with SCT-only constraint should be trusted in version %q (SCT ignored)", version)
		}
	}
}

// TestIsTrustedInVersion_MultipleConstraints tests OR logic between constraint blocks
func TestIsTrustedInVersion_MultipleConstraints(t *testing.T) {
	t.Parallel()

	// Certificate with two constraint blocks (OR logic):
	// Block 1: min_version=139 (trusted in 139+)
	// Block 2: max_version_exclusive=139 (trusted in <139)
	// Combined: trusted in ALL versions (one block always passes)
	anchor := ChromeTrustAnchor{
		Fingerprint: testFP("AA"),
		Constraints: []ChromeConstraint{
			{MinVersion: "139"},     // Passes for 139+
			{MaxVersionExcl: "139"}, // Passes for <139
		},
	}

	// OR logic: if ANY constraint block passes, the cert is trusted
	for _, version := range []string{"137", "138", "139", "140", "current"} {
		if !isTrustedInVersion(&anchor, version) {
			t.Errorf("anchor with OR constraints (>=139 OR <139) should be trusted in version %q", version)
		}
	}
}

// TestIsTrustedInVersion_MinMaxCombined tests a single constraint with both min and max version
func TestIsTrustedInVersion_MinMaxCombined(t *testing.T) {
	t.Parallel()

	// Certificate trusted only in specific version range: [138, 140)
	anchor := ChromeTrustAnchor{
		Fingerprint: testFP("AA"),
		Constraints: []ChromeConstraint{
			{MinVersion: "138", MaxVersionExcl: "140"}, // Trusted in 138 <= v < 140
		},
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"137", false},     // Below min
		{"138", true},      // Equal to min
		{"139", true},      // Within range
		{"140", false},     // Equal to max (exclusive)
		{"141", false},     // Above max
		{"current", false}, // current >= max, so not trusted
	}

	for _, tt := range tests {
		got := isTrustedInVersion(&anchor, tt.version)
		if got != tt.want {
			t.Errorf("isTrustedInVersion(Min=138,Max=140, %q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

// TestIsTrustedInVersion_CurrentVersion tests "current" version handling edge cases
func TestIsTrustedInVersion_CurrentVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		constraints []ChromeConstraint
		want        bool
	}{
		{
			name:        "no constraints",
			constraints: nil,
			want:        true,
		},
		{
			name:        "min version only",
			constraints: []ChromeConstraint{{MinVersion: "999"}},
			want:        true, // current >= any MinVersion
		},
		{
			name:        "max version only",
			constraints: []ChromeConstraint{{MaxVersionExcl: "999"}},
			want:        false, // current is NOT < any MaxVersionExcl
		},
		{
			name:        "SCT only",
			constraints: []ChromeConstraint{{SCTNotAfterSec: 1761955199}},
			want:        true, // SCT ignored
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			anchor := ChromeTrustAnchor{
				Fingerprint: testFP("AA"),
				Constraints: tt.constraints,
			}
			got := isTrustedInVersion(&anchor, "current")
			if got != tt.want {
				t.Errorf("isTrustedInVersion(%s, current) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestGenerateVersionMappedFingerprints tests the version-to-fingerprints mapping
func TestGenerateVersionMappedFingerprints(t *testing.T) {
	t.Parallel()

	anchors := []ChromeTrustAnchor{
		{
			Fingerprint: testFP("AA"), // No constraints - all versions
		},
		{
			Fingerprint: testFP("BB"),
			Constraints: []ChromeConstraint{
				{MinVersion: "139"}, // 139+ only
			},
		},
		{
			Fingerprint: testFP("CC"),
			Constraints: []ChromeConstraint{
				{MaxVersionExcl: "140"}, // <140 only
			},
		},
		{
			Fingerprint: testFP("DD"),
			Constraints: []ChromeConstraint{
				{SCTNotAfterSec: 1761955199}, // SCT only - treated as all versions
			},
		},
	}

	versions := []string{"138", "139", "140", "current"}
	result := generateVersionMappedFingerprints(anchors, versions)

	// Verify version 138: AA (all), CC (<140), DD (SCT ignored) = 3 certs
	if len(result["138"]) != 3 {
		t.Errorf("version 138 should have 3 fingerprints, got %d: %v", len(result["138"]), result["138"])
	}

	// Verify version 139: AA (all), BB (139+), CC (<140), DD (SCT ignored) = 4 certs
	if len(result["139"]) != 4 {
		t.Errorf("version 139 should have 4 fingerprints, got %d: %v", len(result["139"]), result["139"])
	}

	// Verify version 140: AA (all), BB (139+), DD (SCT ignored) = 3 certs (CC excluded)
	if len(result["140"]) != 3 {
		t.Errorf("version 140 should have 3 fingerprints, got %d: %v", len(result["140"]), result["140"])
	}

	// Verify "current": AA (all), BB (139+), DD (SCT ignored) = 3 certs (CC excluded)
	if len(result["current"]) != 3 {
		t.Errorf("version current should have 3 fingerprints, got %d: %v", len(result["current"]), result["current"])
	}

	// Verify specific fingerprints in version 139
	fingerprints := make(map[truststore.Fingerprint]bool)
	for _, fp := range result["139"] {
		fingerprints[fp] = true
	}
	expected := []truststore.Fingerprint{testFP("AA"), testFP("BB"), testFP("CC"), testFP("DD")}
	for _, fp := range expected {
		if !fingerprints[fp] {
			t.Errorf("version 139 missing fingerprint %q", fp.String())
		}
	}
}

// TestExtractSCTNotAfter tests extraction of SCT-only constraints
func TestExtractSCTNotAfter(t *testing.T) {
	t.Parallel()

	sctTimestamp := int64(1761955199) // Example: 2025-10-31 23:59:59 UTC

	tests := []struct {
		name     string
		anchor   ChromeTrustAnchor
		wantNil  bool
		wantUnix int64
	}{
		{
			name: "no constraints",
			anchor: ChromeTrustAnchor{
				Fingerprint: testFP("AA"),
			},
			wantNil: true,
		},
		{
			name: "SCT-only constraint",
			anchor: ChromeTrustAnchor{
				Fingerprint: testFP("AA"),
				Constraints: []ChromeConstraint{
					{SCTNotAfterSec: sctTimestamp},
				},
			},
			wantNil:  false,
			wantUnix: sctTimestamp,
		},
		{
			name: "version-only constraint",
			anchor: ChromeTrustAnchor{
				Fingerprint: testFP("AA"),
				Constraints: []ChromeConstraint{
					{MinVersion: "139"},
				},
			},
			wantNil: true, // No SCT-only constraints
		},
		{
			name: "SCT with version constraint",
			anchor: ChromeTrustAnchor{
				Fingerprint: testFP("AA"),
				Constraints: []ChromeConstraint{
					{SCTNotAfterSec: sctTimestamp, MinVersion: "139"},
				},
			},
			wantNil: true, // Not SCT-only (has version constraint)
		},
		{
			name: "multiple blocks with one SCT-only",
			anchor: ChromeTrustAnchor{
				Fingerprint: testFP("AA"),
				Constraints: []ChromeConstraint{
					{MinVersion: "139"},
					{SCTNotAfterSec: sctTimestamp}, // SCT-only block
				},
			},
			wantNil:  false,
			wantUnix: sctTimestamp,
		},
		{
			name: "multiple SCT-only blocks returns latest",
			anchor: ChromeTrustAnchor{
				Fingerprint: testFP("AA"),
				Constraints: []ChromeConstraint{
					{SCTNotAfterSec: 1000000000},   // Earlier
					{SCTNotAfterSec: sctTimestamp}, // Later (should be returned)
				},
			},
			wantNil:  false,
			wantUnix: sctTimestamp, // Most permissive (latest) timestamp
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := extractSCTNotAfter(&tt.anchor)

			if tt.wantNil {
				if got != nil {
					t.Errorf("extractSCTNotAfter() = %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("extractSCTNotAfter() = nil, want non-nil")
			}

			if got.Unix() != tt.wantUnix {
				t.Errorf("extractSCTNotAfter().Unix() = %d, want %d", got.Unix(), tt.wantUnix)
			}

			// Verify it's in UTC
			if got.Location() != time.UTC {
				t.Errorf("extractSCTNotAfter() location = %v, want UTC", got.Location())
			}
		})
	}
}
