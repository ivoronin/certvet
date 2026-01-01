package generate

import (
	"os"
	"strings"
	"testing"
)

func TestExtractSTLFromCAB(t *testing.T) {
	t.Parallel()

	// Read the actual CAB file from testdata
	cabData, err := os.ReadFile("testdata/authroot.cab")
	if err != nil {
		t.Fatalf("read test CAB file: %v", err)
	}

	stlData, err := extractSTLFromCAB(cabData)
	if err != nil {
		t.Fatalf("extract STL: %v", err)
	}

	// STL should be non-empty
	if len(stlData) == 0 {
		t.Error("extracted STL is empty")
	}

	// STL files start with ASN.1 SEQUENCE tag (0x30) for PKCS7
	if stlData[0] != 0x30 {
		t.Errorf("STL doesn't start with SEQUENCE tag: got 0x%02X", stlData[0])
	}
}

func TestExtractSTLFromCABNoSTLFile(t *testing.T) {
	t.Parallel()

	// Test with invalid/empty CAB data - should error
	_, err := extractSTLFromCAB([]byte{})
	if err == nil {
		t.Error("expected error for empty CAB data")
	}
}

func TestParseCTL(t *testing.T) {
	t.Parallel()

	// Read the actual STL file from testdata
	stlData, err := os.ReadFile("testdata/authroot.stl")
	if err != nil {
		t.Fatalf("read test STL file: %v", err)
	}

	ctl, err := parseCTL(stlData)
	if err != nil {
		t.Fatalf("parse CTL: %v", err)
	}

	// Should find many trusted root certificates
	if len(ctl.Entries) == 0 {
		t.Error("no entries found")
	}

	// Track constraint counts for verification
	var withNotBefore, withDistrust int

	// Verify fingerprint format: uppercase colon-separated hex
	for i, entry := range ctl.Entries {
		fpStr := entry.Fingerprint.String()
		if len(fpStr) != 95 { // 32 bytes * 2 hex chars + 31 colons
			t.Errorf("fingerprint %d has invalid length %d: %s", i, len(fpStr), fpStr)
			continue
		}

		parts := strings.Split(fpStr, ":")
		if len(parts) != 32 {
			t.Errorf("fingerprint %d has %d parts, want 32: %s", i, len(parts), fpStr)
			continue
		}

		// Check each part is 2 uppercase hex chars
		for _, part := range parts {
			if len(part) != 2 {
				t.Errorf("fingerprint %d part %q is not 2 chars", i, part)
			}
			if part != strings.ToUpper(part) {
				t.Errorf("fingerprint %d part %q is not uppercase", i, part)
			}
		}

		// Track constraints
		if entry.NotBeforeMax != nil {
			withNotBefore++
		}
		if entry.DistrustDate != nil {
			withDistrust++
		}

		// Only check first few fingerprints in detail
		if i >= 3 {
			break
		}
	}

	// Log constraint counts for visibility
	t.Logf("Entries with NotBeforeMax: %d, with DistrustDate: %d", withNotBefore, withDistrust)
}

func TestParseCTLInvalidData(t *testing.T) {
	t.Parallel()

	// Test with invalid PKCS7 data
	_, err := parseCTL([]byte("not valid pkcs7"))
	if err == nil {
		t.Error("expected error for invalid PKCS7 data")
	}
}

func TestParseFiletime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		want    string // expected date in YYYY-MM-DD format (empty if error expected)
	}{
		{
			name:    "valid FILETIME Jan 1, 2020",
			data:    []byte{0x00, 0x00, 0x05, 0x69, 0x36, 0xc0, 0xd5, 0x01}, // 2020-01-01 00:00:00 UTC
			wantErr: false,
			want:    "2020-01-01",
		},
		{
			name:    "too short",
			data:    []byte{0x00, 0x70, 0x60, 0x5c},
			wantErr: true,
		},
		{
			name:    "zero FILETIME",
			data:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "too long",
			data:    []byte{0x00, 0x70, 0x60, 0x5c, 0xf5, 0xc4, 0xd5, 0x01, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseFiletime(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFiletime() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				gotDate := got.Format("2006-01-02")
				if gotDate != tt.want {
					t.Errorf("parseFiletime() = %s, want %s", gotDate, tt.want)
				}
			}
		})
	}
}
