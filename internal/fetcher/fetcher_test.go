package fetcher

import (
	"strings"
	"testing"
	"time"
)

// Unit tests - no network access required

func TestParseSCT(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "too short",
			data:      make([]byte, 10),
			wantErr:   true,
			errSubstr: "too short",
		},
		{
			name: "wrong version",
			data: func() []byte {
				data := make([]byte, 50)
				data[0] = 1 // version 1 instead of 0
				return data
			}(),
			wantErr:   true,
			errSubstr: "unsupported SCT version",
		},
		{
			name: "valid SCT v1",
			data: func() []byte {
				// Build a minimal valid SCT:
				// - version: 0 (1 byte)
				// - log_id: 32 bytes
				// - timestamp: 8 bytes (big-endian ms since epoch)
				// - extensions_length: 2 bytes
				// - signature: 2+ bytes
				data := make([]byte, 50)
				data[0] = 0 // version 0

				// Log ID: some recognizable pattern
				for i := 1; i <= 32; i++ {
					data[i] = byte(i)
				}

				// Timestamp: 1000 ms = 1970-01-01 00:00:01 UTC
				// 1000 in big-endian = 0x00_00_00_00_00_00_03_E8
				data[33] = 0x00
				data[34] = 0x00
				data[35] = 0x00
				data[36] = 0x00
				data[37] = 0x00
				data[38] = 0x00
				data[39] = 0x03
				data[40] = 0xE8

				return data
			}(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sct, err := parseSCT(tt.data, 0)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify parsed values for valid case
			if tt.name == "valid SCT v1" {
				// Verify log ID
				for i := 0; i < 32; i++ {
					if sct.LogID[i] != byte(i+1) {
						t.Errorf("LogID[%d] = %d, want %d", i, sct.LogID[i], i+1)
					}
				}

				// Verify timestamp: 1000ms = 1 second after Unix epoch
				expected := time.Date(1970, 1, 1, 0, 0, 1, 0, time.UTC)
				if !sct.Timestamp.Equal(expected) {
					t.Errorf("Timestamp = %v, want %v", sct.Timestamp, expected)
				}
			}
		})
	}
}

