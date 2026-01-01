package truststore

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// validSHA256 is a valid 64-char hex string for testing.
const validSHA256 = "D7A7A0FB5D7E2731D7A7A0FB5D7E2731D7A7A0FB5D7E2731D7A7A0FB5D7E2731"
const validSHA256Formatted = "D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31"

func TestParseFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "no separators (CCADB style)",
			input: validSHA256,
			want:  validSHA256Formatted,
		},
		{
			name:  "space separated (Apple style)",
			input: "D7 A7 A0 FB 5D 7E 27 31 D7 A7 A0 FB 5D 7E 27 31 D7 A7 A0 FB 5D 7E 27 31 D7 A7 A0 FB 5D 7E 27 31",
			want:  validSHA256Formatted,
		},
		{
			name:  "colon separated",
			input: validSHA256Formatted,
			want:  validSHA256Formatted,
		},
		{
			name:  "dash separated",
			input: "D7-A7-A0-FB-5D-7E-27-31-D7-A7-A0-FB-5D-7E-27-31-D7-A7-A0-FB-5D-7E-27-31-D7-A7-A0-FB-5D-7E-27-31",
			want:  validSHA256Formatted,
		},
		{
			name:  "lowercase",
			input: "d7a7a0fb5d7e2731d7a7a0fb5d7e2731d7a7a0fb5d7e2731d7a7a0fb5d7e2731",
			want:  validSHA256Formatted,
		},
		{
			name:  "mixed case",
			input: "D7a7A0fb5D7e2731D7a7A0fb5D7e2731D7a7A0fb5D7e2731D7a7A0fb5D7e2731",
			want:  validSHA256Formatted,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "invalid character",
			input:   "D7A7A0FB5D7E2731D7A7A0FB5D7E2731D7A7A0FB5D7E2731D7A7A0FB5D7E273Z",
			wantErr: true,
		},
		{
			name:    "too short",
			input:   "D7A7A0FB",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   validSHA256 + "FF",
			wantErr: true,
		},
		// Strict validation tests - these must be rejected
		{
			name:    "double separator",
			input:   "D7::A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31",
			wantErr: true,
		},
		{
			name:    "incomplete pair at start",
			input:   "D:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31",
			wantErr: true,
		},
		{
			name:    "mixed separators colon and space",
			input:   "D7:A7 A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31",
			wantErr: true,
		},
		{
			name:    "mixed separators colon and dash",
			input:   "D7:A7-A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31",
			wantErr: true,
		},
		{
			name:    "trailing separator",
			input:   "D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:",
			wantErr: true,
		},
		{
			name:    "leading separator",
			input:   ":D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31:D7:A7:A0:FB:5D:7E:27:31",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFingerprint(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFingerprint(%q) expected error, got %q", tt.input, got.String())
				}
				return
			}
			if err != nil {
				t.Errorf("ParseFingerprint(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got.String() != tt.want {
				t.Errorf("ParseFingerprint(%q).String() = %q, want %q", tt.input, got.String(), tt.want)
			}
		})
	}
}

func TestFingerprintTruncate(t *testing.T) {
	fp, err := ParseFingerprint(validSHA256)
	if err != nil {
		t.Fatalf("ParseFingerprint: %v", err)
	}

	tests := []struct {
		name     string
		octets   int
		expected string
	}{
		{
			name:     "truncate to 4 octets",
			octets:   4,
			expected: "D7:A7:A0:FB...",
		},
		{
			name:     "truncate to 2 octets",
			octets:   2,
			expected: "D7:A7...",
		},
		{
			name:     "truncate to 32 (full length)",
			octets:   32,
			expected: validSHA256Formatted,
		},
		{
			name:     "truncate to more than 32",
			octets:   100,
			expected: validSHA256Formatted,
		},
		{
			name:     "truncate to 0",
			octets:   0,
			expected: "",
		},
		{
			name:     "truncate to negative",
			octets:   -1,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fp.Truncate(tt.octets)
			if result != tt.expected {
				t.Errorf("Fingerprint.Truncate(%d) = %q, want %q", tt.octets, result, tt.expected)
			}
		})
	}
}

func TestFingerprintFromBytes(t *testing.T) {
	bytes := make([]byte, 32)
	for i := range bytes {
		bytes[i] = byte(i)
	}

	fp := FingerprintFromBytes(bytes)
	expected := "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F"
	if fp.String() != expected {
		t.Errorf("FingerprintFromBytes.String() = %q, want %q", fp.String(), expected)
	}
}

func TestFingerprintFromCert(t *testing.T) {
	// GlobalSign Root CA - R3 certificate (known working)
	certPEM := `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	fp := FingerprintFromCert(cert)

	// String should be in correct format
	str := fp.String()
	if len(str) != 95 { // 32 pairs * 2 + 31 colons = 95
		t.Errorf("FingerprintFromCert.String() length = %d, want 95", len(str))
	}
}
