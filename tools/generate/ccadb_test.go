package generate

import (
	"os"
	"testing"

	"github.com/ivoronin/certvet/internal/truststore"
)

func TestParseCCADBCSV(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/ccadb_sample.csv")
	if err != nil {
		t.Fatalf("open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	certs, err := ParseCCADBCSV(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("got %d certs, want 2", len(certs))
	}
}

func TestParseCCADBCSVFingerprint(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/ccadb_sample.csv")
	if err != nil {
		t.Fatalf("open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	certs, err := ParseCCADBCSV(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// First cert fingerprint should be normalized with colons
	want, _ := truststore.ParseFingerprint("4B:87:C6:E5:67:D2:C1:56:ED:B9:35:23:57:BD:8B:16:E9:7B:1B:BB:AA:5B:30:73:D7:F8:2D:50:5E:A0:FE:3D")
	if certs[0].Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", certs[0].Fingerprint.String(), want.String())
	}
}

func TestFilterValidCerts(t *testing.T) {
	t.Parallel()

	// Use a real GlobalSign Root CA certificate for testing
	testPEM := `-----BEGIN CERTIFICATE-----
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

	fp, _ := truststore.ParseFingerprint("4B:87:C6:E5:67:D2:C1:56:ED:B9:35:23:57:BD:8B:16:E9:7B:1B:BB:AA:5B:30:73:D7:F8:2D:50:5E:A0:FE:3D")
	certs := []CCADBCert{
		{Fingerprint: fp, PEM: testPEM},
	}

	valid := filterValidCerts(certs)

	if len(valid) != 1 {
		t.Errorf("got %d valid certs, want 1", len(valid))
	}

	if valid[0].Fingerprint != certs[0].Fingerprint { //nolint:gosec // G602: Safe - test verifies len(valid)==1 above
		t.Errorf("fingerprint mismatch: got %q, want %q", valid[0].Fingerprint.String(), certs[0].Fingerprint.String())
	}
}

func TestFilterValidCertsSkipsMalformed(t *testing.T) {
	t.Parallel()

	// Invalid cert should be skipped with a warning
	// Note: Using a properly formatted (but random) fingerprint for the test
	fp, _ := truststore.ParseFingerprint("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99")
	certs := []CCADBCert{
		{Fingerprint: fp, PEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"},
	}

	valid := filterValidCerts(certs)

	if len(valid) != 0 {
		t.Errorf("got %d valid certs, want 0 for malformed input", len(valid))
	}
}
