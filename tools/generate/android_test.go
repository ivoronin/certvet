package generate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"

	"github.com/ivoronin/certvet/internal/truststore"
)

func TestParseAndroidRefs(t *testing.T) {
	t.Parallel()

	// Read plain text (matching real API format)
	plaintext, err := os.ReadFile("testdata/android_refs.txt")
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}

	r := strings.NewReader(string(plaintext))

	versions, err := ParseAndroidRefs(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Should find Android 7-14 (8 versions)
	if len(versions) != 8 {
		t.Errorf("got %d versions, want 8", len(versions))
	}

	// First should be highest version (14)
	if versions[0].Version != "14" {
		t.Errorf("first version = %s, want 14", versions[0].Version)
	}
	if versions[0].Branch != "android14-release" {
		t.Errorf("first branch = %q, want android14-release", versions[0].Branch)
	}

	// Check codename versions are included
	found7 := false
	for _, v := range versions {
		if v.Version == "7" && v.Branch == "nougat-mr2-release" {
			found7 = true
			break
		}
	}
	if !found7 {
		t.Error("Android 7 (nougat) not found")
	}
}

func TestParseAndroidArchive(t *testing.T) {
	t.Parallel()

	// Create a minimal tar.gz with a test certificate
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	// GlobalSign Root CA - R3 certificate (same as in CCADB test)
	pemData := []byte(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`)

	hdr := &tar.Header{
		Name: "02265526.0",
		Mode: 0644,
		Size: int64(len(pemData)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(pemData); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}

	fingerprints, err := ParseAndroidArchive(&buf)
	if err != nil {
		t.Fatalf("parse archive: %v", err)
	}

	if len(fingerprints) != 1 {
		t.Errorf("got %d fingerprints, want 1", len(fingerprints))
	}

	// Expected fingerprint for GlobalSign Root CA - R3 (computed from the actual PEM)
	want, _ := truststore.ParseFingerprint("CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B")
	if fingerprints[0] != want {
		t.Errorf("fingerprint = %q, want %q", fingerprints[0].String(), want.String())
	}
}
