package generate

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-cabfile/cabfile"
	"github.com/ivoronin/certvet/internal/truststore"
	"go.mozilla.org/pkcs7"
)

const (
	// Windows Update CDN URL for Certificate Trust List
	windowsAuthrootURL = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
)

// Microsoft CTL OIDs
var (
	// OIDMicrosoftCTL is the OID for Microsoft Certificate Trust List content type.
	OIDMicrosoftCTL = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}

	// OIDSHA256Fingerprint is the OID for SHA-256 certificate fingerprint attribute.
	OIDSHA256Fingerprint = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 11, 98}

	// OIDSHA1Fingerprint is the OID for SHA-1 certificate fingerprint attribute.
	OIDSHA1Fingerprint = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 11, 20}

	// OIDNotBeforeFiletime is the OID for NotBefore constraint (certs issued after this date not trusted).
	OIDNotBeforeFiletime = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 11, 126}

	// OIDDisallowedFiletime is the OID for Disallowed constraint (CA completely distrusted after this date).
	OIDDisallowedFiletime = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 11, 104}
)

// windowsEntry holds extracted data for a single Windows CTL entry.
type windowsEntry struct {
	Fingerprint  truststore.Fingerprint
	NotBeforeMax *time.Time // OID .126: certs issued after this not trusted
	DistrustDate *time.Time // OID .104: CA completely distrusted after this
}

// CTL represents a parsed Microsoft Certificate Trust List.
type CTL struct {
	// Entries contains the parsed CTL entries with fingerprints and constraints.
	Entries []windowsEntry
}

// ctlAttribute represents an attribute in a CTL entry.
type ctlAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// ctlEntry represents a trusted subject entry in the CTL.
type ctlEntry struct {
	SubjectIdentifier []byte         // SHA-1 hash of the certificate
	Attributes        []ctlAttribute `asn1:"set"`
}

// filetimeEpochOffset is the number of seconds between Windows FILETIME epoch (1601-01-01)
// and Unix epoch (1970-01-01).
const filetimeEpochOffset = 11644473600

// parseFiletime converts a Windows FILETIME (64-bit little-endian, 100-nanosecond intervals
// since 1601-01-01 UTC) to a Go time.Time.
func parseFiletime(data []byte) (time.Time, error) {
	if len(data) != 8 {
		return time.Time{}, fmt.Errorf("FILETIME must be 8 bytes, got %d", len(data))
	}

	// FILETIME is little-endian 64-bit value
	ft := binary.LittleEndian.Uint64(data)
	if ft == 0 {
		return time.Time{}, fmt.Errorf("zero FILETIME")
	}

	// Convert 100-nanosecond intervals to seconds and nanoseconds
	seconds := int64(ft/10000000) - filetimeEpochOffset
	nanoseconds := int64((ft % 10000000) * 100)

	return time.Unix(seconds, nanoseconds).UTC(), nil
}

// WindowsGenerator implements StoreGenerator for Windows trust store data.
type WindowsGenerator struct{}

// Name returns the generator's display name.
func (WindowsGenerator) Name() string { return "Windows" }

// Generate fetches Windows trust store data and returns TrustEntry structs.
func (WindowsGenerator) Generate() ([]TrustEntry, error) {
	trustedCAB, err := fetchCAB(windowsAuthrootURL)
	if err != nil {
		return nil, fmt.Errorf("fetch trusted roots: %w", err)
	}

	trustedSTL, err := extractSTLFromCAB(trustedCAB)
	if err != nil {
		return nil, fmt.Errorf("extract trusted STL: %w", err)
	}
	trustedCTL, err := parseCTL(trustedSTL)
	if err != nil {
		return nil, fmt.Errorf("parse trusted CTL: %w", err)
	}

	// Create TrustEntry for each entry (Windows has only "current" version)
	entries := make([]TrustEntry, len(trustedCTL.Entries))
	for i, we := range trustedCTL.Entries {
		entries[i] = TrustEntry{
			Platform:     "windows",
			Version:      "current",
			Fingerprint:  we.Fingerprint,
			NotBeforeMax: we.NotBeforeMax,
			DistrustDate: we.DistrustDate,
		}
	}

	return entries, nil
}

// fetchCAB downloads a CAB file from the given URL.
func fetchCAB(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return data, nil
}

// extractSTLFromCAB extracts the .stl file from a Microsoft CAB archive.
func extractSTLFromCAB(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	cab, err := cabfile.New(reader)
	if err != nil {
		return nil, fmt.Errorf("open cab: %w", err)
	}

	// Find the .stl file in the cabinet
	for _, name := range cab.FileList() {
		if strings.HasSuffix(strings.ToLower(name), ".stl") {
			content, err := cab.Content(name)
			if err != nil {
				return nil, fmt.Errorf("open %s in cab: %w", name, err)
			}

			stlData, err := io.ReadAll(content)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", name, err)
			}
			return stlData, nil
		}
	}

	return nil, fmt.Errorf("no .stl file found in cabinet")
}

// parseCTL parses a Microsoft Certificate Trust List from STL data.
// The STL file is PKCS7 SignedData containing the CTL ASN.1 structure.
func parseCTL(stlData []byte) (*CTL, error) {
	// Parse PKCS7 SignedData envelope
	p7, err := pkcs7.Parse(stlData)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs7: %w", err)
	}

	// The CTL content is an implicit SEQUENCE - elements are directly in the content
	// without an outer SEQUENCE wrapper. We parse elements individually.
	// Structure: SubjectUsage, SequenceNumber, ThisUpdate, SubjectAlgorithm, TrustedSubjects, [Extensions]
	content := p7.Content

	// Skip: SubjectUsage (SEQUENCE)
	var subjectUsage asn1.RawValue
	content, err = asn1.Unmarshal(content, &subjectUsage)
	if err != nil {
		return nil, fmt.Errorf("parse subject usage: %w", err)
	}

	// Skip: SequenceNumber (INTEGER)
	var seqNum asn1.RawValue
	content, err = asn1.Unmarshal(content, &seqNum)
	if err != nil {
		return nil, fmt.Errorf("parse sequence number: %w", err)
	}

	// Skip: ThisUpdate (UTCTime or GeneralizedTime)
	var thisUpdate asn1.RawValue
	content, err = asn1.Unmarshal(content, &thisUpdate)
	if err != nil {
		return nil, fmt.Errorf("parse this update: %w", err)
	}

	// Skip: SubjectAlgorithm (SEQUENCE)
	var subjectAlg asn1.RawValue
	content, err = asn1.Unmarshal(content, &subjectAlg)
	if err != nil {
		return nil, fmt.Errorf("parse subject algorithm: %w", err)
	}

	// Parse: TrustedSubjects (SEQUENCE OF TrustedSubject)
	var trustedSubjectsRaw asn1.RawValue
	_, err = asn1.Unmarshal(content, &trustedSubjectsRaw)
	if err != nil {
		return nil, fmt.Errorf("parse trusted subjects: %w", err)
	}

	// Parse individual entries from TrustedSubjects
	entries, err := parseTrustedSubjects(trustedSubjectsRaw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse trusted subject entries: %w", err)
	}

	// Extract windowsEntry from each CTL entry
	var windowsEntries []windowsEntry
	for _, entry := range entries {
		we, err := extractWindowsEntry(entry.Attributes)
		if err != nil {
			// Log warning but continue - some entries might not have SHA-256
			Log.Warn("skipping entry: %v", err)
			continue
		}
		windowsEntries = append(windowsEntries, we)
	}

	return &CTL{Entries: windowsEntries}, nil
}

// parseTrustedSubjects parses the SEQUENCE OF TrustedSubject entries.
func parseTrustedSubjects(data []byte) ([]ctlEntry, error) {
	var entries []ctlEntry

	for len(data) > 0 {
		var entry ctlEntry
		rest, err := asn1.Unmarshal(data, &entry)
		if err != nil {
			return nil, fmt.Errorf("unmarshal entry: %w", err)
		}
		entries = append(entries, entry)
		data = rest
	}

	return entries, nil
}

// extractWindowsEntry extracts fingerprint and constraints from CTL attributes.
// Uses two-pass processing to ensure fingerprint is available for error context.
func extractWindowsEntry(attrs []ctlAttribute) (windowsEntry, error) {
	var entry windowsEntry

	// First pass: extract fingerprint for error context
	for _, attr := range attrs {
		if attr.Type.Equal(OIDSHA256Fingerprint) {
			var fpBytes []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &fpBytes); err != nil {
				return windowsEntry{}, fmt.Errorf("unmarshal fingerprint bytes: %w", err)
			}
			entry.Fingerprint = truststore.FingerprintFromBytes(fpBytes)
			break
		}
	}

	if entry.Fingerprint.IsZero() {
		return windowsEntry{}, fmt.Errorf("no SHA-256 fingerprint found")
	}

	// Second pass: extract constraints with fingerprint context for warnings
	fpPrefix := entry.Fingerprint.Truncate(4)
	for _, attr := range attrs {
		switch {
		case attr.Type.Equal(OIDNotBeforeFiletime):
			// NotBefore constraint: certs issued after this date not trusted
			var ftBytes []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &ftBytes); err != nil {
				Log.Warn("cert %s: unmarshal NotBeforeFiletime: %v", fpPrefix, err)
				continue
			}
			t, err := parseFiletime(ftBytes)
			if err != nil {
				Log.Warn("cert %s: parse NotBeforeFiletime: %v", fpPrefix, err)
				continue
			}
			entry.NotBeforeMax = &t

		case attr.Type.Equal(OIDDisallowedFiletime):
			// Disallowed constraint: CA completely distrusted after this date
			var ftBytes []byte
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &ftBytes); err != nil {
				Log.Warn("cert %s: unmarshal DisallowedFiletime: %v", fpPrefix, err)
				continue
			}
			t, err := parseFiletime(ftBytes)
			if err != nil {
				Log.Warn("cert %s: parse DisallowedFiletime: %v", fpPrefix, err)
				continue
			}
			entry.DistrustDate = &t
		}
	}

	return entry, nil
}
