package truststore

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

// Fingerprint represents a SHA-256 certificate fingerprint.
// Stored as raw bytes internally, formatted on demand.
type Fingerprint [sha256.Size]byte

// sha256Pairs is the expected number of hex pairs in a SHA-256 fingerprint.
const sha256Pairs = 32

// rawHexRe matches raw hex format (64 hex chars, no separators).
var rawHexRe = regexp.MustCompile(`^[0-9A-Fa-f]{64}$`)

// separatorRe matches valid separator-delimited formats with consistent separators.
// Requires exactly 32 hex pairs with the SAME separator throughout.
var separatorRe = regexp.MustCompile(`^[0-9A-Fa-f]{2}([:][0-9A-Fa-f]{2}){31}$|^[0-9A-Fa-f]{2}([-][0-9A-Fa-f]{2}){31}$|^[0-9A-Fa-f]{2}([ ][0-9A-Fa-f]{2}){31}$`)

// separatedGrammar defines the grammar for separator-delimited fingerprints.
//
// Grammar:
//
//	fingerprint := PAIR ( SEP PAIR )*
//	PAIR := [0-9A-Fa-f]{2}
//	SEP  := [: -]
type separatedGrammar struct {
	Pairs []string `parser:"@Pair ( Sep @Pair )*"`
}

var separatedLexer = lexer.MustSimple([]lexer.SimpleRule{
	{Name: "Pair", Pattern: `[0-9A-Fa-f]{2}`},
	{Name: "Sep", Pattern: `[: -]`}, // Exactly one separator char
})

var separatedParser = participle.MustBuild[separatedGrammar](
	participle.Lexer(separatedLexer),
	// No Elide - strict parsing, no silent skipping
)

// ParseFingerprint creates a Fingerprint from various string formats.
//
// Accepts two formats:
//   - Raw hex: exactly 64 hex chars (e.g., "d7a7a0fb...")
//   - Separated: 32 hex pairs with consistent separator (e.g., "D7:A7:A0:FB:...")
//
// Rejects malformed inputs like mixed separators, double separators, or incomplete pairs.
func ParseFingerprint(input string) (Fingerprint, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return Fingerprint{}, fmt.Errorf("empty fingerprint")
	}

	var hexStr string

	// Try raw hex format first (64 hex chars, no separators)
	if rawHexRe.MatchString(input) {
		hexStr = input
	} else {
		// Validate separator-delimited format with consistent separators
		if !separatorRe.MatchString(input) {
			return Fingerprint{}, fmt.Errorf("invalid fingerprint format: must be 64 hex chars or 32 hex pairs with consistent separator")
		}

		// Parse the validated input
		fp, err := separatedParser.ParseString("", input)
		if err != nil {
			return Fingerprint{}, fmt.Errorf("invalid fingerprint format: %w", err)
		}

		if len(fp.Pairs) != sha256Pairs {
			return Fingerprint{}, fmt.Errorf("invalid fingerprint length: got %d pairs, want %d", len(fp.Pairs), sha256Pairs)
		}

		hexStr = strings.Join(fp.Pairs, "")
	}

	// Decode hex to bytes
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("invalid hex: %w", err)
	}

	var f Fingerprint
	copy(f[:], bytes)
	return f, nil
}

// FingerprintFromCert computes the SHA-256 fingerprint of a certificate.
func FingerprintFromCert(cert *x509.Certificate) Fingerprint {
	return Fingerprint(sha256.Sum256(cert.Raw))
}

// FingerprintFromBytes creates a Fingerprint from raw bytes.
// Panics if bytes is not exactly 32 bytes.
func FingerprintFromBytes(bytes []byte) Fingerprint {
	if len(bytes) != sha256.Size {
		panic(fmt.Sprintf("fingerprint must be %d bytes, got %d", sha256.Size, len(bytes)))
	}
	var f Fingerprint
	copy(f[:], bytes)
	return f
}

// String returns the canonical "AA:BB:CC:DD:..." format.
func (f Fingerprint) String() string {
	parts := make([]string, len(f))
	for i, b := range f {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// IsZero returns true if the fingerprint is all zeros (uninitialized).
func (f Fingerprint) IsZero() bool {
	return f == Fingerprint{}
}

// Truncate returns a truncated display string with the specified number of octets.
// Example: Truncate(4) → "AA:BB:CC:DD..."
func (f Fingerprint) Truncate(octets int) string {
	if octets <= 0 {
		return ""
	}
	if octets >= len(f) {
		return f.String()
	}

	parts := make([]string, octets)
	for i := 0; i < octets; i++ {
		parts[i] = fmt.Sprintf("%02X", f[i])
	}
	return strings.Join(parts, ":") + "..."
}
