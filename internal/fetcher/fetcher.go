// Package fetcher provides TLS certificate chain fetching.
package fetcher

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ivoronin/certvet/internal/truststore"
)

// OID for SCT list extension in X.509 certificates (RFC 6962)
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// defaultTLSPort is the standard port for TLS connections.
const defaultTLSPort = "443"

// SCT parsing constants (RFC 6962)
const (
	sctVersion1         = 0  // SCT version 1 identifier
	sctLogIDSize        = 32 // Log ID is 32 bytes (SHA-256)
	sctTimestampSize    = 8  // Timestamp is 8 bytes (uint64)
	sctMinSize          = 45 // Minimum: version(1) + log_id(32) + timestamp(8) + extensions_len(2) + sig_len(2+)
	sctLogIDOffset      = 1  // Log ID starts at byte 1 (after version)
	sctTimestampOffset  = 33 // Timestamp starts at byte 33 (after log ID)
	sctLengthPrefixSize = 2  // Length prefix for SCT list entries
	msPerSecond         = 1000
	nsPerMs             = 1000000
)

// FetchCertChain connects to endpoint via TLS and returns the certificate chain.
// Endpoint can be "host" or "host:port" (default port 443).
// Also extracts Signed Certificate Timestamps (SCTs) from TLS extension and embedded in certificate.
func FetchCertChain(endpoint string, timeout time.Duration) (*truststore.CertChain, error) {
	// Normalize endpoint
	host := endpoint
	addr := endpoint
	if !strings.Contains(endpoint, ":") {
		addr = endpoint + ":" + defaultTLSPort
	} else {
		host = endpoint[:strings.LastIndex(endpoint, ":")]
	}

	// Connect with timeout
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // G402: Intentional - we validate against custom trust stores
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()

	// Get peer certificates
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates received from %s", endpoint)
	}

	chain := &truststore.CertChain{
		Endpoint:   host,
		ServerCert: certs[0],
	}

	if len(certs) > 1 {
		chain.Intermediates = certs[1:]
	}

	// Extract SCTs from TLS extension
	for _, sctBytes := range state.SignedCertificateTimestamps {
		if sct, err := parseSCT(sctBytes, truststore.SCTSourceTLS); err == nil {
			chain.SCTs = append(chain.SCTs, sct)
		}
	}

	// Extract embedded SCTs from server certificate
	embeddedSCTs := extractEmbeddedSCTs(certs[0])
	chain.SCTs = append(chain.SCTs, embeddedSCTs...)

	return chain, nil
}

// parseSCT parses an SCT from raw bytes (RFC 6962 format).
// Returns the SCT with timestamp and log ID extracted.
func parseSCT(data []byte, source truststore.SCTSource) (truststore.SCT, error) {
	if len(data) < sctMinSize {
		return truststore.SCT{}, fmt.Errorf("SCT too short: %d bytes", len(data))
	}

	// Version (1 byte) - must be 0 for v1
	version := data[0]
	if version != sctVersion1 {
		return truststore.SCT{}, fmt.Errorf("unsupported SCT version: %d", version)
	}

	// Log ID (32 bytes)
	var logID [sctLogIDSize]byte
	copy(logID[:], data[sctLogIDOffset:sctLogIDOffset+sctLogIDSize])

	// Timestamp (8 bytes, big-endian milliseconds since Unix epoch)
	timestampMs := binary.BigEndian.Uint64(data[sctTimestampOffset : sctTimestampOffset+sctTimestampSize])
	//nolint:gosec // G115: Safe - SCT timestamps are within int64 range (years 1970-2262)
	timestamp := time.Unix(int64(timestampMs/msPerSecond), int64((timestampMs%msPerSecond)*nsPerMs)).UTC()

	return truststore.SCT{
		Timestamp: timestamp,
		LogID:     logID,
		Source:    source,
	}, nil
}

// extractEmbeddedSCTs extracts SCTs from certificate's SCT list extension.
func extractEmbeddedSCTs(cert *x509.Certificate) []truststore.SCT {
	if cert == nil {
		return nil
	}

	var scts []truststore.SCT

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSCTList) {
			continue
		}

		// The extension value is an OCTET STRING containing the SCT list
		var sctListBytes []byte
		if _, err := asn1.Unmarshal(ext.Value, &sctListBytes); err != nil {
			continue
		}

		// Parse SCT list (TLS format: 2-byte length prefix for list, then 2-byte length prefix for each SCT)
		if len(sctListBytes) < sctLengthPrefixSize {
			continue
		}

		listLen := int(binary.BigEndian.Uint16(sctListBytes[0:sctLengthPrefixSize]))
		if len(sctListBytes) < sctLengthPrefixSize+listLen {
			continue
		}

		offset := sctLengthPrefixSize
		for offset < sctLengthPrefixSize+listLen {
			if offset+sctLengthPrefixSize > len(sctListBytes) {
				break
			}
			sctLen := int(binary.BigEndian.Uint16(sctListBytes[offset : offset+sctLengthPrefixSize]))
			offset += sctLengthPrefixSize

			if offset+sctLen > len(sctListBytes) {
				break
			}
			sctData := sctListBytes[offset : offset+sctLen]
			offset += sctLen

			if sct, err := parseSCT(sctData, truststore.SCTSourceEmbedded); err == nil {
				scts = append(scts, sct)
			}
		}
	}

	return scts
}
