// Package generate provides trust store generation tools.
package generate

import (
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ivoronin/certvet/internal/truststore"
)

const ccadbBaseURL = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat"

// ccadbDecades lists all decades to fetch certificates from.
var ccadbDecades = []string{"1990", "2000", "2010", "2020"}

// CCADBGenerator implements CertGenerator for CCADB certificate data.
type CCADBGenerator struct{}

// Name returns the generator's display name.
func (CCADBGenerator) Name() string { return "CCADB" }

// Generate fetches CCADB certificates and returns them as Certificate structs.
func (CCADBGenerator) Generate() ([]Certificate, error) {
	certs, err := FetchCCADB()
	if err != nil {
		return nil, err
	}

	return filterValidCerts(certs), nil
}

// filterValidCerts filters out invalid certificates and converts to Certificate type.
func filterValidCerts(certs []CCADBCert) []Certificate {
	var valid []Certificate
	for _, cert := range certs {
		block, _ := pem.Decode([]byte(cert.PEM))
		if block == nil {
			Log.Warn("skipping cert %s: failed to decode PEM", cert.Fingerprint.Truncate(4))
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			Log.Warn("skipping cert %s: %v", cert.Fingerprint.Truncate(4), err)
			continue
		}
		valid = append(valid, Certificate(cert))
	}
	return valid
}

// CCADBCert holds a certificate from CCADB.
type CCADBCert struct {
	Fingerprint truststore.Fingerprint // SHA-256 fingerprint
	PEM         string                 // Raw PEM data
}

// FetchCCADB downloads and parses the CCADB certificate bundle from all decades.
func FetchCCADB() ([]CCADBCert, error) {
	seen := make(map[truststore.Fingerprint]bool)
	var allCerts []CCADBCert

	for _, decade := range ccadbDecades {
		url := fmt.Sprintf("%s?NotBeforeDecade=%s", ccadbBaseURL, decade)
		resp, err := httpClient.Get(url)
		if err != nil {
			return nil, fmt.Errorf("fetch CCADB decade %s: %w", decade, err)
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("CCADB decade %s returned status %d", decade, resp.StatusCode)
		}

		certs, err := ParseCCADBCSV(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("parse CCADB decade %s: %w", decade, err)
		}

		// Deduplicate by fingerprint
		for _, cert := range certs {
			if !seen[cert.Fingerprint] {
				seen[cert.Fingerprint] = true
				allCerts = append(allCerts, cert)
			}
		}
	}

	return allCerts, nil
}

// ParseCCADBCSV parses CCADB CSV format from a reader.
func ParseCCADBCSV(r io.Reader) ([]CCADBCert, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = 2
	reader.LazyQuotes = true

	// Skip header
	_, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	var certs []CCADBCert
	lineNum := 1 // Header was line 1
	for {
		lineNum++
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: read record: %w", lineNum, err)
		}

		// CCADB fingerprints are uppercase hex, no separators
		fingerprint, err := truststore.ParseFingerprint(record[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid fingerprint: %w", lineNum, err)
		}

		pem := strings.TrimSpace(record[1])
		if !strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----") {
			return nil, fmt.Errorf("line %d: invalid PEM data", lineNum)
		}

		certs = append(certs, CCADBCert{
			Fingerprint: fingerprint,
			PEM:         pem,
		})
	}

	return certs, nil
}
