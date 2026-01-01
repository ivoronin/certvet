package truststore

import (
	"crypto/x509"
	"embed"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"time"
)

//go:embed data/certificates.csv data/stores.csv
var dataFS embed.FS

// Certs maps fingerprints to their parsed x509 certificates.
var Certs = make(map[Fingerprint]*x509.Certificate)

// Stores contains all trust stores for all platforms and versions.
var Stores []Store

func init() {
	if err := loadCertificates(); err != nil {
		panic(fmt.Sprintf("failed to load certificates: %v", err))
	}

	if err := loadStores(); err != nil {
		panic(fmt.Sprintf("failed to load stores: %v", err))
	}
}

// openFile opens a file from the embedded FS and returns a reader.
func openFile(name string) (io.Reader, func(), error) {
	f, err := dataFS.Open(name)
	if err != nil {
		return nil, nil, err
	}

	cleanup := func() {
		_ = f.Close()
	}

	return f, cleanup, nil
}

// loadCertificates parses certificates from the embedded CSV.
func loadCertificates() error {
	reader, cleanup, err := openFile("data/certificates.csv")
	if err != nil {
		return err
	}
	defer cleanup()

	r := csv.NewReader(reader)

	// Skip header
	if _, err := r.Read(); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read record: %w", err)
		}

		fpStr := record[0]
		// Unescape newlines (stored as literal \n for single-line CSV records)
		pemData := strings.ReplaceAll(record[1], "\\n", "\n")

		fp, err := ParseFingerprint(fpStr)
		if err != nil {
			return fmt.Errorf("parse fingerprint %s: %w", fpStr, err)
		}

		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			return fmt.Errorf("failed to decode PEM for %s", fpStr)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse cert %s: %w", fpStr, err)
		}

		Certs[fp] = cert
	}

	return nil
}

// storeKey identifies a unique platform+version combination.
type storeKey struct {
	platform Platform
	version  string
}

// storeEntry holds parsed data for a single trust store CSV record.
type storeEntry struct {
	fingerprint Fingerprint
	constraints Constraints
}

// parseConstraintColumns extracts date constraints from CSV record columns 3-5.
func parseConstraintColumns(record []string) (Constraints, error) {
	var c Constraints

	if len(record) > 3 && record[3] != "" {
		t, err := time.Parse(time.RFC3339, record[3])
		if err != nil {
			return c, fmt.Errorf("parse not_before_max %s: %w", record[3], err)
		}
		c.NotBeforeMax = &t
	}
	if len(record) > 4 && record[4] != "" {
		t, err := time.Parse(time.RFC3339, record[4])
		if err != nil {
			return c, fmt.Errorf("parse distrust_date %s: %w", record[4], err)
		}
		c.DistrustDate = &t
	}
	if len(record) > 5 && record[5] != "" {
		t, err := time.Parse(time.RFC3339, record[5])
		if err != nil {
			return c, fmt.Errorf("parse sct_not_after %s: %w", record[5], err)
		}
		c.SCTNotAfter = &t
	}
	return c, nil
}

// parseStoreRecords reads CSV records and groups them by platform+version.
func parseStoreRecords(r *csv.Reader) (map[storeKey][]storeEntry, error) {
	result := make(map[storeKey][]storeEntry)

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read record: %w", err)
		}

		platform := Platform(record[0])
		version := record[1]
		fpStr := record[2]

		fp, err := ParseFingerprint(fpStr)
		if err != nil {
			return nil, fmt.Errorf("parse fingerprint %s: %w", fpStr, err)
		}

		constraints, err := parseConstraintColumns(record)
		if err != nil {
			return nil, err
		}

		key := storeKey{platform, version}
		result[key] = append(result[key], storeEntry{fp, constraints})
	}
	return result, nil
}

// buildStore converts grouped entries into a Store.
func buildStore(key storeKey, entries []storeEntry) Store {
	store := Store{
		Platform:     key.platform,
		Version:      key.version,
		Fingerprints: make([]Fingerprint, len(entries)),
	}

	for i, e := range entries {
		store.Fingerprints[i] = e.fingerprint
		if !e.constraints.IsEmpty() {
			if store.Constraints == nil {
				store.Constraints = make(map[Fingerprint]Constraints)
			}
			store.Constraints[e.fingerprint] = e.constraints
		}
	}
	return store
}

// loadStores builds trust stores from the embedded CSV.
// CSV format: platform,version,fingerprint,not_before_max,distrust_date,sct_not_after
func loadStores() error {
	reader, cleanup, err := openFile("data/stores.csv")
	if err != nil {
		return err
	}
	defer cleanup()

	r := csv.NewReader(reader)

	// Skip header
	if _, err := r.Read(); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	storeMap, err := parseStoreRecords(r)
	if err != nil {
		return err
	}

	for key, entries := range storeMap {
		Stores = append(Stores, buildStore(key, entries))
	}

	return nil
}
