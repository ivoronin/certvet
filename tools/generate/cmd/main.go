// Command generate runs all trust store generators to regenerate CSV data files.
// Usage: go run ./tools/generate/cmd

//go:debug x509negativeserial=1

package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ivoronin/certvet/internal/version"
	"github.com/ivoronin/certvet/tools/generate"
)

const dataDir = "internal/truststore/data"

func main() {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil { //nolint:gosec // G301: 0755 is standard for data directories
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		os.Exit(1)
	}

	var failed bool

	// Collect all trust entries from vendor generators first
	// (we need fingerprints to filter certificates)
	var allEntries []generate.TrustEntry

	storeGenerators := []generate.StoreGenerator{
		generate.AppleGenerator{},
		generate.AndroidGenerator{},
		generate.ChromeGenerator{},
		generate.WindowsGenerator{},
	}

	for _, g := range storeGenerators {
		name := g.Name()
		fmt.Printf("Generating %s trust stores...\n", name)

		entries, err := g.Generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating %s trust stores: %v\n", name, err)
			failed = true
			continue
		}

		allEntries = append(allEntries, entries...)
		fmt.Printf("✓ %s (%d entries)\n", name, len(entries))
	}

	// Build set of needed fingerprints
	neededFPs := make(map[string]bool)
	for _, e := range allEntries {
		neededFPs[e.Fingerprint.String()] = true
	}
	fmt.Printf("  %d unique fingerprints needed\n", len(neededFPs))

	// Generate CCADB certificates (filtered to only needed ones)
	fmt.Println("Generating CCADB...")
	allCerts, err := generate.CCADBGenerator{}.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating CCADB: %v\n", err)
		failed = true
	} else {
		// Filter to only certificates referenced in stores
		var certs []generate.Certificate
		for _, c := range allCerts {
			if neededFPs[c.Fingerprint.String()] {
				certs = append(certs, c)
			}
		}

		if err := writeCertificatesCSV(certs); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing certificates.csv: %v\n", err)
			failed = true
		} else {
			fmt.Printf("✓ CCADB (%d/%d certificates used)\n", len(certs), len(allCerts))
		}
	}

	// Write all trust entries to stores.csv
	if err := writeStoresCSV(allEntries); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing stores.csv: %v\n", err)
		failed = true
	} else {
		fmt.Printf("✓ stores.csv (%d total entries)\n", len(allEntries))
	}

	if failed {
		os.Exit(1)
	}
}

// writeCertificatesCSV writes certificates to certificates.csv
// Format: fingerprint,pem
// Sorted by: fingerprint (ascending)
func writeCertificatesCSV(certs []generate.Certificate) error {
	// Sort by fingerprint ascending
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].Fingerprint.String() < certs[j].Fingerprint.String()
	})

	path := filepath.Join(dataDir, "certificates.csv")
	f, err := os.Create(path) //nolint:gosec // G304: Path is constant dataDir + filename
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	if err := w.Write([]string{"fingerprint", "pem"}); err != nil {
		return err
	}

	// Write data
	for _, cert := range certs {
		// Escape newlines so each record is a single line
		escapedPEM := strings.ReplaceAll(cert.PEM, "\n", "\\n")
		if err := w.Write([]string{cert.Fingerprint.String(), escapedPEM}); err != nil {
			return err
		}
	}

	return w.Error()
}

// writeStoresCSV writes trust entries to stores.csv
// Format: platform,version,fingerprint,not_before_max,distrust_date,sct_not_after
// Sorted by: platform (asc), version (semver asc), fingerprint (asc)
func writeStoresCSV(entries []generate.TrustEntry) error {
	// Sort entries: platform asc, version semver asc, fingerprint asc
	sort.Slice(entries, func(i, j int) bool {
		// Compare platform first
		if entries[i].Platform != entries[j].Platform {
			return entries[i].Platform < entries[j].Platform
		}
		// Compare version using centralized version comparison
		if entries[i].Version != entries[j].Version {
			return version.LessThan(entries[i].Version, entries[j].Version)
		}
		// Compare fingerprint
		return entries[i].Fingerprint.String() < entries[j].Fingerprint.String()
	})

	path := filepath.Join(dataDir, "stores.csv")
	f, err := os.Create(path) //nolint:gosec // G304: Path is constant dataDir + filename
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	if err := w.Write([]string{"platform", "version", "fingerprint", "not_before_max", "distrust_date", "sct_not_after"}); err != nil {
		return err
	}

	// Write data
	for _, entry := range entries {
		row := []string{
			entry.Platform,
			entry.Version,
			entry.Fingerprint.String(),
			formatTime(entry.NotBeforeMax),
			formatTime(entry.DistrustDate),
			formatTime(entry.SCTNotAfter),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}

	return w.Error()
}

// formatTime converts a time pointer to RFC3339 string or empty if nil.
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

