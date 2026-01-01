package generate

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ivoronin/certvet/internal/truststore"
)

const (
	androidRefsURL    = "https://android.googlesource.com/platform/system/ca-certificates/+refs/heads?format=TEXT"
	androidArchiveURL = "https://android.googlesource.com/platform/system/ca-certificates/+archive/refs/heads/%s/files.tar.gz"
	minAndroidVersion = 7 // Android 7 (Nougat) and later only
)

// AndroidGenerator implements StoreGenerator for Android trust store data.
type AndroidGenerator struct{}

// Name returns the generator's display name.
func (AndroidGenerator) Name() string { return "Android" }

// Generate fetches Android trust store data and returns TrustEntry structs.
func (AndroidGenerator) Generate() ([]TrustEntry, error) {
	versions, err := DiscoverAndroidVersions()
	if err != nil {
		return nil, err
	}

	var entries []TrustEntry

	for _, v := range versions {
		fingerprints, err := ScrapeAndroidVersion(v.Branch)
		if err != nil {
			Log.Warn("Android %s: %v", v.Version, err)
			continue
		}

		// Create TrustEntry for each fingerprint
		for _, fp := range fingerprints {
			entries = append(entries, TrustEntry{
				Platform:    "android",
				Version:     v.Version,
				Fingerprint: fp,
			})
		}
	}

	return entries, nil
}

// AndroidVersion represents an Android version and its branch.
type AndroidVersion struct {
	Version string // Version as string (e.g., "10", "14")
	Branch  string
}

var androidVersionRE = regexp.MustCompile(`android(\d+)-release`)

// DiscoverAndroidVersions fetches available Android versions from git branches.
func DiscoverAndroidVersions() ([]AndroidVersion, error) {
	resp, err := httpClient.Get(androidRefsURL)
	if err != nil {
		return nil, fmt.Errorf("fetch android refs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("android refs returned status %d", resp.StatusCode)
	}

	return ParseAndroidRefs(resp.Body)
}

// ParseAndroidRefs parses the refs API response to extract versions.
func ParseAndroidRefs(r io.Reader) ([]AndroidVersion, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read refs: %w", err)
	}

	versions := make(map[string]string) // version string → branch name

	// Parse numbered versions (android10-release, android14-release, etc.)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		branchName := strings.TrimPrefix(parts[1], "refs/heads/")

		if matches := androidVersionRE.FindStringSubmatch(branchName); matches != nil {
			ver, _ := strconv.Atoi(matches[1])
			if ver >= minAndroidVersion {
				versions[matches[1]] = branchName // Store version as string
			}
		}
	}

	// Handle special codename branches for pre-10 versions
	codenameBranches := map[string]string{
		"9": "pie-release",
		"8": "oreo-mr1-release",
		"7": "nougat-mr2-release",
	}
	for ver, branch := range codenameBranches {
		if _, exists := versions[ver]; !exists {
			// Check if branch exists in the refs data
			if strings.Contains(string(data), branch) {
				versions[ver] = branch
			}
		}
	}

	// Convert to slice and sort by version descending (numerically)
	var result []AndroidVersion
	for ver, branch := range versions {
		result = append(result, AndroidVersion{Version: ver, Branch: branch})
	}
	sort.Slice(result, func(i, j int) bool {
		vi, _ := strconv.Atoi(result[i].Version)
		vj, _ := strconv.Atoi(result[j].Version)
		return vi > vj
	})

	return result, nil
}

// ScrapeAndroidVersion downloads and extracts fingerprints from an Android branch.
func ScrapeAndroidVersion(branch string) ([]truststore.Fingerprint, error) {
	url := fmt.Sprintf(androidArchiveURL, branch)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch android archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("android archive returned status %d", resp.StatusCode)
	}

	return ParseAndroidArchive(resp.Body)
}

// ParseAndroidArchive extracts fingerprints from a tar.gz archive.
func ParseAndroidArchive(r io.Reader) ([]truststore.Fingerprint, error) {
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	tarReader := tar.NewReader(gzReader)

	var fingerprints []truststore.Fingerprint

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}

		// Android cert files have .0 extension
		if !strings.HasSuffix(header.Name, ".0") {
			continue
		}

		// Read PEM content
		pemBytes, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, fmt.Errorf("read cert file %s: %w", header.Name, err)
		}

		// Parse certificate and compute SHA-256
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("decode PEM in %s: no valid PEM block found", header.Name)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Skip unparseable certificates with warning - Go's TLS stack would reject them too
			Log.Warn("skipping %s: %v", header.Name, err)
			continue
		}

		fp := truststore.Fingerprint(sha256.Sum256(cert.Raw))
		fingerprints = append(fingerprints, fp)
	}

	return fingerprints, nil
}
