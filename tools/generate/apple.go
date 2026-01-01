package generate

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/PuerkitoBio/goquery"
	"github.com/ivoronin/certvet/internal/truststore"
)

// AppleGenerator implements StoreGenerator for Apple trust store data.
type AppleGenerator struct{}

// Name returns the generator's display name.
func (AppleGenerator) Name() string { return "Apple" }

// Generate fetches Apple trust store data and returns TrustEntry structs.
func (AppleGenerator) Generate() ([]TrustEntry, error) {
	versions, err := DiscoverAppleVersions()
	if err != nil {
		return nil, err
	}

	// Track URLs we've already scraped (multiple platforms share the same page)
	scrapedURLs := make(map[string][]truststore.Fingerprint)

	var entries []TrustEntry

	for _, v := range versions {
		// Check if we've already scraped this URL
		fingerprints, cached := scrapedURLs[v.URL]
		if !cached {
			fingerprints, err = ScrapeAppleVersion(v.URL)
			if err != nil {
				Log.Warn("%s %s: %v", v.Platform, v.Version, err)
				continue
			}
			scrapedURLs[v.URL] = fingerprints
		}

		// Create TrustEntry for each fingerprint
		for _, fp := range fingerprints {
			entries = append(entries, TrustEntry{
				Platform:    string(v.Platform),
				Version:     v.Version,
				Fingerprint: fp,
			})
		}
	}

	return entries, nil
}

const (
	appleMasterListURL = "https://support.apple.com/en-us/103272"
	appleBaseURL       = "https://support.apple.com"
)

// Minimum versions per platform (unified store era only, per SDD CON-5)
var minAppleVersions = map[truststore.Platform]string{
	truststore.PlatformIOS:      "12",
	truststore.PlatformIPadOS:   "13", // iPadOS didn't exist before iOS 13 fork
	truststore.PlatformMacOS:    "10.14",
	truststore.PlatformTVOS:     "12",
	truststore.PlatformVisionOS: "1",
	truststore.PlatformWatchOS:  "5",
}

// ApplePlatformVersion represents a platform-version pair from Apple's KB link.
type ApplePlatformVersion struct {
	Platform truststore.Platform
	Version  string // Platform-native version (e.g., "15" for macOS, "18" for iOS)
	URL      string // Trust store page URL
}

// Regex patterns for each Apple platform
var platformPatterns = map[truststore.Platform]*regexp.Regexp{
	truststore.PlatformIOS:      regexp.MustCompile(`(?i)\biOS\s*(\d+(?:\.\d+)*)`),
	truststore.PlatformIPadOS:   regexp.MustCompile(`(?i)\biPadOS\s*(\d+(?:\.\d+)*)`),
	truststore.PlatformMacOS:    regexp.MustCompile(`(?i)\bmacOS\s*(\d+(?:\.\d+)*)`),
	truststore.PlatformTVOS:     regexp.MustCompile(`(?i)\btvOS\s*(\d+(?:\.\d+)*)`),
	truststore.PlatformVisionOS: regexp.MustCompile(`(?i)\bvisionOS\s*(\d+(?:\.\d+)*)`),
	truststore.PlatformWatchOS:  regexp.MustCompile(`(?i)\bwatchOS\s*(\d+(?:\.\d+)*)`),
}

// ParseAppleLinkText extracts all platform-version pairs from a link text.
// Example: "iOS 18, iPadOS 18, macOS 15, tvOS 18, visionOS 2 and watchOS 11"
// Returns multiple ApplePlatformVersion entries (one per platform found).
func ParseAppleLinkText(text string) []ApplePlatformVersion {
	var results []ApplePlatformVersion

	for platform, re := range platformPatterns {
		matches := re.FindStringSubmatch(text)
		if matches != nil {
			version := matches[1]

			// Check minimum version for this platform
			if minVer, ok := minAppleVersions[platform]; ok {
				minSemver, _ := semver.NewVersion(minVer)
				verSemver, err := semver.NewVersion(version)
				if err == nil && verSemver.LessThan(minSemver) {
					continue // Skip versions below minimum
				}
			}

			results = append(results, ApplePlatformVersion{
				Platform: platform,
				Version:  version,
			})
		}
	}

	return results
}

// DiscoverAppleVersions fetches the master page and extracts all platform-version pairs.
func DiscoverAppleVersions() ([]ApplePlatformVersion, error) {
	resp, err := httpClient.Get(appleMasterListURL)
	if err != nil {
		return nil, fmt.Errorf("fetch Apple master page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apple master page returned status %d", resp.StatusCode)
	}

	return ParseAppleMasterPage(resp.Body)
}

// ParseAppleMasterPage extracts all platform-version pairs from the master page HTML.
func ParseAppleMasterPage(r io.Reader) ([]ApplePlatformVersion, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("parse HTML: %w", err)
	}

	// Track seen platform+version combinations to avoid duplicates
	seen := make(map[string]bool)
	var versions []ApplePlatformVersion

	doc.Find("a").Each(func(_ int, link *goquery.Selection) {
		href, exists := link.Attr("href")
		if !exists {
			return
		}

		text := link.Text()
		platformVersions := ParseAppleLinkText(text)

		for _, pv := range platformVersions {
			key := fmt.Sprintf("%s:%s", pv.Platform, pv.Version)
			if seen[key] {
				continue
			}
			seen[key] = true

			// Convert relative URLs to absolute
			fullURL := href
			if strings.HasPrefix(href, "/") {
				fullURL = appleBaseURL + href
			}

			versions = append(versions, ApplePlatformVersion{
				Platform: pv.Platform,
				Version:  pv.Version,
				URL:      fullURL,
			})
		}
	})

	return versions, nil
}

// ScrapeAppleVersion fetches a version page and extracts fingerprints.
func ScrapeAppleVersion(url string) ([]truststore.Fingerprint, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch Apple version page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apple version page returned status %d", resp.StatusCode)
	}

	return ParseAppleVersionPage(resp.Body)
}

// ParseAppleVersionPage extracts fingerprints from a version page HTML.
// This is identical to ParseIOSVersionPage - reused for all Apple platforms.
func ParseAppleVersionPage(r io.Reader) ([]truststore.Fingerprint, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("parse HTML: %w", err)
	}

	var fingerprints []truststore.Fingerprint
	var parseErr error
	rowNum := 0

	// Find table rows with certificate data
	doc.Find("table tr, .table-data tr").Each(func(_ int, row *goquery.Selection) {
		if parseErr != nil {
			return // Stop processing if we hit an error
		}

		cells := row.Find("td")
		if cells.Length() < 9 {
			return // Not a data row
		}

		// SHA-256 fingerprint is in the last column (9th)
		fpCell := strings.TrimSpace(cells.Eq(8).Text())

		// Skip header rows - some older pages use <td> instead of <th> for headers
		if strings.Contains(strings.ToLower(fpCell), "fingerprint") ||
			strings.Contains(strings.ToLower(fpCell), "sha-256") ||
			fpCell == "" {
			return
		}

		rowNum++
		fp, err := truststore.ParseFingerprint(fpCell)
		if err != nil {
			parseErr = fmt.Errorf("row %d: invalid fingerprint %q: %w", rowNum, fpCell, err)
			return
		}
		fingerprints = append(fingerprints, fp)
	})

	if parseErr != nil {
		return nil, parseErr
	}

	return fingerprints, nil
}
