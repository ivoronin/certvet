package truststore

import (
	"regexp"
	"testing"
	"time"
)

// allPlatforms lists every platform that must be present in the trust store data.
var allPlatforms = []Platform{
	PlatformIOS,
	PlatformIPadOS,
	PlatformMacOS,
	PlatformTVOS,
	PlatformVisionOS,
	PlatformWatchOS,
	PlatformAndroid,
	PlatformChrome,
	PlatformWindows,
}

// versionPattern matches valid version strings: "current" or semver-like (e.g., "18", "17.4", "12.1.3")
var versionPattern = regexp.MustCompile(`^(current|\d+(\.\d+)*)$`)

func TestDataQuality_CertificateCount(t *testing.T) {
	const minCerts = 500
	if len(Certs) <= minCerts {
		t.Errorf("expected more than %d certificates, got %d", minCerts, len(Certs))
	}
}

func TestDataQuality_AllPlatformsPresent(t *testing.T) {
	presentPlatforms := make(map[Platform]bool)
	for _, store := range Stores {
		presentPlatforms[store.Platform] = true
	}

	for _, platform := range allPlatforms {
		if !presentPlatforms[platform] {
			t.Errorf("platform %q not found in stores", platform)
		}
	}
}

func TestDataQuality_MinCertsPerStore(t *testing.T) {
	const minCerts = 50
	for _, store := range Stores {
		if len(store.Fingerprints) <= minCerts {
			t.Errorf("%s/%s has only %d certs, expected > %d",
				store.Platform, store.Version,
				len(store.Fingerprints), minCerts)
		}
	}
}

func TestDataQuality_MinVersionsPerPlatform(t *testing.T) {
	const minVersions = 5
	versionCount := make(map[Platform]int)

	for _, store := range Stores {
		versionCount[store.Platform]++
	}

	for _, platform := range []Platform{PlatformAndroid, PlatformIOS} {
		if versionCount[platform] <= minVersions {
			t.Errorf("%s has only %d versions, expected > %d",
				platform, versionCount[platform], minVersions)
		}
	}
}

// TestDataQuality_AllCertsAreUsed ensures no orphaned certificates exist.
// Every cert in Certs should be referenced by at least one store.
func TestDataQuality_AllCertsAreUsed(t *testing.T) {
	usedFingerprints := make(map[Fingerprint]bool)
	for _, store := range Stores {
		for _, fp := range store.Fingerprints {
			usedFingerprints[fp] = true
		}
	}

	var orphanCount int
	for fp := range Certs {
		if !usedFingerprints[fp] {
			orphanCount++
			if orphanCount <= 5 {
				t.Errorf("orphaned certificate not used by any store: %s", fp.Truncate(4))
			}
		}
	}
	if orphanCount > 5 {
		t.Errorf("... and %d more orphaned certificates", orphanCount-5)
	}
}

// TestDataQuality_NoDuplicateStoreEntries ensures no duplicate (platform, version, fingerprint) tuples.
func TestDataQuality_NoDuplicateStoreEntries(t *testing.T) {
	type storeKey struct {
		platform    Platform
		version     string
		fingerprint Fingerprint
	}

	seen := make(map[storeKey]bool)
	var dupCount int

	for _, store := range Stores {
		for _, fp := range store.Fingerprints {
			key := storeKey{store.Platform, store.Version, fp}
			if seen[key] {
				dupCount++
				if dupCount <= 5 {
					t.Errorf("duplicate entry: %s/%s/%s", store.Platform, store.Version, fp.Truncate(4))
				}
			}
			seen[key] = true
		}
	}
	if dupCount > 5 {
		t.Errorf("... and %d more duplicate entries", dupCount-5)
	}
}

// TestDataQuality_ConstraintDatesReasonable ensures all constraint dates are within sane bounds.
func TestDataQuality_ConstraintDatesReasonable(t *testing.T) {
	minDate := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	maxDate := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, store := range Stores {
		for fp, constraints := range store.Constraints {
			if constraints.NotBeforeMax != nil {
				if constraints.NotBeforeMax.Before(minDate) || constraints.NotBeforeMax.After(maxDate) {
					t.Errorf("%s/%s/%s: NotBeforeMax %v outside reasonable range",
						store.Platform, store.Version, fp.Truncate(4), constraints.NotBeforeMax)
				}
			}
			if constraints.DistrustDate != nil {
				if constraints.DistrustDate.Before(minDate) || constraints.DistrustDate.After(maxDate) {
					t.Errorf("%s/%s/%s: DistrustDate %v outside reasonable range",
						store.Platform, store.Version, fp.Truncate(4), constraints.DistrustDate)
				}
			}
			if constraints.SCTNotAfter != nil {
				if constraints.SCTNotAfter.Before(minDate) || constraints.SCTNotAfter.After(maxDate) {
					t.Errorf("%s/%s/%s: SCTNotAfter %v outside reasonable range",
						store.Platform, store.Version, fp.Truncate(4), constraints.SCTNotAfter)
				}
			}
		}
	}
}

// TestDataQuality_VersionFormat ensures all version strings are valid.
// Valid formats: "current" or semver-like patterns (e.g., "18", "17.4", "12.1.3")
func TestDataQuality_VersionFormat(t *testing.T) {
	for _, store := range Stores {
		if !versionPattern.MatchString(store.Version) {
			t.Errorf("%s has invalid version format: %q", store.Platform, store.Version)
		}
	}
}
