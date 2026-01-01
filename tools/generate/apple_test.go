package generate

import (
	"os"
	"strings"
	"testing"

	"github.com/ivoronin/certvet/internal/truststore"
)

func TestParseAppleLinkText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantCount    int
		wantPlatform map[truststore.Platform]string // platform -> expected version
	}{
		{
			name:      "all six platforms",
			input:     "iOS 18, iPadOS 18, macOS 15, tvOS 18, visionOS 2 and watchOS 11",
			wantCount: 6,
			wantPlatform: map[truststore.Platform]string{
				truststore.PlatformIOS:      "18",
				truststore.PlatformIPadOS:   "18",
				truststore.PlatformMacOS:    "15",
				truststore.PlatformTVOS:     "18",
				truststore.PlatformVisionOS: "2",
				truststore.PlatformWatchOS:  "11",
			},
		},
		{
			name:      "minor versions",
			input:     "iOS 17.4, iPadOS 17.4, macOS 14.4, tvOS 17.4, visionOS 1.1 and watchOS 10.4",
			wantCount: 6,
			wantPlatform: map[truststore.Platform]string{
				truststore.PlatformIOS:      "17.4",
				truststore.PlatformIPadOS:   "17.4",
				truststore.PlatformMacOS:    "14.4",
				truststore.PlatformTVOS:     "17.4",
				truststore.PlatformVisionOS: "1.1",
				truststore.PlatformWatchOS:  "10.4",
			},
		},
		{
			name:      "without visionOS (older)",
			input:     "iOS 17, iPadOS 17, macOS 14, tvOS 17, and watchOS 10",
			wantCount: 5,
			wantPlatform: map[truststore.Platform]string{
				truststore.PlatformIOS:     "17",
				truststore.PlatformIPadOS:  "17",
				truststore.PlatformMacOS:   "14",
				truststore.PlatformTVOS:    "17",
				truststore.PlatformWatchOS: "10",
			},
		},
		{
			name:      "older format - below minimum versions",
			input:     "iOS 12, macOS 10.14, tvOS 12, and watchOS 5",
			wantCount: 4,
			wantPlatform: map[truststore.Platform]string{
				truststore.PlatformIOS:     "12",
				truststore.PlatformMacOS:   "10.14",
				truststore.PlatformTVOS:    "12",
				truststore.PlatformWatchOS: "5",
			},
		},
		{
			name:      "skip versions below minimum - iOS 11",
			input:     "iOS 11, macOS 10.13",
			wantCount: 0, // Both below minimum versions
		},
		{
			name:      "case insensitive",
			input:     "IOS 18, IPADOS 18, MACOS 15",
			wantCount: 3,
			wantPlatform: map[truststore.Platform]string{
				truststore.PlatformIOS:    "18",
				truststore.PlatformIPadOS: "18",
				truststore.PlatformMacOS:  "15",
			},
		},
		{
			name:      "ios should not match inside visionos or ipados",
			input:     "visionOS 2, iPadOS 18",
			wantCount: 2,
			wantPlatform: map[truststore.Platform]string{
				truststore.PlatformVisionOS: "2",
				truststore.PlatformIPadOS:   "18",
			},
		},
		{
			name:      "empty string",
			input:     "",
			wantCount: 0,
		},
		{
			name:      "no platforms",
			input:     "List of available root certificates",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			results := ParseAppleLinkText(tt.input)
			if len(results) != tt.wantCount {
				t.Errorf("got %d results, want %d", len(results), tt.wantCount)
				for _, r := range results {
					t.Logf("  found: %s %s", r.Platform, r.Version)
				}
				return
			}

			// Verify expected platforms and versions
			for _, pv := range results {
				expected, ok := tt.wantPlatform[pv.Platform]
				if !ok {
					t.Errorf("unexpected platform %s", pv.Platform)
					continue
				}
				if pv.Version != expected {
					t.Errorf("platform %s: got version %s, want %s", pv.Platform, pv.Version, expected)
				}
			}
		})
	}
}

func TestParseAppleMasterPage(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/apple_master_page.html")
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	versions, err := ParseAppleMasterPage(f)
	if err != nil {
		t.Fatalf("ParseAppleMasterPage failed: %v", err)
	}

	// Should find multiple platform-version pairs from the test data
	if len(versions) == 0 {
		t.Fatal("expected at least some versions, got none")
	}

	// Build a map for easier assertions
	found := make(map[truststore.Platform]map[string]bool)
	for _, v := range versions {
		if found[v.Platform] == nil {
			found[v.Platform] = make(map[string]bool)
		}
		found[v.Platform][v.Version] = true
		// Verify URLs are absolute
		if !strings.HasPrefix(v.URL, "https://support.apple.com") {
			t.Errorf("URL not absolute: %s", v.URL)
		}
	}

	// Check for expected platforms from the test data
	expectedPlatforms := []truststore.Platform{
		truststore.PlatformIOS,
		truststore.PlatformIPadOS,
		truststore.PlatformMacOS,
		truststore.PlatformTVOS,
		truststore.PlatformWatchOS,
	}
	for _, p := range expectedPlatforms {
		if _, ok := found[p]; !ok {
			t.Errorf("missing expected platform: %s", p)
		}
	}

	// Verify iOS 18 is found (from first link in test data)
	if !found[truststore.PlatformIOS]["18"] {
		t.Error("expected to find iOS 18")
	}

	// Verify iOS 11 and macOS 10.13 are NOT found (below minimum versions)
	if found[truststore.PlatformIOS]["11"] {
		t.Error("iOS 11 should be filtered out (below minimum)")
	}
	if found[truststore.PlatformMacOS]["10.13"] {
		t.Error("macOS 10.13 should be filtered out (below minimum)")
	}
}

func TestParseAppleMasterPageDeduplication(t *testing.T) {
	t.Parallel()

	// Test that duplicate platform+version combinations are deduplicated
	html := `
	<html>
	<body>
	<a href="/page1">iOS 18, macOS 15</a>
	<a href="/page2">iOS 18, tvOS 18</a>
	</body>
	</html>
	`

	versions, err := ParseAppleMasterPage(strings.NewReader(html))
	if err != nil {
		t.Fatalf("ParseAppleMasterPage failed: %v", err)
	}

	// Count iOS 18 occurrences - should be exactly 1
	ios18Count := 0
	for _, v := range versions {
		if v.Platform == truststore.PlatformIOS && v.Version == "18" {
			ios18Count++
		}
	}

	if ios18Count != 1 {
		t.Errorf("iOS 18 appeared %d times, should be deduplicated to 1", ios18Count)
	}
}

func TestParseAppleVersionPageSkipsHeaders(t *testing.T) {
	t.Parallel()

	// Test that header rows with <td> instead of <th> are skipped
	html := `
	<html><body>
	<table>
	<tr>
		<td>Name</td><td>Cert</td><td>Type</td><td>Class</td><td>NotBefore</td>
		<td>NotAfter</td><td>Key</td><td>SHA-1</td><td>Fingerprint (SHA-256)</td>
	</tr>
	<tr>
		<td>Test CA</td><td>Cert1</td><td>Root</td><td>3</td><td>2020-01-01</td>
		<td>2030-01-01</td><td>RSA</td><td>AA:BB</td><td>D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4</td>
	</tr>
	</table>
	</body></html>
	`

	fps, err := ParseAppleVersionPage(strings.NewReader(html))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fps) != 1 {
		t.Errorf("expected 1 fingerprint (header skipped), got %d", len(fps))
	}
}

func TestParseAppleVersionPageSkipsEmptyRows(t *testing.T) {
	t.Parallel()

	// Test that rows with empty fingerprint cells are skipped
	html := `
	<html><body>
	<table>
	<tr>
		<td>Test CA</td><td>Cert1</td><td>Root</td><td>3</td><td>2020-01-01</td>
		<td>2030-01-01</td><td>RSA</td><td>AA:BB</td><td></td>
	</tr>
	<tr>
		<td>Test CA</td><td>Cert1</td><td>Root</td><td>3</td><td>2020-01-01</td>
		<td>2030-01-01</td><td>RSA</td><td>AA:BB</td><td>D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4</td>
	</tr>
	</table>
	</body></html>
	`

	fps, err := ParseAppleVersionPage(strings.NewReader(html))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(fps) != 1 {
		t.Errorf("expected 1 fingerprint (empty row skipped), got %d", len(fps))
	}
}

