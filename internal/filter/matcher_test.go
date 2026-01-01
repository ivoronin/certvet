package filter

import (
	"testing"

	"github.com/ivoronin/certvet/internal/truststore"
)

func TestFilterMatch(t *testing.T) {
	tests := []struct {
		name string
		expr string
		pv   truststore.PlatformVersion
		want bool
	}{
		// Single constraint tests
		{"ios>=15 matches ios 18", "ios>=15", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"}, true},
		{"ios>=15 matches ios 15", "ios>=15", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "15"}, true},
		{"ios>=15 rejects ios 14", "ios>=15", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "14"}, false},
		{"ios>=15 rejects android", "ios>=15", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "15"}, false},

		// OR across platforms
		{"ios or android matches ios", "ios>=15,android>=10", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"}, true},
		{"ios or android matches android", "ios>=15,android>=10", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "14"}, true},

		// AND within same platform (range)
		{"android 10-13 matches 10", "android>=10,android<=13", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "10"}, true},
		{"android 10-13 matches 12", "android>=10,android<=13", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "12"}, true},
		{"android 10-13 matches 13", "android>=10,android<=13", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "13"}, true},
		{"android 10-13 rejects 9", "android>=10,android<=13", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "9"}, false},
		{"android 10-13 rejects 14", "android>=10,android<=13", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "14"}, false},

		// Exact match
		{"ios=18 matches 18", "ios=18", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"}, true},
		{"ios=18 rejects 17", "ios=18", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "17"}, false},

		// Semver matching
		{"ios>=17.4 matches 17.4", "ios>=17.4", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "17.4"}, true},
		{"ios>=17.4 matches 17.5", "ios>=17.4", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "17.5"}, true},
		{"ios>=17.4 matches 18", "ios>=17.4", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"}, true},
		{"ios>=17.4 rejects 17.3", "ios>=17.4", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "17.3"}, false},
		{"ios>=17.4 rejects 17", "ios>=17.4", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "17"}, false},

		// Bare platform (matches all versions)
		{"bare ios matches any", "ios", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "15"}, true},
		{"bare ios matches 18", "ios", truststore.PlatformVersion{Platform: truststore.PlatformIOS, Version: "18"}, true},
		{"bare ios rejects android", "ios", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "10"}, false},
		{"bare android matches any", "android", truststore.PlatformVersion{Platform: truststore.PlatformAndroid, Version: "10"}, true},

		// New Apple platforms
		{"macos>=14 matches 15", "macos>=14", truststore.PlatformVersion{Platform: truststore.PlatformMacOS, Version: "15"}, true},
		{"macos>=14 rejects 13", "macos>=14", truststore.PlatformVersion{Platform: truststore.PlatformMacOS, Version: "13"}, false},
		{"ipados>=17 matches 18", "ipados>=17", truststore.PlatformVersion{Platform: truststore.PlatformIPadOS, Version: "18"}, true},
		{"tvos>=17 matches 18", "tvos>=17", truststore.PlatformVersion{Platform: truststore.PlatformTVOS, Version: "18"}, true},
		{"visionos>=1 matches 2", "visionos>=1", truststore.PlatformVersion{Platform: truststore.PlatformVisionOS, Version: "2"}, true},
		{"watchos>=10 matches 11", "watchos>=10", truststore.PlatformVersion{Platform: truststore.PlatformWatchOS, Version: "11"}, true},

		// Multi-platform Apple filter
		{"multi-apple matches macos", "ios,macos,ipados", truststore.PlatformVersion{Platform: truststore.PlatformMacOS, Version: "15"}, true},
		{"multi-apple matches ipados", "ios,macos,ipados", truststore.PlatformVersion{Platform: truststore.PlatformIPadOS, Version: "18"}, true},
		{"multi-apple rejects tvos", "ios,macos,ipados", truststore.PlatformVersion{Platform: truststore.PlatformTVOS, Version: "18"}, false},

		// Platform isolation - ios filter shouldn't match visionos or ipados
		{"ios filter rejects visionos", "ios>=18", truststore.PlatformVersion{Platform: truststore.PlatformVisionOS, Version: "2"}, false},
		{"ios filter rejects ipados", "ios>=18", truststore.PlatformVersion{Platform: truststore.PlatformIPadOS, Version: "18"}, false},

		// Chrome "current" version handling
		{"bare chrome matches current", "chrome", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "current"}, true},
		{"bare chrome matches 138", "chrome", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "138"}, true},
		{"chrome>=139 matches current", "chrome>=139", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "current"}, true},
		{"chrome>=139 matches 140", "chrome>=139", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "140"}, true},
		{"chrome>=139 matches 139", "chrome>=139", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "139"}, true},
		{"chrome>=139 rejects 138", "chrome>=139", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "138"}, false},
		{"chrome<=138 rejects current", "chrome<=138", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "current"}, false},
		{"chrome<=138 matches 138", "chrome<=138", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "138"}, true},
		{"chrome<=138 matches 137", "chrome<=138", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "137"}, true},
		{"chrome=current matches current", "chrome=current", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "current"}, true},
		{"chrome=current rejects 139", "chrome=current", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "139"}, false},
		{"chrome>138 matches current", "chrome>138", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "current"}, true},
		{"chrome<139 rejects current", "chrome<139", truststore.PlatformVersion{Platform: truststore.PlatformChrome, Version: "current"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse(tt.expr)
			if err != nil {
				t.Fatal(err)
			}
			got := f.Match(tt.pv)
			if got != tt.want {
				t.Errorf("Match(%v) = %v, want %v", tt.pv, got, tt.want)
			}
		})
	}
}

func TestFilterStores(t *testing.T) {
	stores := []truststore.Store{
		{Platform: truststore.PlatformIOS, Version: "18"},
		{Platform: truststore.PlatformIOS, Version: "17"},
		{Platform: truststore.PlatformIOS, Version: "16"},
		{Platform: truststore.PlatformAndroid, Version: "35"},
		{Platform: truststore.PlatformAndroid, Version: "34"},
	}

	f, err := Parse("ios>=17,android>=35")
	if err != nil {
		t.Fatal(err)
	}

	filtered := FilterStores(stores, f)
	if len(filtered) != 3 {
		t.Errorf("got %d stores, want 3", len(filtered))
	}

	// Verify correct stores (checking version strings)
	for _, s := range filtered {
		if s.Platform == truststore.PlatformIOS && s.Version == "16" {
			t.Errorf("unexpected iOS %s in result", s.Version)
		}
		if s.Platform == truststore.PlatformAndroid && s.Version == "34" {
			t.Errorf("unexpected Android %s in result", s.Version)
		}
	}
}

func TestFilterStoresNilFilter(t *testing.T) {
	stores := []truststore.Store{
		{Platform: truststore.PlatformIOS, Version: "18"},
	}
	// nil filter returns all stores
	filtered := FilterStores(stores, nil)
	if len(filtered) != 1 {
		t.Errorf("nil filter should return all stores, got %d", len(filtered))
	}
}
