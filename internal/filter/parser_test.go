package filter

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/ivoronin/certvet/internal/truststore"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int // number of constraints
		wantErr string
	}{
		// Original iOS/Android tests (backward compatibility)
		{"single constraint", "ios>=15", 1, ""},
		{"two constraints", "ios>=15,android>=10", 2, ""},
		{"range same platform", "android>=10,android<=13", 2, ""},
		{"case insensitive iOS", "iOS>=15", 1, ""},
		{"case insensitive IOS", "IOS>=15", 1, ""},
		{"case insensitive Android", "ANDROID>=10", 1, ""},
		{"all operators", "ios=18", 1, ""},
		{"greater", "ios>17", 1, ""},
		{"less", "ios<19", 1, ""},
		{"less equal", "ios<=18", 1, ""},
		{"semver version", "ios>=17.4", 1, ""},
		{"semver full", "ios>=17.4.1", 1, ""},
		{"bare platform ios", "ios", 1, ""},
		{"bare platform android", "android", 1, ""},
		{"bare platform windows", "windows", 1, ""},
		{"windows constraint", "windows>=10", 1, ""},
		{"windows current", "windows=current", 1, ""},
		{"mixed bare and constraint", "ios,android>=10", 2, ""},
		{"unknown platform", "linux>=10", 0, "invalid filter"},
		{"invalid operator", "ios>>15", 0, "invalid filter"},
		{"empty", "", 0, "empty"},

		// New Apple platform tests
		{"macos constraint", "macos>=14", 1, ""},
		{"ipados constraint", "ipados>=17", 1, ""},
		{"tvos constraint", "tvos>=17", 1, ""},
		{"visionos constraint", "visionos>=1", 1, ""},
		{"watchos constraint", "watchos>=10", 1, ""},

		// Case insensitivity for new platforms
		{"case insensitive macOS", "MacOS>=14", 1, ""},
		{"case insensitive MACOS", "MACOS>=14", 1, ""},
		{"case insensitive iPadOS", "iPadOS>=17", 1, ""},
		{"case insensitive tvOS", "tvOS>=17", 1, ""},
		{"case insensitive visionOS", "visionOS>=1", 1, ""},
		{"case insensitive watchOS", "watchOS>=10", 1, ""},

		// Bare new platforms
		{"bare macos", "macos", 1, ""},
		{"bare ipados", "ipados", 1, ""},
		{"bare tvos", "tvos", 1, ""},
		{"bare visionos", "visionos", 1, ""},
		{"bare watchos", "watchos", 1, ""},

		// Multi-platform expressions
		{"multi apple platforms", "ipados,tvos>=17,visionos,watchos>=10", 4, ""},
		{"ios and macos", "ios>=17,macos>=14", 2, ""},
		{"all apple platforms", "ios,ipados,macos,tvos,visionos,watchos", 6, ""},

		// Invalid platform name
		{"invalid platform osx", "osx>=10", 0, "invalid filter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := Parse(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(f.Constraints) != tt.want {
				t.Errorf("got %d constraints, want %d", len(f.Constraints), tt.want)
			}
		})
	}
}

func TestParseConstraintValues(t *testing.T) {
	f, err := Parse("ios>=15")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(f.Constraints))
	}
	c := f.Constraints[0]
	if c.Platform != truststore.PlatformIOS {
		t.Errorf("Platform = %v, want ios", c.Platform)
	}
	if c.Operator != OpGreaterEqual {
		t.Errorf("Operator = %v, want >=", c.Operator)
	}

	// Version should be semver 15.0.0
	want := semver.MustParse("15")
	if !c.Version.Equal(want) {
		t.Errorf("Version = %v, want %v", c.Version, want)
	}
}

func TestParseSemverConstraint(t *testing.T) {
	f, err := Parse("ios>=17.4")
	if err != nil {
		t.Fatal(err)
	}

	c := f.Constraints[0]
	want := semver.MustParse("17.4")
	if !c.Version.Equal(want) {
		t.Errorf("Version = %v, want %v", c.Version, want)
	}
}

func TestParseBarePlatform(t *testing.T) {
	f, err := Parse("android")
	if err != nil {
		t.Fatal(err)
	}

	if len(f.Constraints) != 1 {
		t.Fatalf("expected 1 constraint, got %d", len(f.Constraints))
	}

	c := f.Constraints[0]
	if c.Platform != truststore.PlatformAndroid {
		t.Errorf("Platform = %v, want android", c.Platform)
	}
	if c.Version != nil {
		t.Errorf("Version = %v, want nil (bare platform)", c.Version)
	}
}

func TestParseNewPlatformMapping(t *testing.T) {
	// Verify each new platform maps to the correct constant
	tests := []struct {
		input string
		want  truststore.Platform
	}{
		{"macos>=14", truststore.PlatformMacOS},
		{"ipados>=17", truststore.PlatformIPadOS},
		{"tvos>=17", truststore.PlatformTVOS},
		{"visionos>=1", truststore.PlatformVisionOS},
		{"watchos>=10", truststore.PlatformWatchOS},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			f, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(f.Constraints) != 1 {
				t.Fatalf("expected 1 constraint, got %d", len(f.Constraints))
			}
			if f.Constraints[0].Platform != tt.want {
				t.Errorf("Platform = %v, want %v", f.Constraints[0].Platform, tt.want)
			}
		})
	}
}
