package version

import "testing"

func TestCompareAsc(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool // true if a < b (a comes first in ascending order)
	}{
		// Standard semver comparisons
		{"138 < 139", "138", "139", true},
		{"139 > 138", "139", "138", false},
		{"17.4 < 18", "17.4", "18", true},
		{"18 > 17.4", "18", "17.4", false},
		{"17.4 < 17.5", "17.4", "17.5", true},

		// "current" is always greatest
		{"138 < current", "138", "current", true},
		{"139 < current", "139", "current", true},
		{"current > 138", "current", "138", false},
		{"current > 139", "current", "139", false},
		{"current = current (not less)", "current", "current", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareAsc(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("CompareAsc(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
