// Package version provides version comparison utilities.
package version

import "github.com/Masterminds/semver/v3"

// Current is the special version string representing the latest/rolling release.
// Used for Chrome's rolling release model and Windows "current" version.
const Current = "current"

// Compare returns -1, 0, or 1 based on comparing a vs b.
// Handles: semver, integer versions, and "current" special value.
// "current" is always considered greater than any numeric version.
func Compare(a, b string) int {
	// Handle "current" special case
	if a == Current && b == Current {
		return 0
	}
	if a == Current {
		return 1 // current > any numeric
	}
	if b == Current {
		return -1 // any numeric < current
	}

	// Try semver comparison
	va, errA := semver.NewVersion(a)
	vb, errB := semver.NewVersion(b)
	if errA == nil && errB == nil {
		return va.Compare(vb)
	}

	// Semver wins over non-semver in sorting
	if errA == nil {
		return -1
	}
	if errB == nil {
		return 1
	}

	// Fallback to string comparison
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// LessThan returns true if a < b.
func LessThan(a, b string) bool {
	return Compare(a, b) < 0
}

// GreaterOrEqual returns true if a >= b.
func GreaterOrEqual(a, b string) bool {
	return Compare(a, b) >= 0
}

// CompareAsc compares two version strings for ascending sort.
// Returns true if a < b (a should come before b in ascending order).
// This is an alias for LessThan, maintained for backward compatibility.
func CompareAsc(a, b string) bool {
	return LessThan(a, b)
}
