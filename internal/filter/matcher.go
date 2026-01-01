package filter

import (
	"github.com/Masterminds/semver/v3"
	"github.com/ivoronin/certvet/internal/truststore"
	"github.com/ivoronin/certvet/internal/version"
)

// operatorStrategy defines how an operator handles version comparisons.
// Each strategy handles three cases: current constraint, current version, and semver comparison.
type operatorStrategy interface {
	// MatchCurrentConstraint handles when the constraint uses "current" (e.g., chrome=current)
	MatchCurrentConstraint(testIsCurrent bool) bool
	// MatchCurrentVersion handles when the test version is "current" against a numeric constraint
	MatchCurrentVersion() bool
	// MatchSemver handles numeric version comparison (cmp: -1/0/1 from semver.Compare)
	MatchSemver(cmp int) bool
}

// operatorStrategies maps operators to their comparison strategies.
var operatorStrategies = map[Operator]operatorStrategy{
	OpEqual:        equalStrategy{},
	OpGreater:      greaterStrategy{},
	OpLess:         lessStrategy{},
	OpGreaterEqual: greaterEqualStrategy{},
	OpLessEqual:    lessEqualStrategy{},
}

// Strategy implementations

type equalStrategy struct{}

func (equalStrategy) MatchCurrentConstraint(testIsCurrent bool) bool { return testIsCurrent }
func (equalStrategy) MatchCurrentVersion() bool                      { return false } // "current" != any specific version
func (equalStrategy) MatchSemver(cmp int) bool                       { return cmp == 0 }

type greaterStrategy struct{}

func (greaterStrategy) MatchCurrentConstraint(testIsCurrent bool) bool { return false } // Nothing > current
func (greaterStrategy) MatchCurrentVersion() bool                      { return true }  // "current" > any numeric
func (greaterStrategy) MatchSemver(cmp int) bool                       { return cmp > 0 }

type lessStrategy struct{}

func (lessStrategy) MatchCurrentConstraint(testIsCurrent bool) bool { return !testIsCurrent } // Any numeric < current
func (lessStrategy) MatchCurrentVersion() bool                      { return false }          // "current" never < any numeric
func (lessStrategy) MatchSemver(cmp int) bool                       { return cmp < 0 }

type greaterEqualStrategy struct{}

func (greaterEqualStrategy) MatchCurrentConstraint(testIsCurrent bool) bool { return testIsCurrent } // Only current >= current
func (greaterEqualStrategy) MatchCurrentVersion() bool                      { return true }          // "current" >= any numeric
func (greaterEqualStrategy) MatchSemver(cmp int) bool                       { return cmp >= 0 }

type lessEqualStrategy struct{}

func (lessEqualStrategy) MatchCurrentConstraint(testIsCurrent bool) bool { return true }  // Everything <= current
func (lessEqualStrategy) MatchCurrentVersion() bool                      { return false } // "current" never <= any numeric
func (lessEqualStrategy) MatchSemver(cmp int) bool                       { return cmp <= 0 }

// Match checks if a PlatformVersion satisfies the filter.
// Logic: AND within same platform, OR across platforms.
func (f *Filter) Match(pv truststore.PlatformVersion) bool {
	if f == nil || len(f.Constraints) == 0 {
		return true
	}

	// Group constraints by platform
	byPlatform := make(map[truststore.Platform][]Constraint)
	for _, c := range f.Constraints {
		byPlatform[c.Platform] = append(byPlatform[c.Platform], c)
	}

	// Check if this platform is even in the filter
	constraints, ok := byPlatform[pv.Platform]
	if !ok {
		return false // Platform not in filter
	}

	// All constraints for this platform must match (AND)
	for _, c := range constraints {
		if !matchConstraint(c, pv.Version) {
			return false
		}
	}
	return true
}

// matchConstraint compares a constraint against a version string using operator strategies.
func matchConstraint(c Constraint, ver string) bool {
	// Bare platform (nil Version and not IsCurrent) matches any version
	if c.Version == nil && !c.IsCurrent {
		return true
	}

	// Get the strategy for this operator
	strategy, ok := operatorStrategies[c.Operator]
	if !ok {
		return false // Unknown operator
	}

	// Handle constraint with IsCurrent (e.g., chrome=current)
	if c.IsCurrent {
		return strategy.MatchCurrentConstraint(ver == version.Current)
	}

	// Handle "current" test version against numeric constraint
	if ver == version.Current {
		return strategy.MatchCurrentVersion()
	}

	// Parse version string as semver
	v, err := semver.NewVersion(ver)
	if err != nil {
		return false // Invalid version string
	}

	// Compare using semver via strategy
	return strategy.MatchSemver(v.Compare(c.Version))
}

// FilterStores returns stores that match the filter.
func FilterStores(stores []truststore.Store, f *Filter) []truststore.Store {
	if f == nil {
		return stores
	}

	var result []truststore.Store
	for _, s := range stores {
		pv := truststore.PlatformVersion{Platform: s.Platform, Version: s.Version}
		if f.Match(pv) {
			result = append(result, s)
		}
	}
	return result
}
