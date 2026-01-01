// Package filter provides filter expression parsing and matching.
package filter

import (
	"github.com/Masterminds/semver/v3"
	"github.com/ivoronin/certvet/internal/truststore"
)

// Operator for version comparison.
type Operator string

const (
	OpEqual        Operator = "="
	OpGreater      Operator = ">"
	OpLess         Operator = "<"
	OpGreaterEqual Operator = ">="
	OpLessEqual    Operator = "<="
)

// Constraint represents a single filter constraint.
type Constraint struct {
	Platform  truststore.Platform
	Operator  Operator
	Version   *semver.Version // nil means "match any version" (bare platform)
	IsCurrent bool            // true when version is "current" (Chrome only)
}

// Filter represents parsed filter expression.
type Filter struct {
	Constraints []Constraint
}
