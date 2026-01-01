package filter

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/ivoronin/certvet/internal/truststore"
)

// AST types for Participle grammar

// filterExpr is the root of the grammar: comma-separated constraints
type filterExpr struct {
	Constraints []*constraintExpr `parser:"@@ ( ',' @@ )*"`
}

// constraintExpr represents a single constraint: platform[op version]
type constraintExpr struct {
	Platform string `parser:"@Platform"`
	Operator string `parser:"@Operator?"`
	Version  string `parser:"@Version?"`
}

// Build the lexer
// IMPORTANT: Platform pattern uses word boundaries (\b) to prevent "ios" matching inside "visionos" or "ipados"
var filterLexer = lexer.MustSimple([]lexer.SimpleRule{
	{Name: "Whitespace", Pattern: `\s+`},
	{Name: "Comma", Pattern: `,`},
	{Name: "Operator", Pattern: `>=|<=|>|<|=`},
	{Name: "Platform", Pattern: `(?i)\bios\b|\bipados\b|\bmacos\b|\btvos\b|\bvisionos\b|\bwatchos\b|\bandroid\b|\bchrome\b|\bwindows\b`},
	{Name: "Version", Pattern: `\d+(\.\d+)*|current`}, // Semver: 17, 17.4, 17.4.1, or "current"
})

// Build the parser
var filterParser = participle.MustBuild[filterExpr](
	participle.Lexer(filterLexer),
	participle.CaseInsensitive("Platform"),
	participle.Elide("Whitespace"),
)

// Parse parses a filter expression like "ios>=17.4,android>=10" or "android".
func Parse(expr string) (*Filter, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty filter expression")
	}

	ast, err := filterParser.ParseString("", expr)
	if err != nil {
		return nil, fmt.Errorf("invalid filter %q: %w", expr, err)
	}

	constraints := make([]Constraint, 0, len(ast.Constraints))
	for _, c := range ast.Constraints {
		constraint, err := convertConstraint(c)
		if err != nil {
			return nil, err
		}
		constraints = append(constraints, constraint)
	}

	return &Filter{Constraints: constraints}, nil
}

// convertConstraint converts AST constraint to domain Constraint
func convertConstraint(c *constraintExpr) (Constraint, error) {
	// Platform is already validated by lexer, just convert to type
	p := truststore.Platform(strings.ToLower(c.Platform))

	// Handle bare platform (no operator/version)
	if c.Operator == "" && c.Version == "" {
		return Constraint{
			Platform: p,
			Operator: OpGreaterEqual,
			Version:  nil, // nil means match all versions
		}, nil
	}

	// Require both operator and version
	if c.Operator == "" {
		return Constraint{}, fmt.Errorf("missing operator for %s", c.Platform)
	}
	if c.Version == "" {
		return Constraint{}, fmt.Errorf("missing version for %s%s", c.Platform, c.Operator)
	}

	// Handle "current" specially (Chrome only)
	if c.Version == "current" {
		return Constraint{
			Platform:  p,
			Operator:  Operator(c.Operator),
			Version:   nil,
			IsCurrent: true,
		}, nil
	}

	// Parse semver
	ver, err := semver.NewVersion(c.Version)
	if err != nil {
		return Constraint{}, fmt.Errorf("invalid version %q: %w", c.Version, err)
	}

	return Constraint{
		Platform: p,
		Operator: Operator(c.Operator),
		Version:  ver,
	}, nil
}
