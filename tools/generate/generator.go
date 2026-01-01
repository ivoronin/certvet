// Package generate provides trust store generation tools.
package generate

// CertGenerator generates certificate data (CCADB).
type CertGenerator interface {
	Name() string
	Generate() ([]Certificate, error)
}

// StoreGenerator generates trust store entries (vendor stores).
type StoreGenerator interface {
	Name() string
	Generate() ([]TrustEntry, error)
}
