// Package validator provides certificate chain validation against trust stores.
package validator

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ivoronin/certvet/internal/truststore"
)

// getCertByFingerprint looks up a certificate by fingerprint.
// Tests can override this variable to inject mock certificates.
var getCertByFingerprint = func(fp truststore.Fingerprint) *x509.Certificate {
	return truststore.Certs[fp]
}

// ValidateChain validates a certificate chain against multiple trust stores.
// Returns results sorted by platform (alphabetically) and version (ascending).
func ValidateChain(chain *truststore.CertChain, stores []truststore.Store) []truststore.TrustResult {
	if len(stores) == 0 {
		return nil
	}

	// Validate in parallel
	results := make([]truststore.TrustResult, len(stores))
	var wg sync.WaitGroup

	for i, store := range stores {
		wg.Add(1)
		go func(idx int, s truststore.Store) {
			defer wg.Done()
			results[idx] = validateAgainstStore(chain, s)
		}(i, store)
	}

	wg.Wait()

	return results
}

func validateAgainstStore(chain *truststore.CertChain, store truststore.Store) truststore.TrustResult {
	pv := truststore.PlatformVersion{Platform: store.Platform, Version: store.Version}
	result := truststore.TrustResult{Platform: pv}

	// Build root CA pool from trust store, tracking missing certs
	roots := x509.NewCertPool()
	var rootCerts []*x509.Certificate
	missingFingerprints := make(map[truststore.Fingerprint]bool)

	for _, fp := range store.Fingerprints {
		cert := getCertByFingerprint(fp)
		if cert != nil {
			roots.AddCert(cert)
			rootCerts = append(rootCerts, cert)
		} else {
			missingFingerprints[fp] = true
		}
	}

	if len(rootCerts) == 0 {
		result.FailureReason = "no valid root certificates in trust store"
		return result
	}

	// Build intermediates pool
	intermediates := x509.NewCertPool()
	for _, cert := range chain.Intermediates {
		intermediates.AddCert(cert)
	}

	// Verify the chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	chains, err := chain.ServerCert.Verify(opts)
	if err != nil {
		// Check if chain terminates at a known but unavailable root
		if n := len(chain.Intermediates); n > 0 {
			fp := truststore.FingerprintFromCert(chain.Intermediates[n-1])
			if missingFingerprints[fp] {
				result.FailureReason = fmt.Sprintf("chain roots at known CA (fingerprint %s) but certificate data unavailable", fp.String())
				return result
			}
		}
		result.FailureReason = parseVerifyError(err)
		return result
	}

	// Chain verified - find which root CA was used
	if len(chains) > 0 && len(chains[0]) > 0 {
		result.VerifiedChain = chains[0]
		rootCert := chains[0][len(chains[0])-1]
		result.MatchedCA = rootCert.Subject.CommonName
		if result.MatchedCA == "" && len(rootCert.Subject.Organization) > 0 {
			result.MatchedCA = rootCert.Subject.Organization[0]
		}

		// Check date constraints on the matched root CA
		rootFP := truststore.FingerprintFromCert(rootCert)
		constraints := store.ConstraintFor(rootFP)
		if violation := checkConstraints(chain, constraints); violation != "" {
			result.Trusted = false
			result.FailureReason = violation
			return result
		}
	}

	result.Trusted = true
	return result
}

// checkConstraints validates chain against date constraints.
// Returns empty string if all constraints pass, otherwise returns violation description.
func checkConstraints(chain *truststore.CertChain, constraints truststore.Constraints) string {
	if constraints.IsEmpty() {
		return ""
	}

	now := time.Now()

	// Check NotBeforeMax: server cert's NotBefore must be <= this date
	// (certificates issued after this date are not trusted)
	if constraints.NotBeforeMax != nil {
		if chain.ServerCert.NotBefore.After(*constraints.NotBeforeMax) {
			return fmt.Sprintf("certificate issued after trust cutoff (%s > %s)",
				chain.ServerCert.NotBefore.Format(truststore.DateFormat),
				constraints.NotBeforeMax.Format(truststore.DateFormat))
		}
	}

	// Check DistrustDate: CA is completely distrusted after this date
	if constraints.DistrustDate != nil {
		if now.After(*constraints.DistrustDate) {
			return fmt.Sprintf("CA distrusted since %s",
				constraints.DistrustDate.Format(truststore.DateFormat))
		}
	}

	// Check SCTNotAfter: SCT timestamp must be <= this date
	if constraints.SCTNotAfter != nil {
		// Check all SCTs - at least one must be valid
		if len(chain.SCTs) == 0 {
			return fmt.Sprintf("SCT required but none found (deadline: %s)",
				constraints.SCTNotAfter.Format(truststore.DateFormat))
		}

		hasValidSCT := false
		for _, sct := range chain.SCTs {
			if !sct.Timestamp.After(*constraints.SCTNotAfter) {
				hasValidSCT = true
				break
			}
		}
		if !hasValidSCT {
			return fmt.Sprintf("all SCTs issued after deadline (%s)",
				constraints.SCTNotAfter.Format(truststore.DateFormat))
		}
	}

	return ""
}

func parseVerifyError(err error) string {
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return "certificate signed by unknown authority"
	}

	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		switch certInvalid.Reason {
		case x509.Expired:
			return "certificate has expired or is not yet valid"
		case x509.NotAuthorizedToSign:
			return "certificate is not authorized to sign other certificates"
		case x509.TooManyIntermediates:
			return "too many intermediates for path length constraint"
		case x509.IncompatibleUsage:
			return "certificate specifies an incompatible key usage"
		case x509.NameMismatch:
			return "issuer name does not match subject"
		case x509.CANotAuthorizedForThisName:
			return "CA is not authorized for this name"
		default:
			if certInvalid.Detail != "" {
				return certInvalid.Detail
			}
		}
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return fmt.Sprintf("certificate is not valid for %s", hostnameErr.Host)
	}

	return err.Error()
}
