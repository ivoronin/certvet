package generate

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/bufbuild/protocompile"
	"github.com/ivoronin/certvet/internal/truststore"
	"github.com/ivoronin/certvet/internal/version"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// ChromeRootStoreURL is the URL to fetch the Chrome Root Store textproto.
const ChromeRootStoreURL = "https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT"

// ChromeProtoURL is the URL to fetch the Chrome Root Store proto schema.
const ChromeProtoURL = "https://chromium.googlesource.com/chromium/src/+/main/net/cert/root_store.proto?format=TEXT"

// ChromeGenerator implements StoreGenerator for Chrome Root Store data.
type ChromeGenerator struct{}

// Name returns the generator's display name.
func (ChromeGenerator) Name() string { return "Chrome" }

// Generate fetches Chrome Root Store data and returns TrustEntry structs.
func (ChromeGenerator) Generate() ([]TrustEntry, error) {
	protoContent, err := FetchChromeProto()
	if err != nil {
		return nil, fmt.Errorf("fetching proto: %w", err)
	}

	textprotoContent, err := FetchChromeRootStore()
	if err != nil {
		return nil, fmt.Errorf("fetching Chrome Root Store: %w", err)
	}
	_, anchors, err := ParseChromeTextproto(protoContent, textprotoContent)
	if err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}

	// Build fingerprint -> anchor map for looking up SCT constraints
	anchorByFP := make(map[truststore.Fingerprint]ChromeTrustAnchor, len(anchors))
	for _, anchor := range anchors {
		anchorByFP[anchor.Fingerprint] = anchor
	}

	// Synthesize versions from constraint boundaries
	versions := SynthesizeVersions(anchors)

	// Generate version-mapped fingerprints (constraints evaluated at generation time)
	versionMap := generateVersionMappedFingerprints(anchors, versions)

	// Flatten to TrustEntry structs
	var entries []TrustEntry
	for version, fingerprints := range versionMap {
		for _, fp := range fingerprints {
			entry := TrustEntry{
				Platform:    "chrome",
				Version:     version,
				Fingerprint: fp,
			}

			// Surface SCT constraints for all versions (time-aware validation)
			if anchor, ok := anchorByFP[fp]; ok {
				entry.SCTNotAfter = extractSCTNotAfter(&anchor)
			}

			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// ChromeTrustAnchor represents a parsed trust anchor from the Chrome Root Store.
type ChromeTrustAnchor struct {
	Fingerprint  truststore.Fingerprint // SHA256 fingerprint
	EVPolicyOIDs []string               // Extended Validation policy OIDs
	EUTL         bool                   // EU Trust List flag
	Constraints  []ChromeConstraint     // Trust constraints (multiple = AND logic)
}

// ChromeConstraint represents trust constraints for a Chrome certificate.
type ChromeConstraint struct {
	SCTNotAfterSec int64  // SCT must be before this Unix timestamp
	MinVersion     string // Minimum Chrome version for trust
	MaxVersionExcl string // Maximum Chrome version (exclusive) for trust
}

// extractSCTNotAfter finds the SCT-only constraint with the latest timestamp.
// Returns nil if no SCT-only constraints exist (version-only or no constraints).
// SCT-only means: has sct_not_after_sec but no version bounds.
// If multiple SCT-only blocks exist (OR logic), returns the latest (most permissive).
func extractSCTNotAfter(anchor *ChromeTrustAnchor) *time.Time {
	var latest int64
	found := false

	for _, c := range anchor.Constraints {
		// SCT-only constraint: has SCT but no version bounds
		if c.SCTNotAfterSec > 0 && c.MinVersion == "" && c.MaxVersionExcl == "" {
			if !found || c.SCTNotAfterSec > latest {
				latest = c.SCTNotAfterSec
				found = true
			}
		}
	}

	if !found {
		return nil
	}

	t := time.Unix(latest, 0).UTC()
	return &t
}

// FetchChromeRootStore fetches the Chrome Root Store textproto from Chromium source.
func FetchChromeRootStore() ([]byte, error) {
	data, err := FetchURL(ChromeRootStoreURL)
	if err != nil {
		return nil, fmt.Errorf("fetching chrome root store: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return decoded, nil
}

// FetchChromeProto fetches the Chrome Root Store proto schema.
func FetchChromeProto() ([]byte, error) {
	data, err := FetchURL(ChromeProtoURL)
	if err != nil {
		return nil, fmt.Errorf("fetching chrome proto: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}

	return decoded, nil
}

// CompileChromeProto compiles the proto schema and returns the RootStore message descriptor.
func CompileChromeProto(protoContent []byte) (protoreflect.MessageDescriptor, error) {
	// Compile the proto using protocompile
	compiler := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			Accessor: protocompile.SourceAccessorFromMap(map[string]string{
				"root_store.proto": string(protoContent),
			}),
		}),
	}

	files, err := compiler.Compile(context.Background(), "root_store.proto")
	if err != nil {
		return nil, fmt.Errorf("compiling proto: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no file descriptor produced")
	}

	fileDesc := files[0]
	rootStoreDesc := fileDesc.Messages().ByName("RootStore")
	if rootStoreDesc == nil {
		return nil, fmt.Errorf("RootStore message not found in proto")
	}

	return rootStoreDesc, nil
}

// ParseChromeTextproto parses Chrome Root Store textproto using dynamic protobuf.
// Returns the version number and list of trust anchors.
func ParseChromeTextproto(protoContent, textprotoContent []byte) (int, []ChromeTrustAnchor, error) {
	if len(textprotoContent) == 0 {
		return 0, nil, fmt.Errorf("empty textproto input")
	}

	// Compile the proto schema
	rootStoreDesc, err := CompileChromeProto(protoContent)
	if err != nil {
		return 0, nil, fmt.Errorf("compiling proto: %w", err)
	}

	// Create a dynamic message and unmarshal the textproto
	rootStore := dynamicpb.NewMessage(rootStoreDesc)
	if err := prototext.Unmarshal(textprotoContent, rootStore); err != nil {
		return 0, nil, fmt.Errorf("parsing textproto: %w", err)
	}

	// Extract version_major
	versionField := rootStoreDesc.Fields().ByName("version_major")
	version := int(rootStore.Get(versionField).Int())

	// Extract trust_anchors
	trustAnchorsField := rootStoreDesc.Fields().ByName("trust_anchors")
	trustAnchorsList := rootStore.Get(trustAnchorsField).List()

	anchors := make([]ChromeTrustAnchor, 0, trustAnchorsList.Len())
	for i := range trustAnchorsList.Len() {
		ta := trustAnchorsList.Get(i).Message()
		taDesc := ta.Descriptor()

		// Get sha256_hex (it's a oneof field)
		sha256HexField := taDesc.Fields().ByName("sha256_hex")
		sha256Hex := ta.Get(sha256HexField).String()
		if sha256Hex == "" {
			Log.Warn("skipping trust anchor %d: no SHA256 fingerprint", i)
			continue
		}

		fp, err := truststore.ParseFingerprint(sha256Hex)
		if err != nil {
			return 0, nil, fmt.Errorf("parsing fingerprint %q: %w", sha256Hex, err)
		}

		// Get ev_policy_oids
		evPolicyOidsField := taDesc.Fields().ByName("ev_policy_oids")
		evPolicyOidsList := ta.Get(evPolicyOidsField).List()
		evPolicyOids := make([]string, evPolicyOidsList.Len())
		for j := range evPolicyOidsList.Len() {
			evPolicyOids[j] = evPolicyOidsList.Get(j).String()
		}

		// Get eutl
		eutlField := taDesc.Fields().ByName("eutl")
		eutl := ta.Get(eutlField).Bool()

		anchor := ChromeTrustAnchor{
			Fingerprint:  fp,
			EVPolicyOIDs: evPolicyOids,
			EUTL:         eutl,
		}

		// Get constraints
		constraintsField := taDesc.Fields().ByName("constraints")
		constraintsList := ta.Get(constraintsField).List()
		for j := range constraintsList.Len() {
			c := constraintsList.Get(j).Message()
			cDesc := c.Descriptor()

			sctNotAfterField := cDesc.Fields().ByName("sct_not_after_sec")
			minVersionField := cDesc.Fields().ByName("min_version")
			maxVersionField := cDesc.Fields().ByName("max_version_exclusive")

			constraint := ChromeConstraint{
				SCTNotAfterSec: c.Get(sctNotAfterField).Int(),
				MinVersion:     c.Get(minVersionField).String(),
				MaxVersionExcl: c.Get(maxVersionField).String(),
			}
			anchor.Constraints = append(anchor.Constraints, constraint)
		}

		anchors = append(anchors, anchor)
	}

	return version, anchors, nil
}

// isTrustedInVersion determines if a certificate is trusted in a given Chrome version.
// Uses OR logic between constraint blocks: if ANY block passes, the cert is trusted.
// Per ADR-2, SCT constraints are ignored - only version constraints are evaluated.
func isTrustedInVersion(anchor *ChromeTrustAnchor, ver string) bool {
	// No constraints = unconditionally trusted in all versions
	if len(anchor.Constraints) == 0 {
		return true
	}

	// OR logic: if ANY constraint block passes, cert is trusted
	for _, c := range anchor.Constraints {
		if constraintPassesForVersion(c, ver) {
			return true
		}
	}

	return false
}

// constraintPassesForVersion evaluates a single constraint block for a given version.
// A constraint block passes if ALL its conditions are met (AND logic within block).
// Per ADR-2, SCT constraints are ignored - only version constraints are evaluated.
func constraintPassesForVersion(c ChromeConstraint, ver string) bool {
	// If constraint has no version constraints (SCT-only), treat as always passing
	// Per ADR-2: SCT constraints are removed/ignored
	if c.MinVersion == "" && c.MaxVersionExcl == "" {
		return true
	}

	// AND logic: all present conditions must pass

	// Check MinVersion constraint: ver >= MinVersion
	if c.MinVersion != "" {
		if !version.GreaterOrEqual(ver, c.MinVersion) {
			return false
		}
	}

	// Check MaxVersionExcl constraint: ver < MaxVersionExcl
	if c.MaxVersionExcl != "" {
		if !version.LessThan(ver, c.MaxVersionExcl) {
			return false
		}
	}

	return true
}


// generateVersionMappedFingerprints creates a map of version → fingerprints
// by evaluating constraints at generation time rather than runtime.
func generateVersionMappedFingerprints(anchors []ChromeTrustAnchor, versions []string) map[string][]truststore.Fingerprint {
	result := make(map[string][]truststore.Fingerprint, len(versions))

	for _, version := range versions {
		var fingerprints []truststore.Fingerprint
		for i := range anchors {
			if isTrustedInVersion(&anchors[i], version) {
				fingerprints = append(fingerprints, anchors[i].Fingerprint)
			}
		}
		// Sort for reproducibility
		sort.Slice(fingerprints, func(i, j int) bool {
			return fingerprints[i].String() < fingerprints[j].String()
		})
		result[version] = fingerprints
	}

	return result
}

// SynthesizeVersions derives Chrome versions from constraint boundaries.
// Returns versions like ["138", "139", "current"] for constraint-aware validation.
func SynthesizeVersions(anchors []ChromeTrustAnchor) []string {
	versionSet := make(map[string]struct{})

	for _, anchor := range anchors {
		for _, c := range anchor.Constraints {
			if c.MinVersion != "" {
				// Add the version and one below for boundary testing
				versionSet[c.MinVersion] = struct{}{}
				if v, err := strconv.Atoi(c.MinVersion); err == nil && v > 0 {
					versionSet[strconv.Itoa(v-1)] = struct{}{}
				}
			}
			if c.MaxVersionExcl != "" {
				// Add the version and one below for boundary testing
				versionSet[c.MaxVersionExcl] = struct{}{}
				if v, err := strconv.Atoi(c.MaxVersionExcl); err == nil && v > 0 {
					versionSet[strconv.Itoa(v-1)] = struct{}{}
				}
			}
		}
	}

	versions := make([]string, 0, len(versionSet)+1)
	for v := range versionSet {
		versions = append(versions, v)
	}

	// Sort numerically
	sort.Slice(versions, func(i, j int) bool {
		vi, _ := strconv.Atoi(versions[i])
		vj, _ := strconv.Atoi(versions[j])
		return vi < vj
	})

	// Always add "current" at the end
	versions = append(versions, "current")

	return versions
}
