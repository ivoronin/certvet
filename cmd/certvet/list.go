package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ivoronin/certvet/internal/filter"
	"github.com/ivoronin/certvet/internal/output"
	"github.com/ivoronin/certvet/internal/truststore"
)

var (
	listJSON   bool
	listFilter string
	listWide   bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List embedded trust store entries",
	Long:  `Display all root CA certificates in the embedded trust stores.`,
	Args:  cobra.NoArgs,
	Example: `  certvet list
  certvet list -j
  certvet list -f 'ios>=17'`,
	RunE: runList,
}

func init() {
	listCmd.Flags().BoolVarP(&listJSON, "json", "j", false, "Output in JSON format")
	listCmd.Flags().StringVarP(&listFilter, "filter", "f", "", "Filter expression (e.g., ios>=15,android>=10)")
	listCmd.Flags().BoolVarP(&listWide, "wide", "w", false, "Display full fingerprints without truncation")
}

func runList(cmd *cobra.Command, args []string) error {
	// Parse filter
	var f *filter.Filter
	if listFilter != "" {
		var err error
		f, err = filter.Parse(listFilter)
		if err != nil {
			return fmt.Errorf("invalid filter: %w", err)
		}
	}

	// Get and filter stores
	stores := filter.FilterStores(truststore.Stores, f)

	// Build entries
	entries := buildListEntries(stores, listJSON)

	if len(entries) == 0 {
		return nil // Empty result is not an error
	}

	// Output
	list := &output.StoreList{Entries: entries}
	format := output.FormatText
	if listJSON {
		format = output.FormatJSON
	}
	result, err := output.FormatOutput(list, format)
	if err != nil {
		return err
	}
	fmt.Println(result)

	return nil
}

// buildListEntries converts trust stores to list entries for output.
// When jsonMode is true, fingerprints are kept full; otherwise truncated to 4 octets.
func buildListEntries(stores []truststore.Store, jsonMode bool) []output.ListEntry {
	var entries []output.ListEntry

	for _, store := range stores {
		for _, fp := range store.Fingerprints {
			// Lookup certificate to get issuer
			issuer := "-"
			if cert := truststore.Certs[fp]; cert != nil {
				// Prefer CommonName, fallback to Organization
				if cert.Subject.CommonName != "" {
					issuer = cert.Subject.CommonName
				} else if len(cert.Subject.Organization) > 0 {
					issuer = cert.Subject.Organization[0]
				}
			}

			// Truncate fingerprint for text mode (unless wide mode)
			var displayFP string
			if !jsonMode && !listWide {
				displayFP = fp.Truncate(4)
			} else {
				displayFP = fp.String()
			}

			// Format constraints
			constraints := formatConstraints(store.ConstraintFor(fp))

			entries = append(entries, output.ListEntry{
				Platform:    string(store.Platform),
				Version:     store.Version,
				Fingerprint: displayFP,
				Issuer:      issuer,
				Constraints: constraints,
			})
		}
	}

	return entries
}

// formatConstraints returns a short string representation of constraints.
// Empty string if no constraints set.
// Format: NB:YYYY-MM-DD (NotBeforeMax), DT:YYYY-MM-DD (DistrustDate), SCT:YYYY-MM-DD (SCTNotAfter)
func formatConstraints(c truststore.Constraints) string {
	if c.IsEmpty() {
		return ""
	}

	var parts []string
	if c.NotBeforeMax != nil {
		parts = append(parts, "NB:"+c.NotBeforeMax.Format(truststore.DateFormat))
	}
	if c.DistrustDate != nil {
		parts = append(parts, "DT:"+c.DistrustDate.Format(truststore.DateFormat))
	}
	if c.SCTNotAfter != nil {
		parts = append(parts, "SCT:"+c.SCTNotAfter.Format(truststore.DateFormat))
	}
	return strings.Join(parts, ",")
}
