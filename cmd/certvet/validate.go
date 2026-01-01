package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ivoronin/certvet/internal/fetcher"
	"github.com/ivoronin/certvet/internal/filter"
	"github.com/ivoronin/certvet/internal/output"
	"github.com/ivoronin/certvet/internal/truststore"
	"github.com/ivoronin/certvet/internal/validator"
)

var (
	validateJSON    bool
	validateFilter  string
	validateTimeout time.Duration
)

var validateCmd = &cobra.Command{
	Use:   "validate <endpoint>",
	Short: "Check certificate trust for an endpoint",
	Long:  `Fetch SSL certificate chain from endpoint and validate against mobile trust stores.`,
	Args:  cobra.ExactArgs(1),
	Example: `  certvet validate example.com
  certvet validate -j example.com
  certvet validate -f 'ios>=15' example.com`,
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().BoolVarP(&validateJSON, "json", "j", false, "Output in JSON format")
	validateCmd.Flags().StringVarP(&validateFilter, "filter", "f", "", "Filter expression (e.g., ios>=15,android>=10)")
	validateCmd.Flags().DurationVar(&validateTimeout, "timeout", 10*time.Second, "Connection timeout")
}

func runValidate(cmd *cobra.Command, args []string) error {
	endpoint := args[0]

	// Parse filter
	var f *filter.Filter
	if validateFilter != "" {
		var err error
		f, err = filter.Parse(validateFilter)
		if err != nil {
			return fmt.Errorf("invalid filter: %w", err)
		}
	}

	// Fetch chain
	chain, err := fetcher.FetchCertChain(endpoint, validateTimeout)
	if err != nil {
		return err
	}

	// Get and filter stores
	stores := filter.FilterStores(truststore.Stores, f)

	if len(stores) == 0 {
		return fmt.Errorf("no trust stores match filter")
	}

	// Validate
	results := validator.ValidateChain(chain, stores)

	// Check all passed
	allPassed := true
	for _, r := range results {
		if !r.Trusted {
			allPassed = false
			break
		}
	}

	// Build report
	report := &truststore.ValidationReport{
		Endpoint:    endpoint,
		Timestamp:   time.Now(),
		ToolVersion: Version,
		Chain:       *chain,
		Results:     results,
		AllPassed:   allPassed,
	}

	// Output
	format := output.FormatText
	if validateJSON {
		format = output.FormatJSON
	}
	vo := output.NewValidationOutput(report)
	result, err := output.FormatOutput(vo, format)
	if err != nil {
		return err
	}

	fmt.Println(result)

	// Exit with trust fail code if not all passed
	if !allPassed {
		os.Exit(ExitTrustFail)
	}
	return nil
}
