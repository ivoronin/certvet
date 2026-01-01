//go:debug x509negativeserial=1

package main

import (
	"os"

	"github.com/spf13/cobra"
)

// Version is set via ldflags at build time.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "certvet",
	Short: "Check SSL certificate trust across platforms",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(ExitInputError)
	}
}
