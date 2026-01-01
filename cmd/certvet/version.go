package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var versionJSON bool

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version and trust store update date",
	Long:  `Display certvet version and when the embedded trust stores were last updated.`,
	Args:  cobra.NoArgs,
	RunE:  runVersion,
}

func init() {
	versionCmd.Flags().BoolVarP(&versionJSON, "json", "j", false, "Output in JSON format")
}

func runVersion(cmd *cobra.Command, args []string) error {
	if versionJSON {
		info := struct {
			Version string `json:"version"`
		}{
			Version: Version,
		}
		out, err := json.Marshal(info)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("certvet %s\n", Version)
	}
	return nil
}
