package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/scan"
)

var version = "0.0.0-dev"

const defaultAPIURL = "https://api.ossprey.com"

func main() {
	root := &cobra.Command{
		Use:           "ossprey",
		Short:         "Ossprey supply-chain scanner",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	root.AddCommand(newScanCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newScanCmd() *cobra.Command {
	var (
		output          string
		verbose         bool
		local           bool
		dryRunSafe      bool
		dryRunMalicious bool
		apiURL          string
		apiKey          string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Catalogue a directory and emit an OSSBOM",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}

			sbom, err := scan.Run(cmd.Context(), scan.Options{
				Path:    path,
				Verbose: verbose,
			})
			if err != nil {
				return err
			}

			// --local: dump SBOM JSON to stdout and exit. Nothing else.
			if local {
				return sbom.Encode(os.Stdout)
			}

			// Vulnerability source:
			//  --dry-run-malicious: inject fake vuln locally
			//  --dry-run-safe:      no vulns
			//  default:             submit to API, copy returned vulns onto sbom
			switch {
			case dryRunMalicious:
				if err := scan.InjectTestVulnerability(sbom); err != nil {
					return err
				}
			case dryRunSafe:
				// no-op
			default:
				key := apiKey
				if key == "" {
					key = os.Getenv("OSSPREY_API_KEY")
				}
				if key == "" {
					key = os.Getenv("API_KEY")
				}
				c, err := client.New(apiURL, key)
				if err != nil {
					return err
				}
				raw, err := c.Validate(cmd.Context(), sbom.ToMiniBOM())
				if err != nil {
					var skipped *client.ErrSkipped
					if errors.As(err, &skipped) {
						msg := "Ossprey scan skipped: " + skipped.Message
						if skipped.ResetAt != "" {
							msg += " Quota resets at " + skipped.ResetAt + "."
						}
						fmt.Println(msg)
						return nil
					}
					return err
				}
				if err := sbom.ApplyAPIResponse(raw); err != nil {
					return fmt.Errorf("parse API response: %w", err)
				}
			}

			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("create output: %w", err)
				}
				defer f.Close()
				if err := sbom.Encode(f); err != nil {
					return err
				}
			}

			reports, hasMalware := scan.MalwareReports(sbom)
			if hasMalware {
				for _, msg := range reports {
					fmt.Println("Error: " + msg)
				}
				os.Exit(1)
			}

			fmt.Println("No malware found")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "write SBOM to file")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	cmd.Flags().BoolVar(&local, "local", false, "dump SBOM JSON to stdout and exit (no API submission, no verdict)")
	cmd.Flags().BoolVar(&dryRunSafe, "dry-run-safe", false, "skip API submission; emit empty vulnerability list")
	cmd.Flags().BoolVar(&dryRunMalicious, "dry-run-malicious", false, "skip API submission; inject test vulnerability against first component")
	cmd.Flags().StringVar(&apiURL, "url", defaultAPIURL, "Ossprey API URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Ossprey API key (or OSSPREY_API_KEY / API_KEY env var)")

	return cmd
}
