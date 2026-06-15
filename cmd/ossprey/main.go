package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/submit"
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
	root.AddCommand(newCheckCmd())
	for _, bin := range forward.Managers() {
		root.AddCommand(newForwardCmd(bin))
	}

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
				if err := submit.Validate(cmd.Context(), sbom, apiURL, apiKey); err != nil {
					if skipped := reportSkipped(err); skipped {
						return nil
					}
					return err
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

// newCheckCmd scans explicitly-named packages by ecosystem + name[@version],
// without needing a project directory.
func newCheckCmd() *cobra.Command {
	var (
		ecosystem       string
		apiURL          string
		apiKey          string
		dryRunSafe      bool
		dryRunMalicious bool
	)

	cmd := &cobra.Command{
		Use:   "check --eco-system <pypi|npm|github> <name[@version] | owner/repo[@ref]>...",
		Short: "Check named packages (or a github repo) for malware without a project directory",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ecosystem == "" {
				return errors.New("--eco-system is required (pypi or npm)")
			}

			specs := make([]check.Spec, 0, len(args))
			for _, a := range args {
				s, err := check.ParseSpec(ecosystem, a)
				if err != nil {
					return err
				}
				// `check` resolves latest for unpinned packages, failing closed:
				// if we can't pin a version we can't honestly check it.
				if s.Version == "" {
					v, err := registry.ResolveLatest(cmd.Context(), s.Ecosystem, s.Name)
					if err != nil {
						return fmt.Errorf("resolve latest version of %s: %w", s.Name, err)
					}
					s.Version = v
				}
				specs = append(specs, s)
			}

			sbom, err := check.Run(cmd.Context(), check.Options{
				Specs:           specs,
				APIURL:          apiURL,
				APIKey:          apiKey,
				DryRunSafe:      dryRunSafe,
				DryRunMalicious: dryRunMalicious,
			})
			if err != nil {
				if reportSkipped(err) {
					return nil
				}
				return err
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

	cmd.Flags().StringVarP(&ecosystem, "eco-system", "e", "", "package ecosystem: pypi, npm or github (required)")
	cmd.Flags().StringVar(&apiURL, "url", defaultAPIURL, "Ossprey API URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Ossprey API key (or OSSPREY_API_KEY / API_KEY env var)")
	cmd.Flags().BoolVar(&dryRunSafe, "dry-run-safe", false, "skip API submission; emit empty vulnerability list")
	cmd.Flags().BoolVar(&dryRunMalicious, "dry-run-malicious", false, "skip API submission; inject test vulnerability against first package")

	return cmd
}

// newForwardCmd wraps a package manager (npm/yarn/pip/poetry/uv): it checks the
// named packages, blocks on malware, and otherwise execs the real manager.
// Flag parsing is disabled so every argument reaches the real manager untouched;
// configuration comes from OSSPREY_API_URL / OSSPREY_API_KEY env vars.
func newForwardCmd(bin string) *cobra.Command {
	return &cobra.Command{
		Use:                bin + " [args...]",
		Short:              "Check then forward to " + bin + " (blocks install on malware)",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			apiURL := os.Getenv("OSSPREY_API_URL")
			if apiURL == "" {
				apiURL = defaultAPIURL
			}
			err := forward.Run(cmd.Context(), forward.Options{
				Bin:    bin,
				Args:   args,
				APIURL: apiURL,
				APIKey: os.Getenv("OSSPREY_API_KEY"),
			})
			switch {
			case err == nil:
				return nil
			case errors.Is(err, forward.ErrBlocked):
				os.Exit(1)
			default:
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					os.Exit(ee.ExitCode())
				}
				if reportSkipped(err) {
					return nil
				}
				return err
			}
			return nil
		},
	}
}

// reportSkipped prints a friendly quota-skip message and returns true when err
// is a *client.ErrSkipped; otherwise returns false.
func reportSkipped(err error) bool {
	var skipped *client.ErrSkipped
	if !errors.As(err, &skipped) {
		return false
	}
	msg := "Ossprey scan skipped: " + skipped.Message
	if skipped.ResetAt != "" {
		msg += " Quota resets at " + skipped.ResetAt + "."
	}
	fmt.Println(msg)
	return true
}
