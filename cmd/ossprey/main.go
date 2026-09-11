package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/alert"
	"github.com/ossprey/ossprey-cli/internal/ansi"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/env"
	"github.com/ossprey/ossprey-cli/internal/forward"
	monitorpkg "github.com/ossprey/ossprey-cli/internal/monitor"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/submit"
)

var version = "0.0.0-dev"

const defaultAPIURL = "https://api.ossprey.com"

// scanTimeout resolves the whole-scan deadline from --timeout, else OSSPREY_SCAN_TIMEOUT, else none: an interactive scan has no external budget to beat.
func scanTimeout(flag time.Duration) time.Duration {
	if flag > 0 {
		return flag
	}
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("OSSPREY_SCAN_TIMEOUT"))); err == nil && d > 0 {
		return d
	}
	return 0
}

func main() {
	ansi.Enable(os.Stdout)
	ansi.Enable(os.Stderr)
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "ossprey: fatal: %v\n%s\n", r, debug.Stack())
			os.Exit(2)
		}
	}()

	root := &cobra.Command{
		Use:           "ossprey",
		Short:         "Ossprey supply-chain scanner",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	root.AddCommand(newInitCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newCheckCmd())
	root.AddCommand(newLoginCmd())
	root.AddCommand(newLogoutCmd())
	root.AddCommand(newWhoamiCmd())
	root.AddCommand(newUpdateCmd())
	root.AddCommand(newShimCmd())
	root.AddCommand(newPrecommitCmdWithHooks())
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
		output              string
		reportPath          string
		verbose             bool
		local               bool
		dryRunSafe          bool
		dryRunMalicious     bool
		failOnInformational bool
		apiURL              string
		apiKey              string
		noVersionLookup     bool
		skipCI              bool
		passive             bool
		cacheScanOnly       bool
		monitorID           string
		timeout             time.Duration
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Catalogue a directory and emit an OSSBOM",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if skipCI || env.SkipCI() {
				fmt.Println("Ossprey scan skipped (skip-ci)")
				return nil
			}
			// A monitor id names where the scan should land and cannot fetch a
			// verdict, so it always implies passive.
			monitor := monitorID
			fromEnv := false
			if monitor == "" {
				monitor, fromEnv = env.MonitorID(), env.MonitorID() != ""
			}
			passiveMode := passive || cacheScanOnly || env.Passive() || monitor != ""

			// Validated here, before passive mode's fail-open can swallow it. A
			// monitor id names where the scan should land, so a typo must be an
			// error the user sees, not a warning on a scan that went nowhere.
			if monitor != "" && !monitorpkg.ValidToken(monitor) {
				return fmt.Errorf("invalid monitor id %q: expected ospi_ followed by 64 hex characters", monitor)
			}
			if monitor != "" {
				warnMonitorInEffect(monitor, fromEnv)
			}

			path := "."
			if len(args) == 1 {
				path = args[0]
			}

			// --local owns stdout and never reaches a verdict, so there is no
			// report to write; refuse the combination rather than leave an
			// empty or stale file behind for CI to read as "clean".
			if local && reportPath != "" {
				return errors.New("--local and --report are mutually exclusive: --local exits before any verdict")
			}
			// Same reason: a passive scan submits and returns without fetching
			// findings, so a report file would claim a verdict nobody checked.
			// Refused rather than silently skipped, which is what the old
			// --ci-cache-scan-only did and which left CI reading a stale file.
			if passiveMode && reportPath != "" {
				return errors.New("--passive and --report are mutually exclusive: a passive scan never reaches a verdict")
			}
			if passiveMode && local {
				return errors.New("--passive and --local are mutually exclusive: --local never submits the scan")
			}

			sbom, err := scan.Run(cmd.Context(), scan.Options{
				Path:              path,
				Verbose:           verbose,
				SkipVersionLookup: noVersionLookup,
				Timeout:           scanTimeout(timeout),
			})
			if err != nil {
				// Passive monitoring runs in front of other people's work, so a
				// cataloguing failure is reported and shrugged off rather than
				// turned into a non-zero exit somebody has to chase.
				if passiveMode {
					fmt.Fprintf(os.Stderr, "ossprey: warning: could not catalogue %s: %v\n", path, err)
					return nil
				}
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
			case passiveMode:
				if err := submit.Post(cmd.Context(), sbom, apiURL, apiKey, monitor); err != nil {
					fmt.Fprintf(os.Stderr, "ossprey: warning: could not post scan: %v\n", err)
				} else {
					fmt.Println("Scan submitted; results will appear in the Ossprey dashboard")
				}
			default:
				if err := submit.Validate(cmd.Context(), sbom, apiURL, apiKey); err != nil {
					if skipped, ok := printSkipped(err); ok {
						return writeReport(reportPath, scan.SkippedReport(sbom, skipped.Message, skipped.ResetAt))
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

			// A passive scan deliberately reaches no verdict, so there is nothing
			// to report and nothing to exit non-zero over.
			if passiveMode {
				return nil
			}

			// Written before the exit below: a malware verdict is exactly the
			// one CI most needs the report for.
			if err := writeReport(reportPath, scan.NewReport(sbom, failingFloor(failOnInformational))); err != nil {
				return err
			}

			if reportMalware(sbom, failingFloor(failOnInformational)) {
				os.Exit(1)
			}

			fmt.Println("No malware found")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "write SBOM to file")
	cmd.Flags().StringVar(&reportPath, "report", "", "write a JSON verdict report (verdict + findings) to file")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "verbose logging")
	cmd.Flags().BoolVar(&local, "local", false, "dump SBOM JSON to stdout and exit (no API submission, no verdict)")
	cmd.Flags().BoolVar(&failOnInformational, "fail-on-informational", false, "also fail on informational findings, which are reported but exit 0 by default")
	cmd.Flags().BoolVar(&dryRunSafe, "dry-run-safe", false, "skip API submission; emit empty vulnerability list")
	cmd.Flags().BoolVar(&dryRunMalicious, "dry-run-malicious", false, "skip API submission; inject test vulnerability against first component")
	cmd.Flags().BoolVar(&noVersionLookup, "no-version-lookup", false, "don't query the registry to resolve unpinned dependencies; leave them versionless")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "give up cataloging after this long and emit what resolved (or OSSPREY_SCAN_TIMEOUT; 0 disables)")
	cmd.Flags().StringVar(&apiURL, "url", defaultAPIURL, "Ossprey API URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Ossprey API key (or OSSPREY_API_KEY / API_KEY env var; optional after `ossprey login`)")
	cmd.Flags().BoolVar(&skipCI, "skip-ci", false, "skip the Ossprey scan entirely and exit 0 (or OSSPREY_SKIP_CI env var)")
	cmd.Flags().BoolVar(&passive, "passive", false, "submit the scan for the dashboard without waiting for a verdict; always exits 0 (or OSSPREY_PASSIVE env var)")
	cmd.Flags().StringVar(&monitorID, "monitor", "", "submit passively through a monitor's id, with no login or API key (or OSSPREY_MONITOR_ID env var)")
	// The original CI-facing spelling of --passive. Hidden rather than removed:
	// it is set in pipelines we do not control, so it keeps working, but there
	// is only one name left to teach.
	cmd.Flags().BoolVar(&cacheScanOnly, "ci-cache-scan-only", false, "deprecated alias for --passive")
	_ = cmd.Flags().MarkHidden("ci-cache-scan-only")
	cmd.MarkFlagsMutuallyExclusive("skip-ci", "passive", "ci-cache-scan-only")
	cmd.MarkFlagsMutuallyExclusive("skip-ci", "monitor")

	return cmd
}

// newCheckCmd scans explicitly-named packages by ecosystem + name[@version],
// without needing a project directory.
func newCheckCmd() *cobra.Command {
	var (
		ecosystem           string
		apiURL              string
		apiKey              string
		reportPath          string
		dryRunSafe          bool
		dryRunMalicious     bool
		failOnInformational bool
	)

	cmd := &cobra.Command{
		Use:   "check --eco-system <pypi|npm> <name[@version]>...",
		Short: "Check named packages for malware without a project directory",
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
				if skipped, ok := printSkipped(err); ok {
					// sbom is nil when Run failed, so there is no component
					// count to report — only the skip itself.
					return writeReport(reportPath, scan.SkippedReport(
						ossbom.New(ossbom.Environment{}), skipped.Message, skipped.ResetAt))
				}
				return err
			}

			if err := writeReport(reportPath, scan.NewReport(sbom, failingFloor(failOnInformational))); err != nil {
				return err
			}

			if reportMalware(sbom, failingFloor(failOnInformational)) {
				os.Exit(1)
			}

			fmt.Println("No malware found")
			return nil
		},
	}

	cmd.Flags().StringVarP(&ecosystem, "eco-system", "e", "", "package ecosystem: pypi or npm (required)")
	cmd.Flags().StringVar(&reportPath, "report", "", "write a JSON verdict report (verdict + findings) to file")
	cmd.Flags().StringVar(&apiURL, "url", defaultAPIURL, "Ossprey API URL")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Ossprey API key (or OSSPREY_API_KEY / API_KEY env var; optional after `ossprey login`)")
	cmd.Flags().BoolVar(&failOnInformational, "fail-on-informational", false, "also fail on informational findings, which are reported but exit 0 by default")
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
				Bin:       bin,
				Args:      args,
				APIURL:    apiURL,
				APIKey:    os.Getenv("OSSPREY_API_KEY"),
				SkipCI:    env.SkipCI(),
				Passive:   env.Passive() || env.MonitorID() != "",
				MonitorID: env.MonitorID(),
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

// reportMalware prints one "Error: ..." line per failing malware finding, plus a
// "Note: ..." line per informational one, and reports whether any finding fails.
// Shared by scan, check and init so the verdict wording and the exit decision
// cannot drift apart between them. Callers own the os.Exit(1) and their own
// success message.
//
// An informational finding is printed and then deliberately exits 0, the same
// posture as a quota skip: a real API result the user is told about but is not
// blocked by.
var verdictOut io.Writer = os.Stdout

func reportMalware(sbom *ossbom.SBOM, floor severity.Level) bool {
	summary, hasMalware := scan.MalwareReports(sbom, floor)
	profile := ansi.Detect(verdictOut)
	if hasMalware {
		fmt.Fprint(verdictOut, alert.Malware(summary.Alert(), "", profile))
	}
	for _, msg := range summary.Failing {
		fmt.Fprintln(verdictOut, profile.Red("Error: "+msg))
	}
	for _, msg := range summary.Informational {
		fmt.Fprintln(verdictOut, "Note: "+msg)
	}
	return hasMalware
}

// failingFloor is the severity at or above which a finding fails this run.
// --fail-on-informational lowers it so that everything the scan reports fails,
// which is the stricter direction; there is deliberately no way to raise it,
// because that would let a real detection pass.
func failingFloor(failOnInformational bool) severity.Level {
	if failOnInformational {
		return severity.Info
	}
	return severity.FailingFloor
}

// printSkipped prints a friendly quota-skip message and returns the typed
// error when err is a *client.ErrSkipped; ok is false otherwise. Callers treat
// a skip as success (exit 0) — a quota limit must not fail someone's build.
func printSkipped(err error) (skipped *client.ErrSkipped, ok bool) {
	if !errors.As(err, &skipped) {
		return nil, false
	}
	msg := "Ossprey scan skipped: " + skipped.Message
	if skipped.ResetAt != "" {
		msg += " Quota resets at " + skipped.ResetAt + "."
	}
	fmt.Println(msg)
	return skipped, true
}

// reportSkipped reports whether err is a quota skip, printing the message.
func reportSkipped(err error) bool {
	_, ok := printSkipped(err)
	return ok
}

// writeReport writes the JSON report when --report asked for one. Never to
// stdout: `ossprey scan --local` puts the OSSBOM there and CI parses it.
func writeReport(path string, r scan.Report) error {
	if path == "" {
		return nil
	}
	return scan.WriteReport(path, r)
}

// warnMonitorInEffect says, every time, that this scan will not block.
//
// A monitor does two things worth announcing: it turns the malware gate off,
// and it files the scan under whoever owns the id rather than under this
// machine's own account. Both are the point when a person typed --monitor, and
// both are a takeover when OSSPREY_MONITOR_ID was set by someone else -- a
// shared runner, a workflow env: block, a stray export in an image. The two are
// indistinguishable from here, so neither is silent: the env case names the
// variable so an operator who did not set it can see where it came from.
func warnMonitorInEffect(monitor string, fromEnv bool) {
	source := "--monitor"
	if fromEnv {
		source = env.MonitorIDEnv
	}
	fmt.Fprintf(os.Stderr,
		"ossprey: passive monitor %s (via %s): malware will NOT fail this scan, and results go to that monitor's account.\n",
		redactMonitor(monitor), source)
}

// redactMonitor shows enough of an id to recognise it, never enough to reuse
// it: this goes to stderr, which on CI is a log a lot of people can read.
func redactMonitor(monitor string) string {
	const shown = len("ospi_") + 8
	if len(monitor) <= shown {
		return monitor
	}
	return monitor[:shown] + "..."
}
