package main

import (
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/config"
)

// loadSettings returns the machine's scan settings (config.json plus
// OSSPREY_SCAN_IGNORE). A problem with
// them is reported and survived, as loadTrust does: a setting that could not
// be read is not applied, which only ever means more is scanned.
func loadSettings(w io.Writer) config.Settings {
	s, err := config.Load()
	if err != nil {
		fmt.Fprintf(w, "ossprey: warning: %v (settings that could not be read are not applied, so more is scanned)\n", err)
	}
	return s
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage this machine's scan settings (paths every scan leaves out)",
		Long: `Store paths on this machine that every project scan leaves out, so they apply
to every scan and every forwarded install without being typed each time.

  scan.ignore   globs relative to the scanned directory: ` + "`wf`" + ` is the top-level
                wf directory, ` + "`**/fixtures`" + ` a fixtures directory at any depth. A
                matching directory is skipped whole.

Settings are stored on this machine, in config.json beside your login, and are
never read from the repository being scanned. OSSPREY_SCAN_IGNORE (comma or
newline separated) and ` + "`ossprey scan --ignore`" + ` add patterns to them.`,
	}
	cmd.AddCommand(newConfigListCmd(), newConfigAddCmd(), newConfigRemoveCmd(), newConfigUnsetCmd())
	return cmd
}

func newConfigListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the scan settings, and where each comes from",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			path, err := config.Path()
			if err != nil {
				return err
			}
			file, fileErr := config.LoadFile()
			fromEnv, envErr := config.FromEnv()
			if err := errors.Join(fileErr, envErr); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "ossprey: warning: %v\n", err)
			}
			if file.Empty() && fromEnv.Empty() {
				fmt.Fprintln(out, "Nothing is ignored; every scan reads the whole project.")
				fmt.Fprintln(out, "Add a path with `ossprey config add scan.ignore <pattern>`.")
				fmt.Fprintf(out, "\nConfig file: %s\n", path)
				return nil
			}
			fmt.Fprintf(out, "%s:\n", config.KeyScanIgnore)
			for _, p := range file.Scan.Ignore {
				fmt.Fprintf(out, "  %s\n", p)
			}
			for _, p := range fromEnv.Scan.Ignore {
				if !slices.Contains(file.Scan.Ignore, p) {
					fmt.Fprintf(out, "  %s  (from %s)\n", p, config.IgnoreEnv)
				}
			}
			fmt.Fprintf(out, "\nConfig file: %s\n", path)
			return nil
		},
	}
}

// editConfig loads config.json, applies change and saves it. A file that is
// present but cannot be fully read is refused rather than overwritten:
// writing back only what parsed would delete the rest.
func editConfig(change func(*config.Settings) error) error {
	current, err := config.LoadFile()
	if err != nil {
		return fmt.Errorf("%w; fix or remove the file before changing it", err)
	}
	if err := change(&current); err != nil {
		return err
	}
	return config.Save(current)
}

// checkKey rejects anything but the one setting there is.
func checkKey(key string) error {
	if key != config.KeyScanIgnore {
		return fmt.Errorf("unknown setting %q; the only setting is %s", key, config.KeyScanIgnore)
	}
	return nil
}

func newConfigUnsetCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "unset scan.ignore",
		Short:   "Remove every stored ignore pattern",
		Example: "  ossprey config unset scan.ignore",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkKey(args[0]); err != nil {
				return err
			}
			if err := editConfig(func(s *config.Settings) error { s.Scan.Ignore = nil; return nil }); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Unset %s\n", config.KeyScanIgnore)
			return nil
		},
	}
}

// normalizePatterns validates every pattern before anything is written, so a
// bad one leaves the file as it was.
func normalizePatterns(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for _, a := range args {
		n, err := config.NormalizeIgnore(a)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func newConfigAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add scan.ignore <pattern>...",
		Short: "Add paths every project scan leaves out",
		Example: `  ossprey config add scan.ignore wf
  ossprey config add scan.ignore '**/fixtures' 'docs/**/*.md'`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkKey(args[0]); err != nil {
				return err
			}
			add, err := normalizePatterns(args[1:])
			if err != nil {
				return err
			}
			if err := editConfig(func(s *config.Settings) error {
				for _, p := range add {
					if !slices.Contains(s.Scan.Ignore, p) {
						s.Scan.Ignore = append(s.Scan.Ignore, p)
					}
				}
				return nil
			}); err != nil {
				return err
			}
			for _, p := range add {
				fmt.Fprintf(cmd.OutOrStdout(), "Ignoring %s\n", p)
			}
			return nil
		},
	}
}

func newConfigRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove scan.ignore <pattern>...",
		Short:   "Stop ignoring paths",
		Example: "  ossprey config remove scan.ignore wf",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkKey(args[0]); err != nil {
				return err
			}
			drop, err := normalizePatterns(args[1:])
			if err != nil {
				return err
			}
			removed := 0
			if err := editConfig(func(s *config.Settings) error {
				next := config.Without(s.Scan.Ignore, drop)
				removed = len(s.Scan.Ignore) - len(next)
				if removed == 0 {
					return fmt.Errorf("none of those patterns is in the config (patterns set through %s are removed there)", config.IgnoreEnv)
				}
				s.Scan.Ignore = next
				return nil
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %d pattern(s)\n", removed)
			return nil
		},
	}
}
