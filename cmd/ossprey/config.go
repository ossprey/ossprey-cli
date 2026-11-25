package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/config"
	"github.com/ossprey/ossprey-cli/internal/env"
)

// loadSettings returns the machine's scan settings (config.json with
// OSSPREY_SCAN_DEPTH and OSSPREY_SCAN_IGNORE laid over it). A problem with
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
		Short: "Manage this machine's scan settings (depth, ignored paths)",
		Long: `Store scan settings on this machine, so they apply to every scan and every
forwarded install without being set each time.

  scan.depth    how many directory levels a project scan reads: 1 is the scanned
                directory's own files, 0 the whole tree. Unset, ` + "`ossprey scan`" + ` reads
                the whole tree and a forwarded install picks its own depth.
  scan.ignore   paths left out of every project scan, as globs relative to the
                scanned directory: ` + "`wf`" + ` is the top-level wf directory, ` + "`**/fixtures`" + `
                a fixtures directory at any depth. A matching directory is
                skipped whole.

Settings are stored on this machine, in config.json beside your login, and are
never read from the repository being scanned. OSSPREY_SCAN_DEPTH replaces the
stored depth, and OSSPREY_SCAN_IGNORE (comma or newline separated) adds patterns.
A flag on ` + "`ossprey scan`" + ` wins over both.`,
	}
	cmd.AddCommand(newConfigListCmd(), newConfigSetCmd(), newConfigUnsetCmd(), newConfigAddCmd(), newConfigRemoveCmd())
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
				fmt.Fprintln(out, "No scan settings: `ossprey scan` reads the whole tree and nothing is ignored.")
				fmt.Fprintln(out, "Set one with `ossprey config set scan.depth <n>` or `ossprey config add scan.ignore <pattern>`.")
				fmt.Fprintf(out, "\nConfig file: %s\n", path)
				return nil
			}
			switch {
			case fromEnv.Scan.Depth != nil:
				fmt.Fprintf(out, "%s = %d  (from %s", config.KeyScanDepth, *fromEnv.Scan.Depth, env.ScanDepthEnv)
				if file.Scan.Depth != nil {
					fmt.Fprintf(out, ", replacing %d from the file", *file.Scan.Depth)
				}
				fmt.Fprintln(out, ")")
			case file.Scan.Depth != nil:
				fmt.Fprintf(out, "%s = %d\n", config.KeyScanDepth, *file.Scan.Depth)
			}
			if len(file.Scan.Ignore) > 0 || len(fromEnv.Scan.Ignore) > 0 {
				fmt.Fprintf(out, "%s:\n", config.KeyScanIgnore)
				for _, p := range file.Scan.Ignore {
					fmt.Fprintf(out, "  %s\n", p)
				}
				for _, p := range fromEnv.Scan.Ignore {
					if !slices.Contains(file.Scan.Ignore, p) {
						fmt.Fprintf(out, "  %s  (from %s)\n", p, config.IgnoreEnv)
					}
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

// checkKey rejects a key that is not a setting, or one that takes the other
// kind of verb (set/unset for a value, add/remove for a list).
func checkKey(key string, verbs ...string) error {
	if !slices.Contains(config.Keys, key) {
		return fmt.Errorf("unknown setting %q; settings are %s", key, strings.Join(config.Keys, ", "))
	}
	isList := key == config.KeyScanIgnore
	verb := verbs[0]
	if isList != (verb == "add" || verb == "remove") {
		if isList {
			return fmt.Errorf("%s is a list: use `ossprey config add %s <pattern>` or `remove`", key, key)
		}
		return fmt.Errorf("%s is a single value: use `ossprey config set %s <value>`", key, key)
	}
	return nil
}

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "set <key> <value>",
		Short:   "Set a scan setting",
		Example: "  ossprey config set scan.depth 1",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkKey(args[0], "set"); err != nil {
				return err
			}
			d, err := config.ParseDepth(args[1])
			if err != nil {
				return err
			}
			if err := editConfig(func(s *config.Settings) error { s.Scan.Depth = &d; return nil }); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Set %s = %d\n", config.KeyScanDepth, d)
			return nil
		},
	}
}

func newConfigUnsetCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "unset <key>",
		Short:   "Remove a scan setting (for scan.ignore, every pattern)",
		Example: "  ossprey config unset scan.depth",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			if !slices.Contains(config.Keys, key) {
				return fmt.Errorf("unknown setting %q; settings are %s", key, strings.Join(config.Keys, ", "))
			}
			if err := editConfig(func(s *config.Settings) error {
				if key == config.KeyScanDepth {
					s.Scan.Depth = nil
				} else {
					s.Scan.Ignore = nil
				}
				return nil
			}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Unset %s\n", key)
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
			if err := checkKey(args[0], "add"); err != nil {
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
			if err := checkKey(args[0], "remove"); err != nil {
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
