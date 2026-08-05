package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/shim"
)

func newShimCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shim",
		Short: "Intercept npm/pip/… installs by putting ossprey ahead of them on PATH",
		Long: `Install PATH shims so package installs are scanned automatically.

A shim is a small script named after the package manager, in a directory placed
at the front of your PATH. Typing ` + "`npm install left-pad`" + ` runs the shim, which
checks the packages for malware and then runs the real npm. Commands that do not
install anything (` + "`npm run`, `poetry run`" + `, …) are passed straight through.

Because a shim is a real executable rather than a shell alias, it also covers
Makefiles, CI steps, and the commands coding agents run for you.`,
	}
	cmd.AddCommand(newShimInstallCmd(), newShimUninstallCmd(), newShimStatusCmd(), newShimDirCmd())
	return cmd
}

func newShimInstallCmd() *cobra.Command {
	var (
		managers  []string
		all       bool
		noPath    bool
		dir       string
		binary    string
		printOnly bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install PATH shims for the supported package managers",
		Args:  cobra.NoArgs,
		Long: `Write the shim scripts and put their directory at the front of your PATH.

By default only managers you actually have installed are shimmed. Safe to re-run:
it is also how you re-point existing shims after moving the ossprey binary.`,
		Example: `  # Shim every package manager found on this machine
  ossprey shim install

  # Just npm and pip, and don't touch my shell profiles
  ossprey shim install --managers npm,pip --no-path

  # Show what would be written, change nothing
  ossprey shim install --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := shim.Options{
				Dir:          dir,
				Binary:       binary,
				Managers:     managers,
				All:          all,
				SkipProfiles: noPath,
			}
			if printOnly {
				return previewInstall(opts)
			}

			res, err := shim.Install(opts)
			if err != nil {
				return err
			}
			printInstallResult(res, noPath)
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&managers, "managers", nil,
		"only shim these commands (default: every supported manager found on PATH; supported: "+strings.Join(shim.DefaultManagers(), ", ")+")")
	cmd.Flags().BoolVar(&all, "all", false, "also shim supported managers that aren't installed yet")
	cmd.Flags().BoolVar(&noPath, "no-path", false, "write the shims but don't touch shell profiles (set PATH yourself — for containers and CI)")
	cmd.Flags().StringVar(&dir, "dir", "", "shim directory (default: ~/.ossprey/shims, or $"+shim.DirEnv+")")
	cmd.Flags().StringVar(&binary, "binary", "", "ossprey binary the shims should call (default: this one)")
	cmd.Flags().BoolVar(&printOnly, "dry-run", false, "print what would be installed and exit")

	return cmd
}

func newShimUninstallCmd() *cobra.Command {
	var (
		managers []string
		noPath   bool
		dir      string
	)

	cmd := &cobra.Command{
		Use:     "uninstall",
		Short:   "Remove the PATH shims and undo the PATH change",
		Args:    cobra.NoArgs,
		Aliases: []string{"remove"},
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := shim.Uninstall(shim.Options{Dir: dir, Managers: managers, SkipProfiles: noPath})
			if err != nil {
				return err
			}
			if len(res.Done) == 0 {
				fmt.Printf("No ossprey shims found in %s\n", res.Dir)
			} else {
				fmt.Printf("Removed %d shim(s) from %s: %s\n", len(res.Done), res.Dir, strings.Join(names(res.Done), ", "))
			}
			for _, p := range res.Profiles {
				fmt.Println("Cleaned PATH entry from " + p)
			}
			if len(res.Profiles) > 0 || res.OnPath {
				fmt.Println("\nOpen a new terminal for the change to take effect.")
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&managers, "managers", nil, "only remove these shims (PATH is left alone)")
	cmd.Flags().BoolVar(&noPath, "no-path", false, "remove the shims but leave shell profiles alone")
	cmd.Flags().StringVar(&dir, "dir", "", "shim directory (default: ~/.ossprey/shims, or $"+shim.DirEnv+")")

	return cmd
}

func newShimStatusCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show which package managers currently route through ossprey",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := shim.Load(shim.Options{Dir: dir})
			if err != nil {
				return err
			}
			printStatus(st)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "shim directory (default: ~/.ossprey/shims, or $"+shim.DirEnv+")")
	return cmd
}

func newShimDirCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dir",
		Short: "Print the shim directory (for setting PATH yourself)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := shim.Dir()
			if err != nil {
				return err
			}
			fmt.Println(d)
			return nil
		},
	}
}

func previewInstall(opts shim.Options) error {
	res, err := shim.Plan(opts)
	if err != nil {
		return err
	}
	fmt.Printf("Would write shims to %s, calling %s:\n", res.Dir, res.Binary)
	for _, m := range res.Done {
		fmt.Printf("  %-8s shadows %s\n", m.Name, orDash(m.Real))
	}
	for _, m := range res.Skipped {
		fmt.Printf("  %-8s skipped (%s)\n", m.Name, m.Note)
	}
	if !opts.SkipProfiles {
		for _, p := range res.Profiles {
			fmt.Println("Would add the PATH entry to " + p)
		}
	}
	return nil
}

func printInstallResult(res *shim.Result, noPath bool) {
	if len(res.Done) == 0 {
		fmt.Printf("No package managers to shim. Supported: %s\n", strings.Join(shim.DefaultManagers(), ", "))
		fmt.Println("Install one, or re-run with --all to shim them ahead of time.")
		return
	}

	fmt.Printf("Installed %d shim(s) in %s\n\n", len(res.Done), res.Dir)
	for _, m := range res.Done {
		fmt.Printf("  %-8s → ossprey %s → %s\n", m.Name, m.Name, orDash(m.Real))
	}
	for _, m := range res.Skipped {
		fmt.Printf("  %-8s skipped (%s)\n", m.Name, m.Note)
	}

	fmt.Println()
	switch {
	case noPath:
		fmt.Println("PATH not modified (--no-path). Put the shim directory first yourself:")
		fmt.Printf("  export PATH=\"%s:$PATH\"\n", res.Dir)
	case len(res.Profiles) > 0:
		fmt.Println("Added the shim directory to the front of your PATH in:")
		for _, p := range res.Profiles {
			fmt.Println("  " + p)
		}
		fmt.Println("\nOpen a new terminal to pick it up (or run `hash -r`; `rehash` in zsh),")
		fmt.Println("then check it worked with `ossprey shim status`.")
	case res.PathHint != "":
		fmt.Println("Could not update your PATH automatically. Run:")
		fmt.Println("  " + res.PathHint)
	case res.OnPath:
		fmt.Println("The shim directory is already on your PATH — nothing else to do.")
	default:
		fmt.Printf("Your shell profiles already put %s on PATH.\n", res.Dir)
		fmt.Println("Open a new terminal (or `hash -r`) to pick it up, then run `ossprey shim status`.")
	}

	fmt.Printf("\nBypass a single command with %s=1, or undo with `ossprey shim uninstall`.\n", shim.BypassEnv)
}

func printStatus(st *shim.Status) {
	fmt.Println("Shim directory: " + st.Dir)
	if !st.DirExists {
		fmt.Println("\nNo shims installed. Run `ossprey shim install` to intercept package installs.")
		return
	}
	if st.Binary != "" {
		state := "ok"
		if !st.BinaryOK {
			state = "MISSING — shims are passing installs through unchecked; re-run `ossprey shim install`"
		}
		fmt.Printf("Shims call:     %s (%s)\n", st.Binary, state)
	}

	yes, no, meh := marks()
	var uncovered []string
	fmt.Println()
	for _, m := range st.Managers {
		switch {
		case m.Active:
			fmt.Printf("  %s %-8s checked by ossprey, then run from %s\n", yes, m.Name, orDash(m.Real))
		case m.Shim != "" && m.Resolves == "":
			fmt.Printf("  %s %-8s shim installed, but %s isn't on your PATH\n", meh, m.Name, m.Name)
		case m.Shim != "":
			fmt.Printf("  %s %-8s shim installed but NOT active: %s runs %s\n", no, m.Name, m.Name, m.Resolves)
		case m.Resolves != "":
			uncovered = append(uncovered, m.Name)
			fmt.Printf("  %s %-8s not shimmed: %s runs %s unchecked\n", meh, m.Name, m.Name, m.Resolves)
		default:
			fmt.Printf("  %s %-8s not installed\n", meh, m.Name)
		}
	}

	if len(uncovered) > 0 && st.Installed() {
		fmt.Printf("\nInstalled but not intercepted: %s.\n", strings.Join(uncovered, ", "))
		fmt.Printf("  ossprey shim install --managers %s\n", strings.Join(uncovered, ","))
	}
	if !st.OnPath && st.Installed() {
		fmt.Printf("\n%s is not on this shell's PATH. Open a new terminal, or run:\n", st.Dir)
		fmt.Printf("  export PATH=\"%s:$PATH\"\n", st.Dir)
	}
	if st.Bypass {
		fmt.Printf("\n%s is set: every shim is passing installs through unchecked.\n", shim.BypassEnv)
	}

	var managed []string
	for _, p := range st.Profiles {
		if p.Managed {
			managed = append(managed, p.Path)
		}
	}
	if len(managed) > 0 {
		fmt.Println("\nPATH entry written in: " + strings.Join(managed, ", "))
	}
	if runtime.GOOS != "windows" && len(managed) == 0 && st.Installed() {
		fmt.Println("\nNo shell profile carries the PATH entry (installed with --no-path?).")
	}
}

func marks() (yes, no, meh string) {
	if runtime.GOOS == "windows" {
		return "[ok]", "[!!]", "[--]"
	}
	return "✓", "✗", "·"
}

func names(ms []shim.ManagerResult) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "(not found)"
	}
	return s
}
