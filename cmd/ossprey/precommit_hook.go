package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/hook"
)

// newPrecommitCmdWithHooks wires the hook-management subcommands onto the
// `precommit` command. Bare `ossprey precommit` still runs the check itself
// (that is what the installed git hook invokes); install/uninstall/status
// manage the plain git hook for the current repository, mirroring
// `ossprey shim install|uninstall|status`.
func newPrecommitCmdWithHooks() *cobra.Command {
	cmd := newPrecommitCmd()
	cmd.AddCommand(newPrecommitInstallCmd(), newPrecommitUninstallCmd(), newPrecommitStatusCmd())
	return cmd
}

func newPrecommitInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install the pre-commit hook into the current git repository",
		Args:  cobra.NoArgs,
		Long: `Write a pre-commit hook that runs ` + "`ossprey precommit`" + ` on every commit
in this repository. Respects core.hooksPath. Safe to re-run: an existing
ossprey hook is refreshed in place.

A pre-commit hook that ossprey did not write is never overwritten — chain it
yourself, or manage both hooks with the pre-commit framework
(https://pre-commit.com) via this repo's published hook id ` + "`ossprey`" + `.

The hook fails open: if the ossprey binary is missing from PATH it warns and
lets the commit through, and any single commit can bypass it with
` + "`git commit --no-verify`" + `.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := hook.Install(".")
			if err != nil {
				return err
			}
			fmt.Println("Installed pre-commit hook: " + st.Path)
			fmt.Println("Staged dependency changes are now checked against Ossprey's known-malware list on every commit.")
			fmt.Println("Bypass a single commit with `git commit --no-verify`; remove with `ossprey precommit uninstall`.")
			return nil
		},
	}
}

func newPrecommitUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "uninstall",
		Short:   "Remove the ossprey pre-commit hook from the current git repository",
		Args:    cobra.NoArgs,
		Aliases: []string{"remove"},
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := hook.Load(".")
			if err != nil {
				return err
			}
			if st.State == hook.NotInstalled {
				fmt.Println("No ossprey pre-commit hook installed in this repository.")
				return nil
			}
			if _, err := hook.Uninstall("."); err != nil {
				return err
			}
			fmt.Println("Removed pre-commit hook: " + st.Path)
			return nil
		},
	}
}

func newPrecommitStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the ossprey pre-commit hook is installed in this repository",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := hook.Load(".")
			if err != nil {
				return err
			}
			switch st.State {
			case hook.Installed:
				fmt.Println("Installed: " + st.Path)
				fmt.Println("Staged dependency changes are checked against Ossprey's known-malware list on every commit.")
			case hook.Foreign:
				fmt.Println("Not installed. A pre-commit hook ossprey did not write exists at " + st.Path + ".")
				fmt.Println("Chain `ossprey precommit` into it yourself, or use the pre-commit framework (https://pre-commit.com).")
			default:
				fmt.Println("Not installed. Run `ossprey precommit install` in this repository to enable it.")
			}
			return nil
		},
	}
}
