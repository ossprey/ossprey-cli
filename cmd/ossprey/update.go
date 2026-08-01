package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/update"
)

// newUpdateCmd implements `ossprey update`: download the latest released
// binary for this OS/arch, verify its sha256, and replace the running
// executable in place.
func newUpdateCmd() *cobra.Command {
	var (
		targetVersion string
		force         bool
		check         bool
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update ossprey to the latest release",
		Long: `Update the ossprey binary in place.

Downloads the latest release for this OS/architecture from GitHub, verifies
its sha256 checksum, and replaces the currently running executable. If the
binary lives in a root-owned directory (e.g. /usr/local/bin), re-run with
sudo.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return update.Run(cmd.Context(), update.Options{
				Current:   version,
				Target:    targetVersion,
				Force:     force,
				CheckOnly: check,
				Out:       os.Stdout,
			})
		},
	}

	cmd.Flags().StringVar(&targetVersion, "version", "", "install a specific release tag (e.g. v0.2.0) instead of the latest")
	cmd.Flags().BoolVar(&force, "force", false, "reinstall even if already on the target version")
	cmd.Flags().BoolVar(&check, "check", false, "only report whether an update is available; don't install")

	return cmd
}
