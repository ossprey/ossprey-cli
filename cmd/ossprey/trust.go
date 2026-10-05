package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/trust"
)

// loadTrust returns the machine's trust policy (trust.json plus the
// OSSPREY_TRUSTED_* variables). A problem with it is reported and survived:
// whatever could not be read is simply not trusted, so its packages are
// checked, and a typo in a config file must never stop an install or a scan.
func loadTrust(w io.Writer) trust.Policy {
	policy, err := trust.Load()
	if err != nil {
		fmt.Fprintf(w, "ossprey: warning: %v (entries that could not be read are ignored, so their packages are checked)\n", err)
	}
	return policy
}

func newTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage sources whose packages are not checked (private registries, npm scopes)",
		Long: `Declare the package sources that are your own, so their packages are neither
checked nor sent to Ossprey.

  --registry URL   a private registry or index, matched on its full URL prefix
                   against where your lockfiles say each package was fetched from
  --npm-scope @org an npm scope; every @org/* package is trusted by name

Trust is stored on this machine, in trust.json beside your login, and can also be
set with OSSPREY_TRUSTED_REGISTRIES / OSSPREY_TRUSTED_NPM_SCOPES. It is never read
from the repository being scanned.

Only trust a repository that holds packages you publish. One with an upstream
connection to a public registry makes every package it proxies trusted.`,
	}
	cmd.AddCommand(newTrustListCmd(), newTrustAddCmd(), newTrustRemoveCmd())
	return cmd
}

func newTrustListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show the trusted registries and npm scopes, and where each comes from",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			path, err := trust.Path()
			if err != nil {
				return err
			}
			file, fileErr := trust.LoadFile()
			env, envErr := trust.FromEnv()
			if err := errors.Join(fileErr, envErr); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "ossprey: warning: %v\n", err)
			}
			if file.Empty() && env.Empty() {
				fmt.Fprintln(out, "Nothing is trusted; every package is checked.")
				fmt.Fprintln(out, "Add a source with `ossprey trust add --registry <url>` or `--npm-scope @org`.")
				return nil
			}
			printTrust(out, "Registries", file.Registries, env.Registries, trust.RegistriesEnv)
			printTrust(out, "npm scopes", file.NpmScopes, env.NpmScopes, trust.NpmScopesEnv)
			fmt.Fprintf(out, "\nConfig file: %s\n", path)
			return nil
		},
	}
}

func printTrust(out io.Writer, heading string, fromFile, fromEnv []string, envName string) {
	if len(fromFile) == 0 && len(fromEnv) == 0 {
		return
	}
	fmt.Fprintf(out, "%s:\n", heading)
	for _, v := range fromFile {
		fmt.Fprintf(out, "  %s\n", v)
	}
	for _, v := range fromEnv {
		fmt.Fprintf(out, "  %s  (from %s)\n", v, envName)
	}
}

// trustFlags are the entries `trust add` and `trust remove` take.
type trustFlags struct {
	registries []string
	scopes     []string
}

func (f *trustFlags) register(cmd *cobra.Command, verb string) {
	cmd.Flags().StringArrayVar(&f.registries, "registry", nil, "registry URL to "+verb+" (repeatable)")
	cmd.Flags().StringArrayVar(&f.scopes, "npm-scope", nil, "npm scope to "+verb+", e.g. @my-org (repeatable)")
}

func (f *trustFlags) policy() (trust.Policy, error) {
	if len(f.registries) == 0 && len(f.scopes) == 0 {
		return trust.Policy{}, errors.New("name at least one --registry or --npm-scope")
	}
	return trust.Parse(f.registries, f.scopes)
}

func newTrustAddCmd() *cobra.Command {
	var flags trustFlags
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Trust a registry or npm scope",
		Example: `  ossprey trust add --npm-scope @my-org
  ossprey trust add --registry https://my-org-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			add, err := flags.policy()
			if err != nil {
				return err
			}
			// A file that is present but unreadable is refused rather than
			// overwritten: writing back only what parsed would delete the rest.
			current, err := trust.LoadFile()
			if err != nil {
				return fmt.Errorf("%w; fix or remove the file before changing it", err)
			}
			if err := trust.Save(current.Merge(add)); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, r := range add.Registries {
				fmt.Fprintf(out, "Trusted registry %s\n", r)
			}
			for _, s := range add.NpmScopes {
				fmt.Fprintf(out, "Trusted npm scope %s\n", s)
			}
			return nil
		},
	}
	flags.register(cmd, "trust")
	return cmd
}

func newTrustRemoveCmd() *cobra.Command {
	var flags trustFlags
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Stop trusting a registry or npm scope",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			drop, err := flags.policy()
			if err != nil {
				return err
			}
			current, err := trust.LoadFile()
			if err != nil {
				return fmt.Errorf("%w; fix or remove the file before changing it", err)
			}
			next := current.Without(drop)
			removed := len(current.Registries) + len(current.NpmScopes) - len(next.Registries) - len(next.NpmScopes)
			if removed == 0 {
				return errors.New("none of those entries is in the trust config (entries set through the environment are removed there)")
			}
			if err := trust.Save(next); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %d trusted source(s)\n", removed)
			return nil
		},
	}
	flags.register(cmd, "stop trusting")
	return cmd
}
