package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/auth"
)

// newLoginCmd implements `ossprey login`: an Auth0 device-authorization flow.
// The user confirms a short code in their browser; the CLI stores the
// resulting tokens and scans authenticate with them automatically.
func newLoginCmd() *cobra.Command {
	defaults := auth.ConfigFromEnv()
	var cfg auth.Config

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to Ossprey via your browser (Auth0)",
		Long: `Log in to Ossprey using the Auth0 device flow.

Opens (or prints) a browser URL where you confirm a one-time code. The CLI
stores the resulting tokens locally and uses them to authenticate scans, so
no API key is needed. Tokens refresh automatically; run "ossprey logout" to
remove them.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			creds, err := runDeviceLogin(cmd.Context(), cmd.OutOrStdout(), cfg)
			if err != nil {
				return err
			}

			if id := creds.Identity(); id != "" {
				fmt.Printf("Logged in as %s\n", id)
			} else {
				fmt.Println("Logged in")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&cfg.Domain, "auth0-domain", defaults.Domain, "Auth0 domain (or OSSPREY_AUTH0_DOMAIN env var)")
	cmd.Flags().StringVar(&cfg.ClientID, "client-id", defaults.ClientID, "Auth0 client ID (or OSSPREY_AUTH0_CLIENT_ID env var)")
	cmd.Flags().StringVar(&cfg.Audience, "audience", defaults.Audience, "Auth0 API audience (or OSSPREY_AUTH0_AUDIENCE env var)")

	return cmd
}

// newLogoutCmd removes the stored login.
func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored Ossprey login",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := auth.Remove(); err != nil {
				return err
			}
			fmt.Println("Logged out")
			return nil
		},
	}
}

// newWhoamiCmd reports the stored login's identity and expiry.
func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the identity of the stored Ossprey login",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			creds, err := auth.Load()
			if errors.Is(err, auth.ErrNotLoggedIn) {
				return errors.New("not logged in: run `ossprey login`")
			}
			if err != nil {
				return err
			}
			id := creds.Identity()
			if id == "" {
				id = "(unknown identity)"
			}
			fmt.Printf("Logged in as %s (%s)\n", id, creds.Domain)
			switch {
			case creds.Valid():
				fmt.Printf("Access token expires at %s\n", creds.ExpiresAt.Format(time.RFC3339))
			case creds.RefreshToken != "":
				fmt.Println("Access token expired; it will refresh automatically on the next scan")
			default:
				fmt.Println("Access token expired; run `ossprey login` again")
			}
			return nil
		},
	}
}

// runDeviceLogin walks the user through the Auth0 device-authorization flow
// (print code, open browser, poll for approval) and stores the resulting
// credentials. Shared by `ossprey login` and `ossprey init`. Prompts go to out
// so callers keeping stdout machine-readable can route them to stderr.
func runDeviceLogin(ctx context.Context, out io.Writer, cfg auth.Config) (*auth.Credentials, error) {
	dc, err := cfg.RequestDeviceCode(ctx, nil)
	if err != nil {
		return nil, err
	}

	verifyURL := dc.VerificationURIComplete
	if verifyURL == "" {
		verifyURL = dc.VerificationURI
	}
	fmt.Fprintf(out, "First, confirm this code matches your browser: %s\n", dc.UserCode)
	if openBrowser(verifyURL) {
		fmt.Fprintf(out, "Your browser has been opened to complete the login:\n\n    %s\n\n", verifyURL)
	} else {
		fmt.Fprintf(out, "Open this URL in a browser to complete the login:\n\n    %s\n\n", verifyURL)
	}
	fmt.Fprintln(out, "Waiting for the login to be approved...")

	creds, err := cfg.PollToken(ctx, nil, dc)
	if err != nil {
		return nil, err
	}
	if err := auth.Save(creds); err != nil {
		return nil, err
	}
	return creds, nil
}

// openBrowser makes a best-effort attempt to open url in the default browser,
// reporting whether the launch succeeded.
func openBrowser(url string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start() == nil
}
