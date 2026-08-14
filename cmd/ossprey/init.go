package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/setup"
	"github.com/ossprey/ossprey-cli/internal/submit"
)

// keyNameAttempts caps how many fresh random key names init tries when the
// generated name collides with an existing key (409).
const keyNameAttempts = 3

// defaultKeyExpiry is how long the CI API key lives. The API caps expiry at
// two years; one year balances "CI doesn't break next sprint" against not
// minting eternal credentials.
const defaultKeyExpiry = 365 * 24 * time.Hour

// newInitCmd implements `ossprey init`: one command that logs in, mints a CI
// API key, drops a GitHub Actions workflow, and runs the first scan.
func newInitCmd() *cobra.Command {
	defaults := auth.ConfigFromEnv()
	var (
		cfg        auth.Config
		apiURL     string
		keyName    string
		keyExpiry  time.Duration
		noWorkflow bool
		noScan     bool
	)

	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Set up Ossprey for a project: log in, create a CI API key, add a CI workflow, run the first scan",
		Long: `Set up Ossprey for a project in one command.

Runs four steps against the project directory (default "."):

  1. Log in via your browser (skipped if already logged in)
  2. Create an API key for CI and print it once
  3. Write a GitHub Actions workflow (.github/workflows/ossprey.yml)
     that scans every push and pull request
  4. Run the first scan right away

Each step is safe to re-run: an existing login and workflow file are left
untouched, and a fresh key name is generated per run.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("project path: %w", err)
			}

			// Step 1: authenticate — reuse a stored login, else device flow.
			fmt.Println("[1/4] Checking login...")
			token, err := ensureLogin(ctx, cfg)
			if err != nil {
				return err
			}

			// Step 2: mint a CI API key. Failure warns rather than aborts:
			// the user may already have a key, and the remaining steps
			// (workflow file, first scan) still deliver value.
			fmt.Println("[2/4] Creating an API key for CI...")
			key := createCIKey(ctx, apiURL, token, keyName, keyExpiry)
			if key != nil {
				fmt.Printf("Created API key %q (expires %s).\n", key.Name, key.Expiry)
				fmt.Println("This is the only time it is shown — add it to your repository now:")
				fmt.Printf("\n    %s\n\n", key.Key)
				fmt.Println("    gh secret set OSSPREY_API_KEY   # paste the key when prompted")
				fmt.Println("    (or GitHub -> Settings -> Secrets and variables -> Actions -> New repository secret)")
				fmt.Println()
			}

			// Step 3: drop the CI workflow.
			if noWorkflow {
				fmt.Println("[3/4] Skipping CI workflow (--no-workflow)")
			} else {
				fmt.Println("[3/4] Adding GitHub Actions workflow...")
				wfPath, created, err := setup.WriteWorkflow(path, setup.DefaultBranch(path))
				switch {
				case err != nil:
					return err
				case created:
					fmt.Printf("Wrote %s — commit it to enable scans in CI.\n", wfPath)
				default:
					fmt.Printf("%s already exists; left untouched.\n", wfPath)
				}
			}

			// Step 4: first scan, authenticated by the login from step 1.
			if noScan {
				fmt.Println("[4/4] Skipping first scan (--no-scan)")
				return nil
			}
			fmt.Println("[4/4] Running your first scan...")
			return runFirstScan(ctx, path, apiURL)
		},
	}

	cmd.Flags().StringVar(&apiURL, "url", defaultAPIURL, "Ossprey API URL")
	cmd.Flags().StringVar(&keyName, "key-name", "", "name for the created API key (default: generated, e.g. ci-a1b2c3d4)")
	cmd.Flags().DurationVar(&keyExpiry, "key-expiry", defaultKeyExpiry, "lifetime of the created API key (max 2 years)")
	cmd.Flags().BoolVar(&noWorkflow, "no-workflow", false, "don't write the GitHub Actions workflow file")
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "don't run the first scan")
	cmd.Flags().StringVar(&cfg.Domain, "auth0-domain", defaults.Domain, "Auth0 domain (or OSSPREY_AUTH0_DOMAIN env var)")
	cmd.Flags().StringVar(&cfg.ClientID, "client-id", defaults.ClientID, "Auth0 client ID (or OSSPREY_AUTH0_CLIENT_ID env var)")
	cmd.Flags().StringVar(&cfg.Audience, "audience", defaults.Audience, "Auth0 API audience (or OSSPREY_AUTH0_AUDIENCE env var)")

	return cmd
}

// ensureLogin returns a valid access token, reusing (and silently refreshing)
// a stored login or walking the user through the device flow when there is
// none.
func ensureLogin(ctx context.Context, cfg auth.Config) (string, error) {
	token, err := auth.AccessToken(ctx, nil)
	if err == nil {
		if creds, loadErr := auth.Load(); loadErr == nil {
			if id := creds.Identity(); id != "" {
				fmt.Printf("Already logged in as %s.\n", id)
			} else {
				fmt.Println("Already logged in.")
			}
		}
		return token, nil
	}
	if !errors.Is(err, auth.ErrNotLoggedIn) {
		// A stored login that failed to refresh: fall through to a fresh
		// device flow rather than telling the user to run another command.
		fmt.Printf("Stored login could not be refreshed (%v); starting a fresh login.\n", err)
	}
	creds, err := runDeviceLogin(ctx, cfg)
	if err != nil {
		return "", err
	}
	if id := creds.Identity(); id != "" {
		fmt.Printf("Logged in as %s.\n", id)
	}
	return creds.AccessToken, nil
}

// createCIKey creates an API key for CI use, retrying with fresh generated
// names on a 409 name collision. Returns nil (after printing a warning) when
// the key cannot be created — init continues without it.
func createCIKey(ctx context.Context, apiURL, token, name string, expiry time.Duration) *client.APIKey {
	c, err := client.NewBearer(apiURL, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create an API key: %v\n", err)
		return nil
	}

	fixedName := name != ""
	for attempt := 0; attempt < keyNameAttempts; attempt++ {
		if !fixedName {
			name = setup.GenerateKeyName()
		}
		key, err := c.CreateAPIKey(ctx, name, time.Now().Add(expiry))
		if err == nil {
			return key
		}
		var apiErr *client.APIError
		if !fixedName && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
			continue // name collision: try a fresh random name
		}
		fmt.Fprintf(os.Stderr, "warning: could not create an API key: %v\n", err)
		fmt.Fprintln(os.Stderr, "You can create one at https://dashboard.ossprey.com and store it as the OSSPREY_API_KEY repository secret.")
		return nil
	}
	fmt.Fprintf(os.Stderr, "warning: could not create an API key: %d generated names collided\n", keyNameAttempts)
	return nil
}

// runFirstScan catalogs the project, submits it with the stored login, and
// reports the verdict exactly like `ossprey scan`.
func runFirstScan(ctx context.Context, path, apiURL string) error {
	sbom, err := scan.Run(ctx, scan.Options{Path: path})
	if err != nil {
		return err
	}
	if err := submit.Validate(ctx, sbom, apiURL, ""); err != nil {
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
	fmt.Println("No malware found. See your scans at https://dashboard.ossprey.com")
	return nil
}
