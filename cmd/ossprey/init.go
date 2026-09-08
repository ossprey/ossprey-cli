package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/submit"
)

// keyNameAttempts caps how many fresh random key names init tries when the
// generated name collides with an existing key (409).
const keyNameAttempts = 3

// defaultKeyExpiry is how long the CI API key lives. The API caps expiry at
// two years; one year balances "CI doesn't break next sprint" against not
// minting eternal credentials.
const defaultKeyExpiry = 365 * 24 * time.Hour

// maxKeyExpiry mirrors the API's two-year ceiling. Checked locally so an
// over-limit --key-expiry says so plainly, instead of surfacing as the generic
// "could not create an API key" warning after a round trip.
const maxKeyExpiry = 2 * 365 * 24 * time.Hour

// newInitCmd implements `ossprey init`: one command that logs in, mints an API
// key, and scans the project with that key.
func newInitCmd() *cobra.Command {
	defaults := auth.ConfigFromEnv()
	var (
		cfg       auth.Config
		apiURL    string
		keyName   string
		keyExpiry time.Duration
		noKey     bool
		doScan    bool
		noScan    bool
		keyStdout bool
	)

	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Set up Ossprey for a project: log in, create an API key, optionally scan",
		Long: `Set up Ossprey for a project in one command.

Runs three steps against the project directory (default "."):

  1. Log in via your browser (skipped if already logged in)
  2. Create an API key and print it once
  3. Optionally scan the project using that key

Step 3 asks before it runs. Pass --scan or --no-scan to answer up front; when
the terminal isn't interactive (CI, or output piped somewhere) it is skipped
unless you pass --scan.

The scan deliberately authenticates with the key just created rather than with
your login, so a successful scan is proof the key works before you paste it
into CI.

The key is shown once and cannot be retrieved later — the API stores only a
hash of it. Use --key-stdout to pipe it somewhere instead, e.g.

    ossprey init --no-scan --key-stdout | gh secret set OSSPREY_API_KEY

Re-running is safe: an existing login is reused, and each run generates a fresh
key name.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// With --key-stdout, stdout carries the bare key and nothing else so
			// it can be piped into a secret store; every human-facing line goes
			// to stderr instead.
			logOut := cmd.OutOrStdout()
			if keyStdout {
				logOut = cmd.ErrOrStderr()
			}

			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("project path: %w", err)
			}
			if !noKey {
				if keyExpiry <= 0 {
					return fmt.Errorf("--key-expiry must be positive, got %s", keyExpiry)
				}
				if keyExpiry > maxKeyExpiry {
					return fmt.Errorf("--key-expiry cannot exceed 2 years (got %s)", keyExpiry)
				}
			}

			// Step 1: authenticate — reuse a stored login, else device flow.
			// Both remaining steps need credentials, so there is no offline
			// path here: creating a key needs the login, and the scan needs
			// either the key or the login.
			fmt.Fprintln(logOut, "[1/3] Checking login...")
			token, err := ensureLogin(ctx, logOut, cfg)
			if err != nil {
				return err
			}

			// Step 2: mint an API key. Failure warns rather than aborts, so a
			// key limit or a registry hiccup can't cost the user their scan.
			var key *client.APIKey
			if noKey {
				fmt.Fprintln(logOut, "[2/3] Skipping API key creation (--no-key)")
			} else {
				fmt.Fprintln(logOut, "[2/3] Creating an API key...")
				key = createCIKey(ctx, apiURL, token, keyName, keyExpiry)
			}
			if key != nil {
				if keyStdout {
					fmt.Fprintln(cmd.OutOrStdout(), key.Key)
					fmt.Fprintf(logOut, "Created API key %q (expires %s); written to stdout.\n",
						key.Name, key.Expiry)
					fmt.Fprintln(logOut, "It cannot be retrieved later — the API stores only a hash.")
				} else {
					printKeyTo(logOut, key)
				}
			}

			// Step 3: scan, authenticated by the key from step 2 where we have
			// one. Using the key rather than the login makes a clean scan proof
			// that the credential the user is about to paste into CI works.
			run, reason := wantScan(doScan, noScan, keyStdout)
			if !run {
				fmt.Fprintf(logOut, "[3/3] Skipping scan (%s)\n", reason)
				printNextStepsTo(logOut, key != nil)
				return nil
			}
			if key != nil {
				fmt.Fprintln(logOut, "[3/3] Scanning with your new API key...")
			} else {
				fmt.Fprintln(logOut, "[3/3] Scanning with your login (no API key to test)...")
			}
			if err := runFirstScan(ctx, path, apiURL, keyValue(key)); err != nil {
				return err
			}
			printNextStepsTo(logOut, key != nil)
			return nil
		},
	}

	cmd.Flags().StringVar(&apiURL, "url", defaultAPIURL, "Ossprey API URL")
	cmd.Flags().StringVar(&keyName, "key-name", "", "name for the created API key (default: generated, e.g. ci-a1b2c3d4)")
	cmd.Flags().DurationVar(&keyExpiry, "key-expiry", defaultKeyExpiry, "lifetime of the created API key (max 2 years)")
	cmd.Flags().BoolVar(&noKey, "no-key", false, "don't create an API key (use when CI already has one)")
	cmd.Flags().BoolVar(&doScan, "scan", false, "run the example scan without asking")
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "skip the example scan without asking")
	cmd.Flags().BoolVar(&keyStdout, "key-stdout", false, "print only the key to stdout (for piping); implies no scan")
	cmd.MarkFlagsMutuallyExclusive("scan", "no-scan")
	// --key-stdout keeps stdout clean for a pipe; a scan would write its verdict
	// there too, so the two cannot be combined.
	cmd.MarkFlagsMutuallyExclusive("scan", "key-stdout")
	cmd.MarkFlagsMutuallyExclusive("no-key", "key-stdout")
	cmd.Flags().StringVar(&cfg.Domain, "auth0-domain", defaults.Domain, "Auth0 domain (or OSSPREY_AUTH0_DOMAIN env var)")
	cmd.Flags().StringVar(&cfg.ClientID, "client-id", defaults.ClientID, "Auth0 client ID (or OSSPREY_AUTH0_CLIENT_ID env var)")
	cmd.Flags().StringVar(&cfg.Audience, "audience", defaults.Audience, "Auth0 API audience (or OSSPREY_AUTH0_AUDIENCE env var)")

	return cmd
}

// ensureLogin returns a valid access token, reusing (and silently refreshing)
// a stored login or walking the user through the device flow when there is
// none.
//
// A stored login is only reused when it belongs to the tenant cfg asks for.
// Otherwise `ossprey init --auth0-domain <qa> --audience <qa>` from a machine
// already logged into production would silently reuse the production token and
// then fail confusingly against the QA API, with the flags looking honoured.
func ensureLogin(ctx context.Context, out io.Writer, cfg auth.Config) (string, error) {
	stored, loadErr := auth.Load()
	if loadErr == nil && !matchesTenant(stored, cfg) {
		fmt.Fprintf(out, "Stored login is for a different Ossprey tenant (%s), but this run targets %s; logging in again.\n",
			describeTenant(stored.Domain, stored.ClientID, stored.Audience),
			describeTenant(cfg.Domain, cfg.ClientID, cfg.Audience))
		return freshLogin(ctx, out, cfg)
	}

	token, err := auth.AccessToken(ctx, nil)
	if err == nil {
		if loadErr == nil {
			if id := stored.Identity(); id != "" {
				fmt.Fprintf(out, "Already logged in as %s.\n", id)
			} else {
				fmt.Fprintln(out, "Already logged in.")
			}
		}
		return token, nil
	}
	if !errors.Is(err, auth.ErrNotLoggedIn) {
		// A stored login that failed to refresh: fall through to a fresh
		// device flow rather than telling the user to run another command.
		fmt.Fprintf(out, "Stored login could not be refreshed (%v); starting a fresh login.\n", err)
	}
	return freshLogin(ctx, out, cfg)
}

// matchesTenant reports whether stored credentials were issued by the tenant,
// application and audience cfg names. All three identify the token's origin, and
// all three are settable via flags, so all three must agree — comparing only
// domain and audience would let `--client-id <other-app>` silently reuse a token
// minted for a different Auth0 application. An empty field on either side is
// treated as "unknown, don't force a re-login" so credentials written by older
// CLI versions keep working.
func matchesTenant(stored *auth.Credentials, cfg auth.Config) bool {
	for _, f := range []struct{ got, want string }{
		{stored.Domain, cfg.Domain},
		{stored.ClientID, cfg.ClientID},
		{stored.Audience, cfg.Audience},
	} {
		if f.got != "" && f.want != "" && f.got != f.want {
			return false
		}
	}
	return true
}

// describeTenant renders the tenant triple for the mismatch message, omitting
// the parts that are empty (older stored credentials) rather than printing
// stray empty parentheses.
func describeTenant(domain, clientID, audience string) string {
	parts := make([]string, 0, 3)
	if domain != "" {
		parts = append(parts, domain)
	}
	if audience != "" {
		parts = append(parts, "audience "+audience)
	}
	if clientID != "" {
		parts = append(parts, "client "+clientID)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, ", ")
}

func freshLogin(ctx context.Context, out io.Writer, cfg auth.Config) (string, error) {
	creds, err := runDeviceLogin(ctx, out, cfg)
	if err != nil {
		return "", err
	}
	if id := creds.Identity(); id != "" {
		fmt.Fprintf(out, "Logged in as %s.\n", id)
	}
	return creds.AccessToken, nil
}

// wantScan decides whether to run the example scan, returning the reason when
// it declines so the user can see why. The flags win; otherwise an interactive
// terminal is asked. A non-interactive run defaults to *not* scanning: nobody is
// there to answer, and silently doing extra work in a script is worse than
// telling the caller how to opt in.
func wantScan(doScan, noScan, keyStdout bool) (run bool, reason string) {
	switch {
	case doScan:
		return true, ""
	case noScan:
		return false, "--no-scan"
	case keyStdout:
		return false, "--key-stdout keeps stdout clean; pass --scan separately to scan"
	}
	if !stdinIsTerminal() {
		return false, "not an interactive terminal; pass --scan to scan anyway"
	}
	return promptYesNo(os.Stdin, os.Stdout,
		"Run an example scan of this project now to check the key works?", true), "you declined"
}

// stdinIsTerminal reports whether stdin is a real terminal, so init only prompts
// when someone is there to answer.
//
// This uses a terminal ioctl rather than the tempting os.Stat + ModeCharDevice
// check, which is wrong: /dev/null is itself a character device, so
// `ossprey init < /dev/null` in a script would be treated as interactive and
// silently take the prompt's default.
func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// promptYesNo asks a yes/no question, returning def on an empty answer or EOF.
func promptYesNo(in io.Reader, out io.Writer, question string, def bool) bool {
	hint := "[y/N]"
	if def {
		hint = "[Y/n]"
	}
	fmt.Fprintf(out, "\n%s %s ", question, hint)

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(out)
		return def
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def
	case "y", "yes":
		return true
	default:
		return false
	}
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
			name = generateKeyName()
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
		fmt.Fprintln(os.Stderr, "You can create one at https://dashboard.ossprey.com.")
		return nil
	}
	fmt.Fprintf(os.Stderr, "warning: could not create an API key: %d generated names collided\n", keyNameAttempts)
	return nil
}

// generateKeyName returns a fresh key name like "ci-a1b2c3d4". It stays within
// the API's constraints (max 20 chars, no whitespace) and the random suffix keeps
// re-runs of init from colliding with earlier keys.
func generateKeyName() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is effectively fatal elsewhere; a fixed name
		// still works (the API rejects duplicates and init retries).
		return "ci-ossprey-init"
	}
	return "ci-" + hex.EncodeToString(b)
}

// keyValue returns the key's secret, or "" when no key was created — which is
// exactly what submit.Validate treats as "fall back to the stored login".
func keyValue(key *client.APIKey) string {
	if key == nil {
		return ""
	}
	return key.Key
}

// printKeyTo shows the created key once, with the handling advice it warrants.
// The guidance stays CI-agnostic: init doesn't know or care whether the key is
// destined for GitHub Actions, GitLab, Jenkins or a shell profile.
func printKeyTo(out io.Writer, key *client.APIKey) {
	fmt.Fprintf(out, "Created API key %q (expires %s).\n", key.Name, key.Expiry)
	// Not a stylistic warning: the API stores only an HMAC of the key, so this
	// really is the only time the plaintext exists anywhere.
	fmt.Fprintln(out, "This is the only time it is shown — it cannot be retrieved later:")
	fmt.Fprintf(out, "\n    %s\n\n", key.Key)
	fmt.Fprintln(out, "Set it as OSSPREY_API_KEY wherever your scans run. For GitHub Actions:")
	fmt.Fprintln(out, "    gh secret set OSSPREY_API_KEY   # paste the key when prompted")
	// The key is a long-lived credential sitting in the terminal: say so,
	// because scrollback and piped logs outlive the session.
	fmt.Fprintln(out, "\nTreat it like a password. It stays in your terminal scrollback, so clear it")
	fmt.Fprintln(out, "when you're done, and don't pipe this command's output to a file or CI log.")
	fmt.Fprintln(out, "Lost it? Create another with `ossprey init`, and delete the unused one at")
	fmt.Fprintln(out, "https://dashboard.ossprey.com — where you can also revoke this one.")
	fmt.Fprintln(out)
}

// printNextStepsTo points at what init deliberately does not do for the user:
// wiring CI (it can't know which CI) and installing the machine-wide
// protections, which change behaviour outside this project.
func printNextStepsTo(out io.Writer, haveKey bool) {
	fmt.Fprintln(out, "\nNext steps:")
	if haveKey {
		fmt.Fprintln(out, "    Add `ossprey scan .` to your CI, with OSSPREY_API_KEY set to this key.")
	}
	fmt.Fprintln(out, "    ossprey shim install         # check every npm/pip install on this machine")
	fmt.Fprintln(out, "    ossprey precommit install    # block commits that add known-malicious packages")
}

// runFirstScan catalogs the project and reports the verdict exactly like
// `ossprey scan`. apiKey is the key just minted: passing it makes a clean scan
// proof the credential works. Empty falls back to the stored login.
func runFirstScan(ctx context.Context, path, apiURL, apiKey string) error {
	sbom, err := scan.Run(ctx, scan.Options{Path: path})
	if err != nil {
		return err
	}
	if err := submit.Validate(ctx, sbom, apiURL, apiKey); err != nil {
		if reportSkipped(err) {
			return nil
		}
		return err
	}

	if reportMalware(sbom, severity.FailingFloor) {
		os.Exit(1)
	}
	fmt.Println("No malware found. See your scans at https://dashboard.ossprey.com")
	return nil
}
