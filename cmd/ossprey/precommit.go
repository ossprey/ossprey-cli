package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/precommit"
	"github.com/ossprey/ossprey-cli/internal/submit"
)

// defaultPrecommitCheckTimeout bounds the whole known-bad lookup. A
// pre-commit hook runs on every `git commit`, so the network budget is tight
// — but it must also cover the API's cold start. Measured in production: the
// first check after the backend Lambda goes idle takes ~6-7s end-to-end
// (first-invocation handler cost, plus a possible Auth0 token refresh
// client-side), while warm checks take 0.3-0.5s. The old 5s budget made
// every post-idle commit silently fail open, so the default is 10s: warm
// commits never feel it, cold ones get checked instead of skipped.
const defaultPrecommitCheckTimeout = 10 * time.Second

// precommitCheckTimeout returns the check budget, honoring the
// OSSPREY_PRECOMMIT_TIMEOUT env var (a Go duration string like "3s" or
// "15s"). An unset, unparseable, or non-positive value falls back to the
// default without a warning — this runs inside a git hook, and a typo'd env
// var must never make committing noisier or break it.
func precommitCheckTimeout() time.Duration {
	if v := os.Getenv("OSSPREY_PRECOMMIT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultPrecommitCheckTimeout
}

// Test seams, mirroring internal/forward's execFn/checkFn pattern.
var (
	precommitDeltaFn = precommit.StagedDelta
	precommitCheckFn = checkMalwarePurls
	// precommitLoginFn reports whether an `ossprey login` session is stored.
	// A seam so tests don't touch the real credential store.
	precommitLoginFn = func() error { _, err := auth.Load(); return err }
)

// checkMalwarePurls is the default precommitCheckFn: one client, one
// (batched) CheckMalware call under the hook's deadline. Credentials resolve
// through submit.NewClient — the exact order the scan path uses (--api-key,
// then the stored `ossprey login` session, then OSSPREY_API_KEY / API_KEY).
func checkMalwarePurls(ctx context.Context, apiURL, apiKey string, purls []string) ([]client.MalwareHit, error) {
	// The timeout wraps credential resolution too, not just the lookup:
	// submit.NewClient may refresh an expired `ossprey login` token over
	// HTTP (auth.AccessToken), and on the raw command context that refresh
	// could stall `git commit` for the HTTP client's full ~30s before
	// failing open. Everything network-shaped in this hook shares the one
	// budget.
	ctx, cancel := context.WithTimeout(ctx, precommitCheckTimeout())
	defer cancel()
	c, err := submit.NewClient(ctx, apiURL, apiKey)
	if err != nil {
		return nil, err
	}
	return c.CheckMalware(ctx, purls)
}

// hasPrecommitCredentials reports whether any credential source that
// submit.NewClient consults is available: the --api-key flag, an environment
// API key, or a stored `ossprey login` session. Used only for the fail-open
// early exit; the actual resolution happens inside submit.NewClient.
func hasPrecommitCredentials(apiKey string) bool {
	if apiKey != "" || client.APIKeyFromEnv() != "" {
		return true
	}
	return precommitLoginFn() == nil
}

// newPrecommitCmd is the command a git pre-commit hook invokes. It diffs the
// staged dependency manifests against HEAD and checks only the packages the
// commit introduces against the known-malware lookup.
//
// Exit-code semantics deliberately differ from `scan` (where errors exit 1):
// this runs on every commit, so anything that is not a confirmed malware hit
// — no API key or login session, network outage, endpoint not deployed, git
// trouble — fails
// OPEN with a one-line warning and exit 0. A scanner that can break `git
// commit` gets ripped out (same convention as the PATH shims).
func newPrecommitCmd() *cobra.Command {
	var (
		apiURL  string
		apiKey  string
		verbose bool
	)

	cmd := &cobra.Command{
		Use:   "precommit",
		Short: "Git pre-commit hook: block commits that stage known-malicious packages",
		Long: `Check the dependencies added or version-bumped by the staged changes
against Ossprey's known-malware list, and block the commit on a hit.

Intended to be run from a git pre-commit hook. Silent when the commit is
clean.

Exit codes:
  0  no known-malicious packages staged, or the check was skipped
     (no API key or login session, network/API error, not a git repo) —
     the check fails open so it can never break committing
  1  one or more staged packages are known-malicious`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runPrecommit(cmd.Context(), apiURL, apiKey, verbose, os.Stderr) {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&apiURL, "url", envOr("OSSPREY_API_URL", defaultAPIURL), "Ossprey API URL (or OSSPREY_API_URL env var)")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "Ossprey API key (or OSSPREY_API_KEY / API_KEY env var)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "report progress even when the commit is clean")

	return cmd
}

// runPrecommit does the work and reports whether the commit must be blocked.
// It never returns an error: every failure mode short of a confirmed malware
// hit fails open (warning on w, blocked=false). Default output on a clean
// commit is nothing at all — a hook that chats on every commit is noise.
func runPrecommit(ctx context.Context, apiURL, apiKey string, verbose bool, w io.Writer) (blocked bool) {
	if !hasPrecommitCredentials(apiKey) {
		fmt.Fprintln(w, "ossprey: no API key or login session (set OSSPREY_API_KEY or run `ossprey login`); skipping pre-commit malware check")
		return false
	}

	delta, err := precommitDeltaFn(ctx, ".")
	if err != nil {
		fmt.Fprintf(w, "ossprey: could not read staged changes (%v); skipping pre-commit malware check\n", err)
		return false
	}

	// Only send pinned packages. A versionless entry means the manifest
	// declares a range with no lockfile pinning it — resolving "latest" here
	// could block a commit over a version the developer will never install.
	// Commit-time false blocks are the product risk, so skip them.
	type staged struct{ pkg precommit.Package }
	byPurl := make(map[string]staged)
	var purls []string
	for _, p := range delta.Packages {
		if p.Version == "" || p.Name == "" {
			continue
		}
		// Same purl shape as ossbom.ToMiniBOM: pkg:<type>/<name>@<version>,
		// with npm scoped names (@scope/name) passed through verbatim.
		purl := "pkg:" + p.Type + "/" + p.Name + "@" + p.Version
		if _, ok := byPurl[purl]; ok {
			continue
		}
		byPurl[purl] = staged{pkg: p}
		purls = append(purls, purl)
	}
	if len(purls) == 0 {
		if verbose {
			fmt.Fprintln(w, "ossprey: no new pinned dependencies staged; nothing to check")
		}
		return false
	}

	hits, err := precommitCheckFn(ctx, apiURL, apiKey, purls)
	if err != nil {
		fmt.Fprintf(w, "ossprey: malware check unavailable (%v); allowing commit\n", err)
		return false
	}
	if len(hits) == 0 {
		if verbose {
			fmt.Fprintf(w, "ossprey: %d staged package(s) checked, none known-malicious\n", len(purls))
		}
		return false
	}

	fmt.Fprintln(w, "ossprey: commit blocked — known malicious package(s) staged:")
	for _, h := range hits {
		if s, ok := byPurl[h.Purl]; ok {
			fmt.Fprintf(w, "  %s@%s (%s, from %s): %s\n", s.pkg.Name, s.pkg.Version, s.pkg.Type, s.pkg.Path, h.Reason)
			continue
		}
		// Purl not echoed back exactly as sent — report it raw rather than
		// dropping a hit.
		name, version := splitHitPurl(h.Purl)
		fmt.Fprintf(w, "  %s@%s: %s\n", name, version, h.Reason)
	}
	fmt.Fprintln(w, "Remove the package(s) and re-stage, or bypass at your own risk with `git commit --no-verify`.")
	return true
}

// splitHitPurl extracts (name, version) from "pkg:<type>/<name>@<version>".
// npm scoped names keep their @scope prefix, so cut at the LAST '@'.
func splitHitPurl(purl string) (string, string) {
	s := strings.TrimPrefix(purl, "pkg:")
	if _, after, ok := strings.Cut(s, "/"); ok {
		s = after
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
