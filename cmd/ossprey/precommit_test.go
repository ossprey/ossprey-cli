package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/precommit"
)

// stubPrecommitLogin pins the stored-login seam and clears the API-key env
// vars so credential tests never depend on the developer's real environment.
func stubPrecommitLogin(t *testing.T, loginErr error) {
	t.Helper()
	t.Setenv("OSSPREY_API_KEY", "")
	t.Setenv("API_KEY", "")
	orig := precommitLoginFn
	t.Cleanup(func() { precommitLoginFn = orig })
	precommitLoginFn = func() error { return loginErr }
}

// stubPrecommit swaps the delta and check seams for the test's duration.
func stubPrecommit(t *testing.T,
	delta func(context.Context, string) (precommit.Delta, error),
	check func(context.Context, string, string, []string) ([]client.MalwareHit, error),
) {
	t.Helper()
	origDelta, origCheck := precommitDeltaFn, precommitCheckFn
	t.Cleanup(func() { precommitDeltaFn, precommitCheckFn = origDelta, origCheck })
	if delta != nil {
		precommitDeltaFn = delta
	}
	if check != nil {
		precommitCheckFn = check
	}
}

func oneStagedPackage() func(context.Context, string) (precommit.Delta, error) {
	return func(context.Context, string) (precommit.Delta, error) {
		return precommit.Delta{Packages: []precommit.Package{
			{Type: "npm", Name: "evil-pkg", Version: "1.2.3", Path: "package-lock.json"},
		}}, nil
	}
}

func TestPrecommitCleanIsSilent(t *testing.T) {
	var checkedPurls []string
	stubPrecommit(t, oneStagedPackage(),
		func(_ context.Context, _, _ string, purls []string) ([]client.MalwareHit, error) {
			checkedPurls = purls
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); blocked {
		t.Fatal("clean commit must not be blocked")
	}
	if out.Len() != 0 {
		t.Errorf("clean commit must be silent, got: %q", out.String())
	}
	if len(checkedPurls) != 1 || checkedPurls[0] != "pkg:npm/evil-pkg@1.2.3" {
		t.Errorf("purls sent: got %v", checkedPurls)
	}
}

func TestPrecommitHitBlocks(t *testing.T) {
	stubPrecommit(t, oneStagedPackage(),
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			return []client.MalwareHit{{Purl: "pkg:npm/evil-pkg@1.2.3", Reason: "exfiltrates env vars"}}, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); !blocked {
		t.Fatal("malware hit must block the commit")
	}
	got := out.String()
	for _, want := range []string{
		"commit blocked",
		"evil-pkg@1.2.3 (npm, from package-lock.json): exfiltrates env vars",
		"--no-verify",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestPrecommitScopedHitWithoutDeltaMatch(t *testing.T) {
	// Purl echoed back but not present in byPurl (defensive path): the raw
	// purl split must keep npm scope prefixes intact.
	stubPrecommit(t, oneStagedPackage(),
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			return []client.MalwareHit{{Purl: "pkg:npm/@scope/bad@2.0.0", Reason: "typosquat"}}, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); !blocked {
		t.Fatal("hit must block")
	}
	if !strings.Contains(out.String(), "@scope/bad@2.0.0: typosquat") {
		t.Errorf("output: %q", out.String())
	}
}

func TestPrecommitNoCredentialsFailsOpen(t *testing.T) {
	stubPrecommitLogin(t, auth.ErrNotLoggedIn)
	stubPrecommit(t,
		func(context.Context, string) (precommit.Delta, error) {
			t.Error("delta must not be computed without credentials")
			return precommit.Delta{}, nil
		},
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			t.Error("check must not run without credentials")
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "", false, &out); blocked {
		t.Fatal("missing credentials must fail open")
	}
	if !strings.Contains(out.String(), "no API key or login session") {
		t.Errorf("want single-line warning about both credential sources, got: %q", out.String())
	}
}

func TestPrecommitLoginSessionOnlyRunsCheck(t *testing.T) {
	// No --api-key, no env key, but a stored `ossprey login` session: the
	// check must run (submit.NewClient resolves the session to a bearer
	// client) rather than fail open.
	stubPrecommitLogin(t, nil)
	var gotAPIKey string
	checked := false
	stubPrecommit(t, oneStagedPackage(),
		func(_ context.Context, _, apiKey string, purls []string) ([]client.MalwareHit, error) {
			checked = true
			gotAPIKey = apiKey
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "", false, &out); blocked {
		t.Fatal("clean commit must not be blocked")
	}
	if !checked {
		t.Fatal("check must run when a login session exists")
	}
	if gotAPIKey != "" {
		t.Errorf("api key passed through must stay empty so the session wins, got %q", gotAPIKey)
	}
	if out.Len() != 0 {
		t.Errorf("clean commit must be silent, got: %q", out.String())
	}
}

func TestPrecommitEnvKeyOnlyRunsCheck(t *testing.T) {
	stubPrecommitLogin(t, auth.ErrNotLoggedIn)
	t.Setenv("OSSPREY_API_KEY", "env-key")
	checked := false
	stubPrecommit(t, oneStagedPackage(),
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			checked = true
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "", false, &out); blocked {
		t.Fatal("clean commit must not be blocked")
	}
	if !checked {
		t.Fatal("check must run when an env API key exists")
	}
}

func TestPrecommitGitErrorFailsOpen(t *testing.T) {
	stubPrecommit(t,
		func(context.Context, string) (precommit.Delta, error) {
			return precommit.Delta{}, errors.New("not a git repository")
		},
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			t.Error("check must not run when the delta failed")
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); blocked {
		t.Fatal("git error must fail open")
	}
	if !strings.Contains(out.String(), "skipping pre-commit malware check") {
		t.Errorf("want fail-open warning, got: %q", out.String())
	}
}

func TestPrecommitCheckErrorFailsOpen(t *testing.T) {
	stubPrecommit(t, oneStagedPackage(),
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			return nil, errors.New("malware check failed (status 404)")
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); blocked {
		t.Fatal("API error must fail open")
	}
	if !strings.Contains(out.String(), "allowing commit") {
		t.Errorf("want fail-open warning, got: %q", out.String())
	}
}

func TestPrecommitEmptyDeltaIsSilent(t *testing.T) {
	stubPrecommit(t,
		func(context.Context, string) (precommit.Delta, error) { return precommit.Delta{}, nil },
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			t.Error("check must not run for an empty delta")
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); blocked {
		t.Fatal("empty delta must not block")
	}
	if out.Len() != 0 {
		t.Errorf("empty delta must be silent, got: %q", out.String())
	}
}

func TestPrecommitVersionlessPackagesAreSkipped(t *testing.T) {
	stubPrecommit(t,
		func(context.Context, string) (precommit.Delta, error) {
			return precommit.Delta{Packages: []precommit.Package{
				{Type: "npm", Name: "lodash", Version: "", Path: "package.json"},
			}}, nil
		},
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			t.Error("versionless-only delta must not reach the API")
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); blocked {
		t.Fatal("versionless packages must not block")
	}
	if out.Len() != 0 {
		t.Errorf("must be silent, got: %q", out.String())
	}
}

func TestPrecommitTimeoutDefault(t *testing.T) {
	t.Setenv("OSSPREY_PRECOMMIT_TIMEOUT", "")
	if got := precommitCheckTimeout(); got != defaultPrecommitCheckTimeout {
		t.Errorf("unset env: got %v, want %v", got, defaultPrecommitCheckTimeout)
	}
}

func TestPrecommitTimeoutEnvOverride(t *testing.T) {
	t.Setenv("OSSPREY_PRECOMMIT_TIMEOUT", "3s")
	if got := precommitCheckTimeout(); got != 3*time.Second {
		t.Errorf("got %v, want 3s", got)
	}
}

func TestPrecommitTimeoutInvalidFallsBackToDefault(t *testing.T) {
	// Invalid or non-positive values must silently fall back — this runs in
	// a git hook, so a typo'd env var can never be an error.
	for _, v := range []string{"bananas", "10", "-2s", "0s", "0"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("OSSPREY_PRECOMMIT_TIMEOUT", v)
			if got := precommitCheckTimeout(); got != defaultPrecommitCheckTimeout {
				t.Errorf("env %q: got %v, want default %v", v, got, defaultPrecommitCheckTimeout)
			}
		})
	}
}

func TestPrecommitCheckHonorsEnvTimeout(t *testing.T) {
	// The real precommitCheckFn (checkMalwarePurls) against a server that
	// never answers: with a tiny env timeout it must give up quickly rather
	// than hang `git commit`. This exercises the full wrap — credential
	// resolution and the HTTP call share the one budget.
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hang
	}))
	t.Cleanup(func() { close(hang); srv.Close() })

	t.Setenv("OSSPREY_PRECOMMIT_TIMEOUT", "50ms")
	start := time.Now()
	_, err := checkMalwarePurls(context.Background(), srv.URL, "key", []string{"pkg:npm/evil-pkg@1.2.3"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("hanging server must yield an error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("check took %v; the 50ms env timeout was not honored", elapsed)
	}
}

func TestPrecommitVerboseCleanReportsCount(t *testing.T) {
	stubPrecommit(t, oneStagedPackage(),
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", true, &out); blocked {
		t.Fatal("clean commit must not be blocked")
	}
	if !strings.Contains(out.String(), "1 staged package(s) checked") {
		t.Errorf("verbose output: %q", out.String())
	}
}

// An Info hit is reported but must not block, consistent with this hook's
// documented fail-open posture.
func TestPrecommitInformationalHitDoesNotBlock(t *testing.T) {
	stubPrecommit(t, oneStagedPackage(),
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			return []client.MalwareHit{{
				Purl:     "pkg:npm/evil-pkg@1.2.3",
				Reason:   "This package was previously identified as malicious and removed from NPM",
				Severity: "Info",
			}}, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); blocked {
		t.Fatal("an informational hit must not block the commit")
	}
	got := out.String()
	if !strings.Contains(got, "flagged for information only") {
		t.Errorf("output missing the informational notice:\n%s", got)
	}
	if strings.Contains(got, "commit blocked") {
		t.Errorf("output must not claim the commit was blocked:\n%s", got)
	}
}

// Info must never mask a real detection staged alongside it.
func TestPrecommitInformationalAlongsideRealHitStillBlocks(t *testing.T) {
	stubPrecommit(t,
		func(context.Context, string) (precommit.Delta, error) {
			return precommit.Delta{Packages: []precommit.Package{
				{Type: "npm", Name: "evil-pkg", Version: "1.2.3", Path: "package-lock.json"},
				{Type: "npm", Name: "removed-pkg", Version: "0.0.1-security", Path: "package-lock.json"},
			}}, nil
		},
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			return []client.MalwareHit{
				{Purl: "pkg:npm/removed-pkg@0.0.1-security", Reason: "removed from NPM", Severity: "Info"},
				{Purl: "pkg:npm/evil-pkg@1.2.3", Reason: "exfiltrates env vars", Severity: "Critical"},
			}, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); !blocked {
		t.Fatal("a real detection must still block even alongside an informational hit")
	}
	got := out.String()
	if !strings.Contains(got, "evil-pkg@1.2.3 (npm, from package-lock.json): exfiltrates env vars") {
		t.Errorf("output missing the blocking hit:\n%s", got)
	}
	if !strings.Contains(got, "flagged for information only") {
		t.Errorf("output missing the informational notice:\n%s", got)
	}
}

// An ungraded hit is exactly what an older server sends, so it must block.
func TestPrecommitUngradedHitBlocks(t *testing.T) {
	stubPrecommit(t, oneStagedPackage(),
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			return []client.MalwareHit{{Purl: "pkg:npm/evil-pkg@1.2.3", Reason: "exfiltrates env vars"}}, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); !blocked {
		t.Fatal("a hit with no severity must block")
	}
}

// The reason is API-supplied free text printed to the developer's terminal, on
// both the blocking and the informational line.
func TestPrecommitSanitisesHitReason(t *testing.T) {
	for _, tc := range []struct {
		name     string
		severity string
		blocks   bool
	}{
		{"blocking", "Critical", true},
		{"informational", "Info", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubPrecommit(t, oneStagedPackage(),
				func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
					return []client.MalwareHit{{
						Purl:     "pkg:npm/evil-pkg@1.2.3",
						Reason:   "exfiltrates env vars\nossprey: commit allowed\x1b[32m",
						Severity: tc.severity,
					}}, nil
				})

			var out bytes.Buffer
			if blocked := runPrecommit(context.Background(), "https://api.test", "key", false, &out); blocked != tc.blocks {
				t.Fatalf("blocked = %v, want %v", blocked, tc.blocks)
			}
			body := strings.TrimSuffix(out.String(), "\n")
			if strings.ContainsAny(body, "\r\x1b") || strings.Contains(body, "\n\x1b") {
				t.Errorf("control characters survived: %q", out.String())
			}
			if strings.Contains(out.String(), "ossprey: commit allowed") &&
				!strings.Contains(out.String(), "vars ossprey: commit allowed") {
				t.Errorf("a forged line survived onto its own line: %q", out.String())
			}
		})
	}
}
