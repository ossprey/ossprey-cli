package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/precommit"
)

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

func TestPrecommitNoAPIKeyFailsOpen(t *testing.T) {
	stubPrecommit(t,
		func(context.Context, string) (precommit.Delta, error) {
			t.Error("delta must not be computed without an API key")
			return precommit.Delta{}, nil
		},
		func(context.Context, string, string, []string) ([]client.MalwareHit, error) {
			t.Error("check must not run without an API key")
			return nil, nil
		})

	var out bytes.Buffer
	if blocked := runPrecommit(context.Background(), "https://api.test", "", false, &out); blocked {
		t.Fatal("missing API key must fail open")
	}
	if !strings.Contains(out.String(), "no API key") {
		t.Errorf("want single-line warning about API key, got: %q", out.String())
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
