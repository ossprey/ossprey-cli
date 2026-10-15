package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo creates an isolated git repository and makes it the working
// directory, since the hook commands act on ".".
func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// Keep the developer's global/system git config (core.hooksPath) out.
	empty := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", empty)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	t.Chdir(dir)
	return dir
}

func runPrecommitSub(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newPrecommitCmdWithHooks()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	return out, err
}

func TestPrecommitHookLifecycle(t *testing.T) {
	repo := gitRepo(t)
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")

	out, err := runPrecommitSub(t, "status")
	if err != nil || !strings.Contains(out, "Not installed. Run `ossprey precommit install`") {
		t.Fatalf("status before install: %q, %v", out, err)
	}

	out, err = runPrecommitSub(t, "install")
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(out, "Installed pre-commit hook:") || !strings.Contains(out, "--no-verify") {
		t.Errorf("install output:\n%s", out)
	}
	if _, err := os.Stat(hookPath); err != nil {
		t.Fatalf("hook not written: %v", err)
	}
	// Re-running refreshes in place rather than failing.
	if _, err := runPrecommitSub(t, "install"); err != nil {
		t.Errorf("re-install: %v", err)
	}

	out, err = runPrecommitSub(t, "status")
	if err != nil || !strings.Contains(out, "Installed: ") {
		t.Errorf("status after install: %q, %v", out, err)
	}

	out, err = runPrecommitSub(t, "uninstall")
	if err != nil || !strings.Contains(out, "Removed pre-commit hook:") {
		t.Errorf("uninstall: %q, %v", out, err)
	}
	if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
		t.Errorf("hook still present: %v", err)
	}

	out, err = runPrecommitSub(t, "uninstall")
	if err != nil || !strings.Contains(out, "No ossprey pre-commit hook installed") {
		t.Errorf("second uninstall: %q, %v", out, err)
	}
}

// A hook ossprey did not write is never overwritten or deleted.
func TestPrecommitHookLeavesAForeignHookAlone(t *testing.T) {
	repo := gitRepo(t)
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	const theirs = "#!/bin/sh\necho their hook\n"
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte(theirs), 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := runPrecommitSub(t, "status")
	if err != nil || !strings.Contains(out, "A pre-commit hook ossprey did not write exists") {
		t.Errorf("status: %q, %v", out, err)
	}
	if _, err := runPrecommitSub(t, "install"); err == nil {
		t.Error("install overwrote a foreign hook without error")
	}
	if _, err := runPrecommitSub(t, "uninstall"); err == nil {
		t.Error("uninstall of a foreign hook reported success")
	}
	data, err := os.ReadFile(hookPath)
	if err != nil || string(data) != theirs {
		t.Errorf("foreign hook changed: %q, %v", data, err)
	}
}

func TestPrecommitHookCmdsOutsideARepoError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(t.TempDir()))
	t.Chdir(t.TempDir())
	for _, sub := range []string{"install", "status", "uninstall"} {
		if _, err := runPrecommitSub(t, sub); err == nil {
			t.Errorf("precommit %s outside a repository succeeded", sub)
		}
	}
}
