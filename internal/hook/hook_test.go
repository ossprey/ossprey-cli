package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// initRepo creates an empty git repository and returns its path. No commits
// are needed: hook management only touches the hooks directory.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	return dir
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestInstallWritesExecutableHook(t *testing.T) {
	repo := initRepo(t)

	st, err := Install(repo)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if st.State != Installed {
		t.Fatalf("state = %v, want Installed", st.State)
	}
	if want := filepath.Join(repo, ".git", "hooks", "pre-commit"); st.Path != want {
		t.Fatalf("path = %q, want %q", st.Path, want)
	}

	body, err := os.ReadFile(st.Path)
	if err != nil {
		t.Fatalf("read hook: %v", err)
	}
	if !strings.Contains(string(body), Marker) {
		t.Fatalf("hook does not carry marker:\n%s", body)
	}
	if !strings.Contains(string(body), "exec ossprey precommit") {
		t.Fatalf("hook does not exec ossprey precommit:\n%s", body)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(st.Path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("hook is not executable: mode %v", info.Mode())
		}
	}
}

func TestInstallRefusesForeignHook(t *testing.T) {
	repo := initRepo(t)
	foreign := "#!/bin/sh\necho somebody else's hook\n"
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hookPath, []byte(foreign), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(repo); err == nil {
		t.Fatal("Install over a foreign hook did not error")
	} else if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("error = %v, want refusal message", err)
	}

	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != foreign {
		t.Fatalf("foreign hook was modified:\n%s", body)
	}
}

func TestReinstallRefreshesOurHook(t *testing.T) {
	repo := initRepo(t)
	if _, err := Install(repo); err != nil {
		t.Fatalf("first Install: %v", err)
	}

	// Simulate a stale/damaged ossprey hook: still marked, wrong body.
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	stale := "#!/bin/sh\n# " + Marker + "\necho old version\n"
	if err := os.WriteFile(hookPath, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Install(repo); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != Script {
		t.Fatalf("reinstall did not refresh the script:\n%s", body)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(hookPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("refreshed hook lost the executable bit: mode %v", info.Mode())
		}
	}
}

func TestUninstallRemovesOurHookOnly(t *testing.T) {
	repo := initRepo(t)
	if _, err := Install(repo); err != nil {
		t.Fatalf("Install: %v", err)
	}

	st, err := Uninstall(repo)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if st.State != NotInstalled {
		t.Fatalf("state = %v, want NotInstalled", st.State)
	}
	if _, err := os.Stat(st.Path); !os.IsNotExist(err) {
		t.Fatalf("hook still exists after uninstall (stat err = %v)", err)
	}

	// Idempotent: uninstalling again is not an error.
	if _, err := Uninstall(repo); err != nil {
		t.Fatalf("second Uninstall: %v", err)
	}
}

func TestUninstallLeavesForeignHook(t *testing.T) {
	repo := initRepo(t)
	foreign := "#!/bin/sh\necho keep me\n"
	hookPath := filepath.Join(repo, ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hookPath, []byte(foreign), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Uninstall(repo); err == nil {
		t.Fatal("Uninstall of a foreign hook did not error")
	}
	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != foreign {
		t.Fatalf("foreign hook was modified:\n%s", body)
	}
}

func TestLoadStates(t *testing.T) {
	repo := initRepo(t)

	st, err := Load(repo)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.State != NotInstalled {
		t.Fatalf("empty repo state = %v, want NotInstalled", st.State)
	}

	if _, err := Install(repo); err != nil {
		t.Fatal(err)
	}
	if st, _ = Load(repo); st.State != Installed {
		t.Fatalf("after install state = %v, want Installed", st.State)
	}

	if err := os.WriteFile(st.Path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if st, _ = Load(repo); st.State != Foreign {
		t.Fatalf("foreign hook state = %v, want Foreign", st.State)
	}
}

func TestCoreHooksPathRespected(t *testing.T) {
	repo := initRepo(t)
	// Relative core.hooksPath is resolved against the repo root by git.
	run(t, repo, "config", "core.hooksPath", "custom/hooks")

	st, err := Install(repo)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	want := filepath.Join(repo, "custom", "hooks", "pre-commit")
	if st.Path != want {
		t.Fatalf("path = %q, want %q", st.Path, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("hook not written under core.hooksPath: %v", err)
	}
	// The default location must be untouched.
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "pre-commit")); !os.IsNotExist(err) {
		t.Fatalf("hook also written to default location (stat err = %v)", err)
	}
}

func TestCoreHooksPathAbsolute(t *testing.T) {
	repo := initRepo(t)
	hooks := filepath.Join(t.TempDir(), "hooks")
	run(t, repo, "config", "core.hooksPath", hooks)

	st, err := Install(repo)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if want := filepath.Join(hooks, "pre-commit"); st.Path != want {
		t.Fatalf("path = %q, want %q", st.Path, want)
	}
}

func TestNotAGitRepo(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("Load outside a git repo did not error")
	}
	if _, err := Install(dir); err == nil {
		t.Fatal("Install outside a git repo did not error")
	}
}
