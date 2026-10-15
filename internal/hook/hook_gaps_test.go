package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func requirePOSIX(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("runs the hook under /bin/sh")
	}
}

// runHook runs the generated hook with PATH set to pathDirs only.
func runHook(t *testing.T, pathDirs ...string) (string, int) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	hook := filepath.Join(t.TempDir(), "pre-commit")
	if err := os.WriteFile(hook, []byte(Script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, hook, "--extra")
	cmd.Env = []string{"PATH=" + strings.Join(pathDirs, string(os.PathListSeparator))}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

// No ossprey on PATH: warn and let the commit through.
func TestHookFailsOpenWithoutTheBinary(t *testing.T) {
	requirePOSIX(t)
	out, code := runHook(t, t.TempDir())
	if code != 0 {
		t.Fatalf("hook exited %d without ossprey; a missing binary must not block commits", code)
	}
	if !strings.Contains(out, "skipping pre-commit malware check") {
		t.Fatalf("hook failed open silently: %q", out)
	}
}

// With ossprey present the hook hands over to `ossprey precommit`, passing its
// arguments and returning its verdict as the hook's exit status.
func TestHookExecsOsspreyPrecommitAndKeepsItsExitCode(t *testing.T) {
	requirePOSIX(t)
	for _, verdict := range []int{0, 1} {
		bin := t.TempDir()
		body := "#!/bin/sh\necho \"ossprey $*\"\nexit " + strconv.Itoa(verdict) + "\n"
		if err := os.WriteFile(filepath.Join(bin, "ossprey"), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		out, code := runHook(t, bin)
		if !strings.Contains(out, "ossprey precommit --extra") {
			t.Fatalf("hook did not exec `ossprey precommit`: %q", out)
		}
		if code != verdict {
			t.Fatalf("hook exit = %d, want ossprey's %d", code, verdict)
		}
	}
}

// Installing from a subdirectory still targets the repository's hooks dir.
func TestInstallFromSubdirectory(t *testing.T) {
	repo := initRepo(t)
	sub := filepath.Join(repo, "web", "app")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := Install(sub)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(repo, ".git", "hooks", "pre-commit"))
	got, _ := filepath.EvalSymlinks(st.Path)
	if got != want {
		t.Fatalf("hook path = %q, want %q", st.Path, want)
	}
}

// A linked worktree shares the main repository's hooks, so that is where the
// hook goes (git runs it from there for every worktree).
func TestInstallFromLinkedWorktree(t *testing.T) {
	repo := initRepo(t)
	run(t, repo, "-c", "user.email=t@ossprey.com", "-c", "user.name=T", "commit", "-q", "--allow-empty", "-m", "init")
	wt := filepath.Join(t.TempDir(), "wt")
	run(t, repo, "worktree", "add", "-q", wt)

	st, err := Install(wt)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(repo, ".git", "hooks"))
	got, _ := filepath.EvalSymlinks(filepath.Dir(st.Path))
	if got != want {
		t.Fatalf("worktree hook dir = %q, want the shared %q", st.HooksDir, want)
	}
	if st, _ := Load(repo); st.State != Installed {
		t.Fatalf("main checkout does not see the worktree's install: %v", st.State)
	}
}

// End to end: git really runs the installed hook, and a failing verdict stops
// the commit while a clean one lets it through.
func TestInstalledHookGatesARealCommit(t *testing.T) {
	requirePOSIX(t)
	repo := initRepo(t)
	if _, err := Install(repo); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	fake := filepath.Join(bin, "ossprey")
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}

	commit := func() error {
		cmd := exec.Command(gitPath, "-C", repo, "-c", "user.email=t@ossprey.com", "-c", "user.name=T",
			"commit", "-q", "--allow-empty", "-m", "x")
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		return cmd.Run()
	}

	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := commit(); err == nil {
		t.Fatal("commit succeeded although ossprey precommit reported malware")
	}
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatalf("clean commit was blocked: %v", err)
	}
}

// Uninstall under core.hooksPath removes the hook there and leaves the
// directory's other hooks alone.
func TestUninstallUnderCoreHooksPathKeepsOtherHooks(t *testing.T) {
	repo := initRepo(t)
	hooks := filepath.Join(t.TempDir(), "shared-hooks")
	run(t, repo, "config", "core.hooksPath", hooks)
	if _, err := Install(repo); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(hooks, "commit-msg")
	if err := os.WriteFile(other, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(repo); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(hooks, "pre-commit")); !os.IsNotExist(err) {
		t.Fatal("hook survived uninstall")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("uninstall touched another hook: %v", err)
	}
}
