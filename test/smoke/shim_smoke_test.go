//go:build smoke

package smoke

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestShimEndToEnd installs real shims with the real binary, then runs a package
// manager through one. It is the only test that covers the whole chain the
// customer actually uses: PATH → shim script → ossprey → real manager.
func TestShimEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shim scripts; the .cmd path is covered by unit tests")
	}

	root := t.TempDir()
	home := filepath.Join(root, "home")
	realDir := filepath.Join(root, "real")
	for _, d := range []string{home, realDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A stand-in npm, so this test needs nothing installed on the machine.
	if err := os.WriteFile(filepath.Join(realDir, "npm"),
		[]byte("#!/bin/sh\necho \"REAL NPM: $*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shimDir := filepath.Join(home, ".ossprey", "shims")
	env := []string{"HOME=" + home, "PATH=" + realDir + ":" + os.Getenv("PATH")}

	out, code := run(t, env, binPath, "shim", "install", "--managers", "npm")
	if code != 0 {
		t.Fatalf("shim install exited %d: %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(shimDir, "npm")); err != nil {
		t.Fatalf("no npm shim written: %v", err)
	}
	profile, err := os.ReadFile(filepath.Join(home, ".profile"))
	if err != nil || !strings.Contains(string(profile), shimDir) {
		t.Fatalf("~/.profile does not prepend the shim dir: %v\n%s", err, profile)
	}

	// With the shim dir first on PATH, `npm run build` must reach the real npm
	// with its arguments intact — and must not loop.
	shimEnv := []string{"HOME=" + home, "PATH=" + shimDir + ":" + realDir}
	out, code = run(t, shimEnv, filepath.Join(shimDir, "npm"), "run", "build")
	if code != 0 {
		t.Fatalf("npm run through the shim exited %d: %s", code, out)
	}
	if !strings.Contains(out, "REAL NPM: run build") {
		t.Fatalf("shim did not reach the real npm:\n%s", out)
	}

	out, code = run(t, shimEnv, binPath, "shim", "status")
	if code != 0 || !strings.Contains(out, "npm") {
		t.Fatalf("shim status exited %d: %s", code, out)
	}
	if !strings.Contains(out, "✓") {
		t.Fatalf("status does not report npm as intercepted:\n%s", out)
	}

	if out, code = run(t, env, binPath, "shim", "uninstall"); code != 0 {
		t.Fatalf("shim uninstall exited %d: %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(shimDir, "npm")); !os.IsNotExist(err) {
		t.Fatal("uninstall left the npm shim behind")
	}
	if profile, err := os.ReadFile(filepath.Join(home, ".profile")); err == nil &&
		strings.Contains(string(profile), shimDir) {
		t.Fatalf("uninstall left the PATH entry behind:\n%s", profile)
	}
}

func run(t *testing.T, env []string, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		}
		t.Fatalf("run %s: %v\n%s", name, err, out)
	}
	return string(out), 0
}
