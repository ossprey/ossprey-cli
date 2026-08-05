package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScriptCarriesMarkerAndBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, scriptName("npm"))
	bin := filepath.Join(dir, "..", "ossprey")

	if err := os.WriteFile(path, []byte(Script("npm", dir, bin)), 0o755); err != nil {
		t.Fatal(err)
	}
	if !IsShim(path) {
		t.Fatal("generated shim is not recognised by IsShim")
	}
	if got := ShimBinary(path); got != bin {
		t.Fatalf("ShimBinary = %q, want %q", got, bin)
	}
}

func TestIsShimIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "npm")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho real npm\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if IsShim(path) {
		t.Fatal("a real script was mistaken for a shim — this is the guard against shadowing the wrong file")
	}
	if got := ShimBinary(path); got != "" {
		t.Fatalf("ShimBinary of a non-shim = %q, want empty", got)
	}
}

func TestShimExecsOssprey(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	realDir := filepath.Join(root, "real")
	for _, d := range []string{shimDir, realDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	ossprey := filepath.Join(root, "ossprey")
	writeExec(t, ossprey, "#!/bin/sh\necho \"ossprey called: $*\"\necho \"PATH=$PATH\"\n")
	writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\necho \"real npm: $*\"\n")

	writeExec(t, filepath.Join(shimDir, "npm"), Script("npm", shimDir, ossprey))

	out := runShim(t, shimDir, realDir, nil, "install", "left-pad")
	if !strings.Contains(out, "ossprey called: npm install left-pad") {
		t.Fatalf("shim did not forward to ossprey with the original args:\n%s", out)
	}
	if strings.Contains(out, shimDir) {
		t.Fatalf("shim left its own directory on PATH — a recursion waiting to happen:\n%s", out)
	}
}

func TestShimPreservesGlobbyPathEntries(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)

	ossprey := filepath.Join(root, "ossprey")
	writeExec(t, ossprey, "#!/bin/sh\necho \"PATH=$PATH\"\n")
	writeExec(t, filepath.Join(shimDir, "npm"), Script("npm", shimDir, ossprey))
	mkdirs(t, filepath.Join(root, "match-a"), filepath.Join(root, "match-b"))

	globby := filepath.Join(root, "match-*")
	cmd := exec.Command(filepath.Join(shimDir, "npm"), "install", "x")
	cmd.Env = []string{"PATH=" + shimDir + ":" + globby + ":" + realDir}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shim: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), globby) {
		t.Fatalf("the PATH entry %s was rewritten by pathname expansion:\n%s", globby, out)
	}
}

func TestShimBypassSkipsOssprey(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)

	ossprey := filepath.Join(root, "ossprey")
	writeExec(t, ossprey, "#!/bin/sh\necho \"ossprey called\"\n")
	writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\necho \"real npm: $*\"\n")
	writeExec(t, filepath.Join(shimDir, "npm"), Script("npm", shimDir, ossprey))

	out := runShim(t, shimDir, realDir, []string{BypassEnv + "=1"}, "install", "left-pad")
	if strings.Contains(out, "ossprey called") {
		t.Fatalf("%s did not bypass the check:\n%s", BypassEnv, out)
	}
	if !strings.Contains(out, "real npm: install left-pad") {
		t.Fatalf("bypass did not reach the real npm:\n%s", out)
	}
}

func TestShimFailsOpen(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)

	writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\necho \"real npm: $*\"\n")
	writeExec(t, filepath.Join(shimDir, "npm"), Script("npm", shimDir, filepath.Join(root, "does-not-exist")))

	out := runShim(t, shimDir, realDir, nil, "install", "left-pad")
	if !strings.Contains(out, "real npm: install left-pad") {
		t.Fatalf("shim did not fall through to the real npm when ossprey was missing:\n%s", out)
	}
	if !strings.Contains(out, "is missing") {
		t.Fatalf("shim fell through silently; a developer needs to know they are unprotected:\n%s", out)
	}
}

func runShim(t *testing.T, shimDir, realDir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(shimDir, "npm"), args...)
	cmd.Env = append([]string{"PATH=" + shimDir + ":" + realDir}, env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shim: %v\n%s", err, out)
	}
	return string(out)
}

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func requirePOSIX(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shim behaviour; the .cmd shim is exercised on Windows CI")
	}
}
