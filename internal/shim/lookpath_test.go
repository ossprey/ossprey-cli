package shim

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestLookPathRealSkipsShims covers the failure this whole guard exists for: if
// `ossprey npm` resolved `npm` to the shim that invoked it, every install would
// fork until the machine died.
func TestLookPathRealSkipsShims(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)

	writeExec(t, filepath.Join(shimDir, "npm"), Script("npm", shimDir, filepath.Join(root, "ossprey")))
	real := filepath.Join(realDir, "npm")
	writeExec(t, real, "#!/bin/sh\nexit 0\n")

	t.Setenv("PATH", shimDir+":"+realDir)

	got, err := LookPathReal("npm")
	if err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Fatalf("LookPathReal = %q, want the real npm at %q", got, real)
	}
}

func TestLookPathRealReportsShimOnlyPath(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	mkdirs(t, shimDir)
	writeExec(t, filepath.Join(shimDir, "npm"), Script("npm", shimDir, filepath.Join(root, "ossprey")))
	t.Setenv("PATH", shimDir)

	_, err := LookPathReal("npm")
	if err == nil {
		t.Fatal("expected an error when only a shim is on PATH")
	}
	// The message has to name the fix; this is the state a broken uninstall or a
	// removed node install leaves a developer in.
	if !strings.Contains(err.Error(), "ossprey shim") {
		t.Fatalf("error does not tell the user what to do: %v", err)
	}
}

func TestLookPathRealSkipsNonExecutable(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	mkdirs(t, a, b)
	if err := writeFilePreservingMode(filepath.Join(a, "npm"), []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(b, "npm")
	writeExec(t, real, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", a+":"+b)

	got, err := LookPathReal("npm")
	if err != nil || got != real {
		t.Fatalf("LookPathReal = %q, %v; want %q", got, err, real)
	}
}
