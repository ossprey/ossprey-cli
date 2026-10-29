package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/shim"
)

// runShim runs `ossprey shim <args>`, capturing stdout. Every call that could
// touch PATH passes --no-path: on Windows the PATH change is the user registry.
func runShim(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newShimCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	return out, err
}

func isolateShim(t *testing.T) string {
	t.Helper()
	isolateConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(shim.BypassEnv, "")
	dir := filepath.Join(t.TempDir(), "shims")
	t.Setenv(shim.DirEnv, dir)
	return dir
}

// fakeBinary is a file standing in for the ossprey binary the shims call.
func fakeBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ossprey")
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	if err := os.WriteFile(p, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The monitor id is the whole credential: install, dry-run and status output
// land in scrollback and CI logs, so none of them may print it in full.
func TestShimMonitorIDNeverPrintedInFull(t *testing.T) {
	dir := isolateShim(t)
	bin := fakeBinary(t)

	preview, err := runShim(t, "install", "--dry-run", "--managers", "npm", "--no-path", "--binary", bin, "--monitor", validMonitorID)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !strings.Contains(preview, "Would write shims to "+dir) || !strings.Contains(preview, "Passive (monitor)") {
		t.Errorf("preview:\n%s", preview)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("--dry-run wrote the shim directory: %v", statErr)
	}

	installed, err := runShim(t, "install", "--managers", "npm", "--no-path", "--binary", bin, "--monitor", validMonitorID)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(installed, "Installed 1 shim(s)") || !strings.Contains(installed, "PATH not modified (--no-path)") {
		t.Errorf("install output:\n%s", installed)
	}

	// Shim directory first, so npm resolves to the shim and reports as active.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	status, err := runShim(t, "status", "--dir", dir)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(status, "Shims call:     "+bin+" (ok)") {
		t.Errorf("status does not name the binary:\n%s", status)
	}
	if !strings.Contains(status, "monitor, never blocked") || !strings.Contains(status, "(monitor ospi_") {
		t.Errorf("status does not report the monitor mode:\n%s", status)
	}

	for name, out := range map[string]string{"dry run": preview, "install": installed, "status": status} {
		if strings.Contains(out, validMonitorID) {
			t.Errorf("%s printed the full monitor id:\n%s", name, out)
		}
	}
}

// A hostile or mistyped id is refused before anything is written, dry run
// included, and is not echoed back.
func TestShimInstallRejectsABadMonitorID(t *testing.T) {
	dir := isolateShim(t)
	bad := "ospi_$(touch pwned)"
	for _, extra := range [][]string{{"--dry-run"}, nil} {
		args := append([]string{"install", "--managers", "npm", "--no-path", "--binary", fakeBinary(t), "--monitor", bad}, extra...)
		_, err := runShim(t, args...)
		if err == nil {
			t.Fatalf("%v: accepted", args)
		}
		if strings.Contains(err.Error(), "pwned") {
			t.Errorf("error echoed the id: %v", err)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("a refused install wrote %s: %v", dir, err)
	}
}

// Status must say loudly when the binary a shim calls is gone: the shims then
// fail open and pass installs through unchecked.
func TestShimStatusFlagsAMissingBinary(t *testing.T) {
	dir := isolateShim(t)
	bin := fakeBinary(t)
	if _, err := runShim(t, "install", "--managers", "npm", "--no-path", "--binary", bin); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	status, err := runShim(t, "status", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "MISSING") || !strings.Contains(status, "unchecked") {
		t.Errorf("status hides the missing binary:\n%s", status)
	}
}

func TestShimStatusWithNothingInstalled(t *testing.T) {
	dir := isolateShim(t)
	status, err := runShim(t, "status")
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(dir)
	if !strings.Contains(status, "Shim directory: "+abs) || !strings.Contains(status, "No shims installed") {
		t.Errorf("status:\n%s", status)
	}
}

// A watchdog shim reports that it never blocks, so nobody reads status as
// "protected" when the gate is off.
func TestShimStatusSaysPassiveShimsNeverBlock(t *testing.T) {
	dir := isolateShim(t)
	if _, err := runShim(t, "install", "--managers", "npm", "--no-path", "--binary", fakeBinary(t), "--watchdog"); err != nil {
		t.Fatal(err)
	}
	// Put the shim directory first so npm resolves to the shim (Active).
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	status, err := runShim(t, "status", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "watchdog, never blocked") {
		t.Errorf("status does not say the watchdog shim never blocks:\n%s", status)
	}
}

func TestShimInstallWithNoManagersFound(t *testing.T) {
	isolateShim(t)
	t.Setenv("PATH", t.TempDir())
	out, err := runShim(t, "install", "--no-path", "--binary", fakeBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "No package managers to shim") || !strings.Contains(out, "--all") {
		t.Errorf("output:\n%s", out)
	}
}

func TestShimUninstallRemovesOnlyOurShims(t *testing.T) {
	dir := isolateShim(t)
	if _, err := runShim(t, "install", "--managers", "npm,pip", "--no-path", "--binary", fakeBinary(t)); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "README.txt")
	if err := os.WriteFile(foreign, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runShim(t, "uninstall", "--no-path")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Removed 2 shim(s) from "+dir) {
		t.Errorf("uninstall output:\n%s", out)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("uninstall removed a file it did not write: %v", err)
	}

	out, err = runShim(t, "uninstall", "--no-path")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "No ossprey shims found in "+dir) {
		t.Errorf("second uninstall output:\n%s", out)
	}
}

// `shim dir` is what tests and scripts ask for instead of assuming a path.
func TestShimDirHonoursTheOverride(t *testing.T) {
	dir := isolateShim(t)
	out, err := runShim(t, "dir")
	if err != nil {
		t.Fatal(err)
	}
	if out != dir+"\n" {
		t.Errorf("shim dir = %q, want %q", out, dir)
	}
}
