package shim

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fail-open paths (bypass, missing binary) exec the manager by name, so a
// PATH that still reaches the shim under another spelling -- a trailing slash,
// a doubled separator, a symlinked alias -- used to exec the shim again,
// forever. Each case must reach the real manager, under a timeout.
func TestShimFailOpenDoesNotLoopOnAnotherSpellingOfItsDir(t *testing.T) {
	requirePOSIX(t)
	grep, err := exec.LookPath("grep")
	if err != nil {
		t.Skip("no grep")
	}

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(shimDir, alias); err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\necho \"real npm: $*\"\n")
	present := filepath.Join(root, "ossprey")
	writeExec(t, present, "#!/bin/sh\necho ossprey called\n")

	spellings := map[string]string{
		"trailing slash": shimDir + "/",
		"doubled slash":  root + "//shims",
		"symlink alias":  alias,
	}
	for name, entry := range spellings {
		for _, failOpen := range []string{"bypass", "missing binary"} {
			t.Run(name+"/"+failOpen, func(t *testing.T) {
				bin, env := present, []string{BypassEnv + "=1"}
				if failOpen == "missing binary" {
					bin, env = filepath.Join(root, "gone"), nil
				}
				writeExec(t, filepath.Join(shimDir, "npm"), Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: bin}))

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "sh", filepath.Join(shimDir, "npm"), "install", "x")
				cmd.Env = append([]string{"PATH=" + strings.Join([]string{entry, realDir, filepath.Dir(grep)}, ":")}, env...)
				out, err := cmd.CombinedOutput()
				if ctx.Err() != nil {
					t.Fatalf("shim looped until the timeout:\n%.500s", out)
				}
				if err != nil || !strings.Contains(string(out), "real npm: install x") {
					t.Fatalf("real npm did not run: %v\n%s", err, out)
				}
			})
		}
	}
}

// When every candidate is a shim the marker check cannot see (no grep on PATH),
// the depth guard stops the loop with an error instead of spinning.
func TestShimReentryGuardStopsALoop(t *testing.T) {
	requirePOSIX(t)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}

	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	mkdirs(t, shimDir)
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(shimDir, alias); err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(shimDir, "npm"), Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: filepath.Join(root, "gone")}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh, filepath.Join(shimDir, "npm"), "install")
	cmd.Env = []string{"PATH=" + alias}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("shim looped until the timeout:\n%.500s", out)
	}
	if err == nil || !strings.Contains(string(out), "giving up") {
		t.Fatalf("want a clear re-entry error, got %v:\n%.2000s", err, out)
	}
}

// A newline in the binary or shim path would end the `# ossprey-bin:` header
// line early (and break the .cmd shim outright), so it is refused up front.
func TestPlanRejectsANewlineInPaths(t *testing.T) {
	root := t.TempDir()
	for _, o := range []Options{
		{Dir: filepath.Join(root, "shims"), Binary: filepath.Join(root, "oss\nprey")},
		{Dir: filepath.Join(root, "sh\rims"), Binary: filepath.Join(root, "ossprey")},
	} {
		o.SkipProfiles, o.All, o.Managers = true, true, []string{"npm"}
		if _, err := Plan(o); err == nil {
			t.Errorf("Plan(%q, %q) accepted a line break", o.Dir, o.Binary)
		}
	}
}
