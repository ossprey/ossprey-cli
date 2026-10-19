package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// captureStderr returns what fn wrote to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	defer func() {
		os.Stderr = orig
	}()
	fn()
	os.Stderr = orig
	w.Close()
	out := <-done
	r.Close()
	return out
}

// --timeout keeps what was catalogued before the deadline instead of failing:
// a lockfile parsed first survives a resolver that hangs past it, the scan is
// not an error, the deadline is said once, and the resolver's own failure is
// not reported per manifest.
func TestRunTimeoutEmitsPartialSBOM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte("#!/bin/sh\nexec "+sleep+" 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("OSSPREY_RESOLVE_TIMEOUT", "") // only the scan deadline applies
	noCI(t)

	dir := t.TempDir()
	for rel, body := range map[string]string{
		"locked/package-lock.json": `{"name":"a","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"a","version":"1.0.0"},` +
			`"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`,
		"unlocked/package.json": `{"name":"b","version":"1.0.0","dependencies":{"is-odd":"^3.0.0"}}`,
	} {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx := warn.NewContext(context.Background(), false)
	var (
		names  []string
		runErr error
	)
	start := time.Now()
	stderr := captureStderr(t, func() {
		sbom, err := Run(ctx, Options{Path: dir, SkipVersionLookup: true, Timeout: 1500 * time.Millisecond})
		runErr = err
		if sbom != nil {
			names = componentNames(sbom)
		}
	})
	if runErr != nil {
		t.Fatalf("Run: %v (a deadline must not fail the scan)", runErr)
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Errorf("Run took %s; the scan deadline did not bound it", el)
	}
	if !strings.Contains(strings.Join(names, " "), "left-pad") {
		t.Errorf("components = %v; what resolved before the deadline was lost", names)
	}
	if !strings.Contains(stderr, "scan deadline (1.5s) reached") {
		t.Errorf("deadline not reported on stderr:\n%s", stderr)
	}
	if out := warn.Drain(ctx); strings.Contains(out, "npm") {
		t.Errorf("per-manifest resolver failure reported past the deadline:\n%s", out)
	}
}

// A scan with no deadline must not announce one.
func TestRunWithoutTimeoutIsSilentAboutDeadlines(t *testing.T) {
	dir := t.TempDir()
	stderr := captureStderr(t, func() {
		if _, err := Run(context.Background(), Options{Path: dir, NoExec: true, SkipVersionLookup: true}); err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	if strings.Contains(stderr, "deadline") {
		t.Errorf("unexpected deadline message:\n%s", stderr)
	}
}
