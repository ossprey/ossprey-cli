package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func TestParseNpmLock(t *testing.T) {
	// lockfileVersion 3 "packages" map: root project ("" key, no resolved),
	// a scoped dep, a nested dep, and a file: dep (no resolved).
	lock := []byte(`{
		"name": "app",
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app", "version": "1.0.0"},
			"node_modules/bootstrap": {"version": "3.4.7", "resolved": "https://registry.npmjs.org/bootstrap/-/bootstrap-3.4.7.tgz"},
			"node_modules/@types/bun": {"version": "1.3.14", "resolved": "https://registry.npmjs.org/@types/bun/-/bun-1.3.14.tgz"},
			"node_modules/a/node_modules/nested": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/nested/-/nested-2.0.0.tgz"},
			"node_modules/local-dep": {"version": "9.9.9"}
		}
	}`)

	got, err := parseNpmLock(lock, file.NewLocation("package.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := keySet(got)

	// real registry deps resolved (scope preserved, nested flattened to name)
	for _, want := range []string{"bootstrap@3.4.7", "@types/bun@1.3.14", "nested@2.0.0"} {
		if !keys[want] {
			t.Errorf("missing %q; got %v", want, keys)
		}
	}
	// root project and the file:/local dep (no "resolved") are dropped
	if keys["app@1.0.0"] {
		t.Error("root project should not be emitted")
	}
	if keys["local-dep@9.9.9"] {
		t.Error("dep without a registry tarball should be dropped")
	}
	if len(got) != 3 {
		t.Errorf("got %d packages, want 3: %v", len(got), keys)
	}
	for _, p := range got {
		if p.Type != pkg.NpmPkg {
			t.Errorf("%s: type = %v, want NpmPkg", p.Name, p.Type)
		}
	}
}

func TestParseNpmLock_BadJSON(t *testing.T) {
	if _, err := parseNpmLock([]byte(`{not json`), file.NewLocation("package.json")); err == nil {
		t.Error("expected error on invalid JSON")
	}
}

func TestNpmNameFromLockKey(t *testing.T) {
	tests := map[string]string{
		"node_modules/lodash":                   "lodash",
		"node_modules/@types/bun":               "@types/bun",
		"node_modules/a/node_modules/b":         "b",
		"node_modules/x/node_modules/@s/scoped": "@s/scoped",
	}
	for in, want := range tests {
		if got := npmNameFromLockKey(in); got != want {
			t.Errorf("npmNameFromLockKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasNpmLockfile(t *testing.T) {
	bare := t.TempDir()
	if hasNpmLockfile(bare) {
		t.Error("dir with no lockfile should report false")
	}
	withLock := t.TempDir()
	writeFile(t, withLock, "package-lock.json", "{}")
	if !hasNpmLockfile(withLock) {
		t.Error("dir with package-lock.json should report true")
	}
	withYarn := t.TempDir()
	writeFile(t, withYarn, "yarn.lock", "")
	if !hasNpmLockfile(withYarn) {
		t.Error("dir with yarn.lock should report true")
	}
}

// fakeNpm writes a script that stands in for npm, with the given body.
func fakeNpm(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in for npm is POSIX only")
	}
	path := filepath.Join(t.TempDir(), "npm")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

const fakeLock = `{"name":"app","lockfileVersion":3,"packages":{` +
	`"":{"name":"app","version":"1.0.0"},` +
	`"node_modules/bootstrap":{"version":"3.4.7","resolved":"https://registry.npmjs.org/bootstrap/-/bootstrap-3.4.7.tgz"}}}`

func manifest(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"app","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A grandchild holding the output pipe open past npm's own exit trips WaitDelay,
// which replaces the successful status with ErrWaitDelay. The lock is already
// written, so the resolve must not be discarded.
func TestRunNpmResolve_RecoversLockWhenPipeOutlivesNpm(t *testing.T) {
	npm := fakeNpm(t, "cat > package-lock.json <<'JSON'\n"+fakeLock+"\nJSON\nsleep 30 &\nexit 0\n")

	got, err := runNpmResolve(context.Background(), npm, t.TempDir(), manifest(t), file.NewLocation("package.json"))
	if err != nil {
		t.Fatalf("resolve discarded a completed npm run: %v", err)
	}
	if !keySet(got)["bootstrap@3.4.7"] {
		t.Errorf("packages = %v, want bootstrap@3.4.7", keySet(got))
	}
}

// A genuine npm failure must still be reported, and must not be masked by a
// stale or partial lock.
func TestRunNpmResolve_RealFailureStillErrors(t *testing.T) {
	npm := fakeNpm(t, "echo 'npm error code E404' >&2\nexit 1\n")

	if _, err := runNpmResolve(context.Background(), npm, t.TempDir(), manifest(t), file.NewLocation("package.json")); err == nil {
		t.Fatal("expected an error for a failing npm")
	} else if !strings.Contains(err.Error(), "E404") {
		t.Errorf("error should carry npm's output, got: %v", err)
	}
}

// Exiting cleanly without writing a lock is still a failure.
func TestRunNpmResolve_NoLockIsAnError(t *testing.T) {
	npm := fakeNpm(t, "exit 0\n")

	if _, err := runNpmResolve(context.Background(), npm, t.TempDir(), manifest(t), file.NewLocation("package.json")); err == nil {
		t.Fatal("expected an error when no package-lock.json is produced")
	}
}
