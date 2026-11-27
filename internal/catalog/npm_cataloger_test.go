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
	"github.com/anchore/syft/syft/source"
)

func TestParseNpmLock(t *testing.T) {
	// lockfileVersion 3 "packages" map: root project ("" key, no resolved),
	// a scoped dep, a nested dep, and a file: dep as npm records one (a
	// link under node_modules pointing at the local package, which has no
	// resolved of its own).
	lock := []byte(`{
		"name": "app",
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app", "version": "1.0.0"},
			"node_modules/bootstrap": {"version": "3.4.7", "resolved": "https://registry.npmjs.org/bootstrap/-/bootstrap-3.4.7.tgz"},
			"node_modules/@types/bun": {"version": "1.3.14", "resolved": "https://registry.npmjs.org/@types/bun/-/bun-1.3.14.tgz"},
			"node_modules/a/node_modules/nested": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/nested/-/nested-2.0.0.tgz"},
			"node_modules/local-dep": {"resolved": "../local-dep", "link": true},
			"../local-dep": {"version": "9.9.9"}
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
		t.Error("a file: dep, linked from node_modules, should be dropped")
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

// lockedDirs is npmLockDirs over a fresh index of root with the given ignore
// patterns, as NpmResolveCataloger computes it during a scan.
func lockedDirs(t *testing.T, root string, ignore ...string) map[string]bool {
	t.Helper()
	src, err := newDirectorySource(root, 0, ignore...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	return npmLockDirs(resolver, root)
}

func TestNpmLockDirs(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"bare/package.json":          "{}",
		"npm/package-lock.json":      "{}",
		"yarn/yarn.lock":             "",
		"pnpm/pnpm-lock.yaml":        "",
		"shrink/npm-shrinkwrap.json": "{}",
		"ignored/package-lock.json":  "{}",
	})
	locked := lockedDirs(t, root, "ignored/package-lock.json")
	for dir, want := range map[string]bool{"bare": false, "npm": true, "yarn": true, "pnpm": true, "shrink": true, "ignored": false} {
		if got := locked[filepath.Join(root, dir)]; got != want {
			t.Errorf("%s: locked = %v, want %v", dir, got, want)
		}
	}
}

// TestIgnoredLockfileDoesNotStandTheResolveDown pins that the stand-down reads
// the scan's own index. An ignored lockfile is never read by the lock
// catalogers, so if the resolve still stood down for it the project would
// keep only its direct dependencies, with nothing said.
func TestIgnoredLockfileDoesNotStandTheResolveDown(t *testing.T) {
	npm := fakeNpm(t, "cat > package-lock.json <<'JSON'\n"+fakeLock+"\nJSON\nexit 0\n")
	t.Setenv("PATH", filepath.Dir(npm)+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin")
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"package.json": `{"name":"app","version":"1.0.0","dependencies":{"bootstrap":"^3.4.0"}}`,
		"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0"},` +
			`"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`,
	})
	names := func(ignore ...string) map[string]bool {
		pkgs, err := Catalog(context.Background(), root, Options{SkipVersionLookup: true, Ignore: ignore})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, p := range pkgs {
			got[p.Name+"@"+p.Version] = true
		}
		return got
	}
	if got := names(); !got["left-pad@1.3.0"] || got["bootstrap@3.4.7"] {
		t.Errorf("with the lockfile read: %v, want left-pad from the lock and no resolve", got)
	}
	if got := names("package-lock.json"); got["left-pad@1.3.0"] || !got["bootstrap@3.4.7"] {
		t.Errorf("with the lockfile ignored: %v, want the resolve's bootstrap and not the lock's left-pad", got)
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
