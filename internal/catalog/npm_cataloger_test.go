package catalog

import (
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
