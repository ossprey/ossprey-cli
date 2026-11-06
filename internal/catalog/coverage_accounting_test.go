package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// unresolvedFor catalogs files on a host with no resolver on PATH and returns
// the manifests recorded unresolved.
func unresolvedFor(t *testing.T, files map[string]string) []string {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	proj := t.TempDir()
	writeTree(t, proj, files)
	ctx := warn.NewContext(context.Background(), false)
	if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	return warn.Unresolved(ctx)
}

const validCargoLock = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"

// A crate with dependencies and no Cargo.lock covering it catalogues direct
// dependencies only, which must not read as complete.
func TestCargoCrateWithoutLockIsUnresolved(t *testing.T) {
	crate := "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n"
	member := "[package]\nname = \"core\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n"
	root := "[workspace]\nmembers = [\"crates/*\"]\n"
	cases := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"no lock", map[string]string{"Cargo.toml": crate}, []string{"Cargo.toml"}},
		{"lock beside", map[string]string{"Cargo.toml": crate, "Cargo.lock": validCargoLock}, nil},
		{"unparseable lock", map[string]string{"Cargo.toml": crate, "Cargo.lock": "[[package]\nname = "}, []string{"Cargo.toml"}},
		{"member under a locked workspace root", map[string]string{
			"Cargo.toml": root, "Cargo.lock": validCargoLock, "crates/core/Cargo.toml": member,
		}, nil},
		{"member under a workspace root with no lock", map[string]string{
			"Cargo.toml": root, "crates/core/Cargo.toml": member,
		}, []string{"crates/core/Cargo.toml"}},
		{"no dependencies", map[string]string{"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := unresolvedFor(t, tc.files); !slices.Equal(got, tc.want) {
				t.Errorf("unresolved = %v, want %v", got, tc.want)
			}
		})
	}
}

// A truncated npm lockfile no longer stands the resolve down: with no npm to
// resolve instead, the package.json is unresolved.
func TestUnreadableNpmLockIsUnresolved(t *testing.T) {
	pj := `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`
	good := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`
	for _, lock := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		t.Run(lock, func(t *testing.T) {
			if got := unresolvedFor(t, map[string]string{"package.json": pj, lock: good[:40]}); !slices.Equal(got, []string{"package.json"}) {
				t.Errorf("truncated %s: unresolved = %v, want [package.json]", lock, got)
			}
			if got := unresolvedFor(t, map[string]string{"package.json": pj, lock: good}); len(got) != 0 {
				t.Errorf("valid %s: unresolved = %v, want none", lock, got)
			}
		})
	}
}

// A pyproject whose uv.lock (or poetry.lock) parses is covered by that lock,
// even on a host with no Python resolver at all.
func TestPythonLockCoversPyprojectWithoutResolver(t *testing.T) {
	pp := "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n"
	uvLock := "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	if got := unresolvedFor(t, map[string]string{"pyproject.toml": pp, "uv.lock": uvLock}); len(got) != 0 {
		t.Errorf("with uv.lock: unresolved = %v, want none", got)
	}
	if got := unresolvedFor(t, map[string]string{"pyproject.toml": pp, "uv.lock": "[[package\n"}); !slices.Equal(got, []string{"pyproject.toml"}) {
		t.Errorf("with a broken uv.lock: unresolved = %v, want [pyproject.toml]", got)
	}
	if got := unresolvedFor(t, map[string]string{"pyproject.toml": pp}); !slices.Equal(got, []string{"pyproject.toml"}) {
		t.Errorf("without a lock: unresolved = %v, want [pyproject.toml]", got)
	}
}

// Windows names one directory several ways; a manifest is still reported
// relative to the scan root, never as an absolute path.
func TestRelWithin(t *testing.T) {
	sep := string(filepath.Separator)
	root := sep + filepath.Join("Users", "RunnerAdmin", "Temp", "scan")
	for _, tc := range []struct {
		p    string
		fold bool
		want string
		ok   bool
	}{
		{filepath.Join(root, "a", "Cargo.toml"), false, filepath.Join("a", "Cargo.toml"), true},
		{sep + filepath.Join("users", "runneradmin", "temp", "scan", "Cargo.toml"), true, "Cargo.toml", true},
		{sep + filepath.Join("users", "runneradmin", "temp", "scan", "Cargo.toml"), false, "", false},
		{sep + filepath.Join("Users", "RunnerAdmin", "Temp", "scanner", "x"), true, "", false},
		{sep + filepath.Join("Users", "RunnerAdmin", "Temp", "other"), false, "", false},
	} {
		got, ok := relWithin(root, tc.p, tc.fold)
		if ok != tc.ok || got != tc.want {
			t.Errorf("relWithin(%q, %q, %v) = %q, %v; want %q, %v", root, tc.p, tc.fold, got, ok, tc.want, tc.ok)
		}
	}
}

// A root given through a symlink still yields relative manifest paths.
func TestUnresolvedPathsAreRelativeUnderASymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	t.Setenv("PATH", t.TempDir())
	real := t.TempDir()
	writeTree(t, real, map[string]string{"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n"})
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	ctx := warn.NewContext(context.Background(), false)
	if _, err := Catalog(ctx, link, Options{SkipVersionLookup: true}); err != nil {
		t.Fatal(err)
	}
	if got := warn.Unresolved(ctx); !slices.Equal(got, []string{"Cargo.toml"}) {
		t.Errorf("unresolved = %v, want [Cargo.toml]", got)
	}
}
