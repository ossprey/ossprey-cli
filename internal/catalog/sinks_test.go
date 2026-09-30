package catalog

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"
)

// TestDirectorySourceSkipsPackageSinks checks the index itself, because that
// is where the time went: catalogers already dropped node_modules packages,
// but syft still opened every file under it first. A sink at any depth must
// be absent from the index while the project's own manifests stay in it.
func TestDirectorySourceSkipsPackageSinks(t *testing.T) {
	proj := t.TempDir()
	for _, rel := range []string{
		"package.json",
		"packages/web/package.json",
		"node_modules/left-pad/package.json",
		"node_modules/.pnpm/a@1.0.0/node_modules/a/package.json",
		"packages/web/node_modules/b/package.json",
		".venv/lib/python3.12/site-packages/c/package.json",
		"target/debug/package.json",
		".git/package.json",
	} {
		sinkFixture(t, proj, rel, `{"name":"x","version":"1.0.0"}`)
	}

	src, err := newDirectorySource(proj)
	if err != nil {
		t.Fatalf("newDirectorySource: %v", err)
	}
	defer src.Close()
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("FileResolver: %v", err)
	}
	locs, err := resolver.FilesByGlob("**/package.json")
	if err != nil {
		t.Fatalf("FilesByGlob: %v", err)
	}

	var got []string
	for _, l := range locs {
		got = append(got, strings.TrimPrefix(filepath.ToSlash(l.RealPath), "/"))
	}
	want := map[string]bool{"package.json": true, "packages/web/package.json": true}
	if len(got) != len(want) {
		t.Fatalf("indexed %v, want only %v", got, want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("indexed %s, which sits in a package sink", g)
		}
	}
}

// TestPackageSinkExcludesFreshSlice guards the copy: syft rewrites the
// exclusion slice in place, so a shared one would carry the first scan's root
// into the next.
func TestPackageSinkExcludesFreshSlice(t *testing.T) {
	a := packageSinkExcludes()
	a[0] = "/some/root/" + a[0]
	if b := packageSinkExcludes(); b[0] != "**/"+packageSinks[0] {
		t.Fatalf("packageSinkExcludes shares its slice: got %q", b[0])
	}
}

// TestCatalogStillReadsLockfileBesideSinks is the coverage half: excluding
// node_modules must not cost the lockfile that names what is in it.
func TestCatalogStillReadsLockfileBesideSinks(t *testing.T) {
	proj := t.TempDir()
	writeFixture(t, proj, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`)
	writeFixture(t, proj, "package-lock.json", `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
  }
}`)
	sinkFixture(t, proj, "node_modules/left-pad/package.json", `{"name":"left-pad","version":"1.3.0"}`)

	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	for _, p := range pkgs {
		if p.Name == "left-pad" && p.Version == "1.3.0" {
			return
		}
	}
	t.Fatalf("left-pad@1.3.0 from package-lock.json missing: %+v", pkgs)
}

func sinkFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
