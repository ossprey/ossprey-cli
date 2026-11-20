package catalog

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"
)

// indexedManifests lists the package.json files the source for proj indexes
// at maxDepth, root-relative.
func indexedManifests(t *testing.T, proj string, maxDepth int) []string {
	t.Helper()
	src, err := newDirectorySource(proj, maxDepth)
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
	root, err := filepath.EvalSymlinks(proj)
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.ToSlash(root) + "/"
	var got []string
	for _, l := range locs {
		p := strings.TrimPrefix(filepath.ToSlash(l.RealPath), prefix)
		got = append(got, strings.TrimPrefix(p, "/"))
	}
	slices.Sort(got)
	return got
}

// TestDirectorySourceStopsAtMaxDepth checks the index, not catalogue output:
// the walk is the cost a depth limit exists to cut, so a file below the limit
// must never be indexed at all.
func TestDirectorySourceStopsAtMaxDepth(t *testing.T) {
	proj := t.TempDir()
	for _, rel := range []string{
		"package.json",
		"a/package.json",
		"a/b/package.json",
		".hidden/package.json",
	} {
		sinkFixture(t, proj, rel, `{"name":"x","version":"1.0.0"}`)
	}
	for _, tc := range []struct {
		depth int
		want  []string
	}{
		{0, []string{".hidden/package.json", "a/b/package.json", "a/package.json", "package.json"}},
		{1, []string{"package.json"}},
		{2, []string{".hidden/package.json", "a/package.json", "package.json"}},
		{3, []string{".hidden/package.json", "a/b/package.json", "a/package.json", "package.json"}},
	} {
		if got := indexedManifests(t, proj, tc.depth); !slices.Equal(got, tc.want) {
			t.Errorf("depth %d indexed %v, want %v", tc.depth, got, tc.want)
		}
	}
}

func TestDepthExclude(t *testing.T) {
	for d, want := range map[int]string{-1: "", 0: "", 1: "./*/*", 2: "./*/*/*"} {
		if got := depthExclude(d); got != want {
			t.Errorf("depthExclude(%d) = %q, want %q", d, got, want)
		}
	}
}

// TestCatalogMaxDepthOneReadsOnlyTheRoot is the end-to-end half: a nested
// project's dependencies are left out, the root's own lockfile is still read.
func TestCatalogMaxDepthOneReadsOnlyTheRoot(t *testing.T) {
	proj := t.TempDir()
	writeFixture(t, proj, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`)
	writeFixture(t, proj, "package-lock.json", `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
  }
}`)
	sinkFixture(t, proj, "examples/demo/package.json", `{"name":"demo","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}`)

	names := func(depth int) []string {
		pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true, MaxDepth: depth})
		if err != nil {
			t.Fatalf("Catalog: %v", err)
		}
		var out []string
		for _, p := range pkgs {
			out = append(out, p.Name)
		}
		return out
	}
	if got := names(1); !slices.Contains(got, "left-pad") || slices.Contains(got, "is-odd") {
		t.Errorf("depth 1 catalogued %v, want left-pad and not the nested is-odd", got)
	}
	if got := names(0); !slices.Contains(got, "left-pad") || !slices.Contains(got, "is-odd") {
		t.Errorf("depth 0 catalogued %v, want both", got)
	}
}
