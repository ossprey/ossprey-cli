package catalog

import (
	"context"
	"os"
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

// TestDepthOneCataloguesWhatTheWholeTreeDoes is the guard against the depth
// limit dropping detection: for every fixture project a forwarder would scan
// at depth 1, that scan must catalogue exactly what the whole-tree scan does.
// A fixture where the two differ has dependencies declared below its root, so
// it must be one the forwarder scans in full (a workspace root, or a manifest
// naming a local path); otherwise the limit has cost a real component. A new
// ecosystem's fixture is held to the same rule by being in the directory.
func TestDepthOneCataloguesWhatTheWholeTreeDoes(t *testing.T) {
	root := filepath.Join("..", "..", "test", "test_packages")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no fixtures found")
	}
	components := func(t *testing.T, proj string, depth int) []string {
		t.Helper()
		pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true, MaxDepth: depth})
		if err != nil {
			t.Fatalf("Catalog at depth %d: %v", depth, err)
		}
		var out []string
		for _, p := range pkgs {
			out = append(out, p.Type+"/"+p.Name+"@"+p.Version)
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			proj := filepath.Join(root, e.Name())
			whole, shallow := components(t, proj, 0), components(t, proj, 1)
			if len(whole) == 0 {
				t.Fatal("the whole-tree scan catalogued nothing, so the comparison proves nothing")
			}
			if slices.Equal(whole, shallow) {
				return
			}
			if IsWorkspaceRoot(proj) || HasLocalDeps(proj) {
				return // the forwarder scans this one in full
			}
			var missing []string
			for _, c := range whole {
				if !slices.Contains(shallow, c) {
					missing = append(missing, c)
				}
			}
			t.Errorf("depth 1 catalogued %d components, the whole tree %d; a forwarder would scan at depth 1 and miss %v",
				len(shallow), len(whole), missing)
		})
	}
}

// TestLocalDependencyNeedsTheWholeTree is why HasLocalDeps exists: the
// dependencies of a `file:` dependency are declared in its own manifest,
// which depth 1 never reads, so the forwarder must not pick depth 1 here.
func TestLocalDependencyNeedsTheWholeTree(t *testing.T) {
	proj := t.TempDir()
	writeFixture(t, proj, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"local":"file:./local"}}`)
	sinkFixture(t, proj, "local/package.json", `{"name":"local","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}`)

	has := func(depth int) bool {
		pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true, MaxDepth: depth})
		if err != nil {
			t.Fatalf("Catalog: %v", err)
		}
		return slices.ContainsFunc(pkgs, func(p Package) bool { return p.Name == "is-odd" })
	}
	if has(1) {
		t.Fatal("depth 1 read the local dependency's manifest; this test no longer shows the gap")
	}
	if !has(0) {
		t.Error("the whole-tree scan did not catalogue the local dependency's is-odd")
	}
	if !HasLocalDeps(proj) {
		t.Error("HasLocalDeps = false, so a forwarder would scan at depth 1 and miss is-odd")
	}
}
