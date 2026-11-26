package catalog

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// indexedPaths lists every regular file the source for proj indexes with
// the given ignore patterns, root-relative.
func indexedPaths(t *testing.T, proj string, ignore ...string) []string {
	t.Helper()
	src, err := newDirectorySource(proj, 0, ignore...)
	if err != nil {
		t.Fatalf("newDirectorySource: %v", err)
	}
	defer src.Close()
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("FileResolver: %v", err)
	}
	locs, err := resolver.FilesByGlob("**/*")
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
		got = append(got, strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(l.RealPath), prefix), "/"))
	}
	slices.Sort(got)
	return got
}

// TestIgnorePatternsAreLeftOutOfTheIndex checks the index, not catalogue
// output: the walk is the cost an ignore pattern exists to cut. It also pins
// that a pattern is anchored at the scanned directory, as documented: `wf`
// is the top-level directory only, and `**/` is needed to reach any depth.
func TestIgnorePatternsAreLeftOutOfTheIndex(t *testing.T) {
	proj := t.TempDir()
	for _, rel := range []string{
		"package.json",
		"README.md",
		"wf/a/b/data.txt",
		"wf/package.json",
		"src/wf/package.json",
		"src/fixtures/package.json",
		"fixtures/package.json",
		"docs/guide.md",
	} {
		sinkFixture(t, proj, rel, "{}")
	}
	for _, tc := range []struct {
		ignore []string
		want   []string
	}{
		{nil, []string{"README.md", "docs/guide.md", "fixtures/package.json", "package.json", "src/fixtures/package.json", "src/wf/package.json", "wf/a/b/data.txt", "wf/package.json"}},
		{[]string{"wf"}, []string{"README.md", "docs/guide.md", "fixtures/package.json", "package.json", "src/fixtures/package.json", "src/wf/package.json"}},
		{[]string{"**/fixtures"}, []string{"README.md", "docs/guide.md", "package.json", "src/wf/package.json", "wf/a/b/data.txt", "wf/package.json"}},
		{[]string{"*.md"}, []string{"docs/guide.md", "fixtures/package.json", "package.json", "src/fixtures/package.json", "src/wf/package.json", "wf/a/b/data.txt", "wf/package.json"}},
		{[]string{"**/*.md", "wf/**/*.txt"}, []string{"fixtures/package.json", "package.json", "src/fixtures/package.json", "src/wf/package.json", "wf/package.json"}},
	} {
		if got := indexedPaths(t, proj, tc.ignore...); !slices.Equal(got, tc.want) {
			t.Errorf("ignore %q indexed\n  %q\nwant\n  %q", tc.ignore, got, tc.want)
		}
	}
	// The package sinks stay excluded beside an ignore pattern.
	sinkFixture(t, proj, "node_modules/x/package.json", "{}")
	if got := indexedPaths(t, proj, "wf"); slices.Contains(got, "node_modules/x/package.json") {
		t.Errorf("an ignore pattern let node_modules into the index: %q", got)
	}
}

// TestCatalogIgnoreDropsAnIgnoredProjectAndSaysSo is the end-to-end half: the
// ignored directory's dependencies are gone, the root's are not, and the scan
// says paths were skipped rather than reading as a scan of everything.
func TestCatalogIgnoreDropsAnIgnoredProjectAndSaysSo(t *testing.T) {
	proj := t.TempDir()
	writeFixture(t, proj, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`)
	sinkFixture(t, proj, "wf/demo/package.json", `{"name":"demo","version":"1.0.0","dependencies":{"is-odd":"3.0.1"}}`)

	ctx := warn.NewContext(context.Background(), false)
	pkgs, err := Catalog(ctx, proj, Options{SkipVersionLookup: true, NoExec: true, Ignore: []string{"wf"}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	if !slices.Contains(names, "left-pad") || slices.Contains(names, "is-odd") {
		t.Errorf("catalogued %v, want left-pad and not the ignored is-odd", names)
	}
	if got := warn.Drain(ctx); !strings.Contains(got, "1 ignore pattern(s)") || !strings.Contains(got, "wf") {
		t.Errorf("warnings = %q, want one line naming the ignore pattern", got)
	}

	ctx = warn.NewContext(context.Background(), false)
	if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true, NoExec: true}); err != nil {
		t.Fatal(err)
	}
	if got := warn.Drain(ctx); strings.Contains(got, "ignore pattern") {
		t.Errorf("a scan with no patterns warned about them: %q", got)
	}
}

// TestIgnoredScanTrustsNoCrateByRegistry: an ignore pattern hides cargo
// configs as a depth limit does, so a replacement under it could not veto a
// crate's registry trust, and the trust is withheld.
func TestIgnoredScanTrustsNoCrateByRegistry(t *testing.T) {
	base := t.TempDir()
	t.Setenv("CARGO_HOME", filepath.Join(base, "home"))
	const index = "https://crates.corp.example/internal/"
	writeTree(t, base, map[string]string{
		"home/.keep":                    "",
		"proj/Cargo.lock":               "version = 4\n\n[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+" + index + "\"\nchecksum = \"aaaa\"\n",
		"proj/tools/.cargo/config.toml": "[source.internal]\nregistry = \"sparse+" + index + "\"\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"sparse+https://mirror.example/\"\n",
	})
	ctx := warn.NewContext(context.Background(), false)
	pkgs, err := Catalog(ctx, filepath.Join(base, "proj"), Options{SkipVersionLookup: true, NoExec: true, Ignore: []string{"tools"}, Trust: testPolicy(t, []string{index}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(pkgs, func(p Package) bool { return p.Name == "acme-sparse" })
	if i < 0 {
		t.Fatalf("acme-sparse not catalogued: %v", pkgs)
	}
	if pkgs[i].Trusted {
		t.Error("acme-sparse is trusted, though the config that replaces its registry was ignored")
	}
	if got := warn.Drain(ctx); !strings.Contains(got, "registry trust was not applied") {
		t.Errorf("warnings = %q, want one saying trust was not applied", got)
	}
}

// TestIgnoreTurnsTheCargoVendorFilterOff: the vendor filter hides a crate's
// Cargo files only once it has seen every manifest and config that could
// build it by path. An ignore pattern can hide one (here an alias in an
// ignored tools/.cargo/config.toml that builds vendor/aliased), so with any
// pattern applied the filter stays off and the crate's own files are read,
// which errs toward checking more.
func TestIgnoreTurnsTheCargoVendorFilterOff(t *testing.T) {
	proj := t.TempDir()
	vendoringRoot(t, proj, "", "", lockEntry("aliased", "0.1.0", "alal"))
	vendoredCrate(t, proj, "vendor/aliased", "0.1.0", "alal", "[dev-dependencies]\ntrybuild = \"=1.0.108\"\n")
	sinkFixture(t, proj, "tools/.cargo/config.toml", "[alias]\nbuild-aliased = \"build --manifest-path ../vendor/aliased/Cargo.toml\"\n")

	names := func(ignore ...string) map[string]bool {
		t.Helper()
		pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true, Ignore: ignore})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, p := range pkgs {
			got[p.Name] = true
		}
		return got
	}
	if !names()["trybuild"] {
		t.Fatal("with the alias visible the crate is built by path, so its dev-dependency must be read")
	}
	if !names("tools")["trybuild"] {
		t.Error("ignoring the config that builds the crate let the vendor filter hide it")
	}
}

// TestIgnoredCargoLockDoesNotHideAGitPatch: a [patch] git target the root's
// Cargo.lock records is left to the lock, which syft reads. An ignored lock is
// never read, so if it still recorded the target the fork would go out from
// neither file; the manifest's target goes out instead, as for a lock the
// lockfile caps hide.
func TestIgnoredCargoLockDoesNotHideAGitPatch(t *testing.T) {
	t.Setenv("CARGO_HOME", t.TempDir())
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"Cargo.toml": lockless7,
		"Cargo.lock": appLock(gitSerde("#" + patchRev)),
	})
	components := func(ignore ...string) []string {
		t.Helper()
		got, err := Catalog(context.Background(), dir, Options{NoExec: true, Ignore: ignore})
		if err != nil {
			t.Fatal(err)
		}
		return cargoComponents(t, got, dir)
	}
	if got := components(); !slices.Contains(got, "serde@1.0.100?vcs_url=git+https://github.com/evil/serde@"+patchRev+" Cargo.lock") {
		t.Fatalf("with the lock read, want the fork from the lock: %q", got)
	}
	if got := components("Cargo.lock"); !slices.Contains(got, "serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml") {
		t.Errorf("with the lock ignored, the fork went out from neither file: %q", got)
	}
}
