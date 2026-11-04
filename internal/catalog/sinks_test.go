package catalog

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
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
		".cache/gatsby/package.json",
		".next/dev/node_modules/d/package.json",
		".nuxt/package.json",
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

	// RealPath is root-relative ("/package.json") on Unix but absolute under
	// the resolved root on Windows ("C:/.../package.json").
	root, err := filepath.EvalSymlinks(proj)
	if err != nil {
		t.Fatal(err)
	}
	rootPrefix := filepath.ToSlash(root) + "/"
	var got []string
	for _, l := range locs {
		p := strings.TrimPrefix(filepath.ToSlash(l.RealPath), rootPrefix)
		got = append(got, strings.TrimPrefix(p, "/"))
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
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "dependencies": {"is-odd": "3.0.1"}},
    "node_modules/is-odd": {"version": "3.0.1", "resolved": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"}
  }
}`)
	sinkFixture(t, proj, "node_modules/left-pad/package.json", `{"name":"left-pad","version":"1.3.0"}`)

	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	for _, p := range pkgs {
		// Transitive, so only the lockfile can have supplied it; the
		// package.json fallback would name left-pad on its own.
		if p.Name == "is-odd" && p.Version == "3.0.1" {
			return
		}
	}
	t.Fatalf("is-odd@3.0.1 from package-lock.json missing: %+v", pkgs)
}

// vendorConfig is the cargo config `cargo vendor` tells a project to add for vendor directory dir.
func vendorConfig(dir string) string {
	return fmt.Sprintf("[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = %q\n", dir)
}

// lockEntry is a Cargo.lock package from crates.io with checksum sum, or a path crate when sum is "".
func lockEntry(name, version, sum string) string {
	if sum == "" {
		return fmt.Sprintf("\n[[package]]\nname = %q\nversion = %q\n", name, version)
	}
	return fmt.Sprintf("\n[[package]]\nname = %q\nversion = %q\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = %q\n", name, version, sum)
}

// vendoredCrate writes a crate's marker recording sum and its manifest declaring deps.
func vendoredCrate(t *testing.T, proj, dir, version, sum, deps string) {
	t.Helper()
	sinkFixture(t, proj, dir+"/.cargo-checksum.json", fmt.Sprintf(`{"files":{},"package":%q}`, sum))
	sinkFixture(t, proj, dir+"/Cargo.toml", fmt.Sprintf("[package]\nname = %q\nversion = %q\n\n%s", path.Base(dir), version, deps))
}

// cargoVendorFixture vendors into vendor/ and, in a second project, third_party/rust.
func cargoVendorFixture(t *testing.T) string {
	t.Helper()
	proj := t.TempDir()
	for rel, content := range map[string]string{
		"Cargo.toml": `[package]
name = "my-app"
version = "0.1.0"

[workspace]
members = ["crates/app"]
exclude = ["other-proj"]

[dependencies]
anyhow = "=1.0.100"
patched = { path = "vendor/patched" }
`,
		"Cargo.lock":         "version = 4\n" + lockEntry("my-app", "0.1.0", "") + lockEntry("anyhow", "1.0.100", "aaaa"),
		".cargo/config.toml": vendorConfig("vendor"),
		"crates/app/Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[dependencies]
itoa = "=1.0.15"
`,
		"vendor/patched/Cargo.toml": `[package]
name = "patched"
version = "0.1.0"

[dependencies]
memchr = "=2.7.4"
`,
		"vendor/anyhow/Cargo.lock": "version = 4\n" + lockEntry("anyhow", "1.0.100", "") + lockEntry("futures", "0.3.31", "bbbb"),
		// Only the crate's own Cargo files are hidden.
		"vendor/anyhow/package-lock.json": `{
  "name": "anyhow-site", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "anyhow-site", "version": "1.0.0", "dependencies": {"in-vendor": "1.0.0"}},
    "node_modules/in-vendor": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/in-vendor/-/in-vendor-1.0.0.tgz"}
  }
}`,
		// Another lockfile recording a different checksum proves nothing either way.
		"tools/other/Cargo.lock": "version = 4\n" + lockEntry("anyhow", "1.0.100", "zzzz"),
		"other-proj/Cargo.toml": `[package]
name = "other-proj"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
`,
		"other-proj/Cargo.lock":         "version = 4\n" + lockEntry("other-proj", "0.1.0", "") + lockEntry("serde", "1.0.228", "cccc"),
		"other-proj/.cargo/config.toml": vendorConfig("third_party/rust"),
	} {
		sinkFixture(t, proj, rel, content)
	}
	vendoredCrate(t, proj, "vendor/anyhow", "1.0.100", "aaaa", "[dev-dependencies]\ntrybuild = \"1.0.108\"\n")
	vendoredCrate(t, proj, "other-proj/third_party/rust/serde", "1.0.228", "cccc", "[dev-dependencies]\nserde_derive = \"=1.0.228\"\n")
	return proj
}

// TestCatalogSkipsCargoVendorTrees: a vendored crate's own lockfile and dev-dependencies are not the project's.
func TestCatalogSkipsCargoVendorTrees(t *testing.T) {
	got := catalogNames(t, cargoVendorFixture(t))
	// Root lock, workspace member, unmarked path dependency, second project's lock, npm lockfile in a vendored crate.
	for name, version := range map[string]string{"anyhow": "1.0.100", "itoa": "1.0.15", "memchr": "2.7.4", "serde": "1.0.228", "in-vendor": "1.0.0"} {
		if v, ok := got[name]; !ok || v != version {
			t.Errorf("%s@%s missing, got %v", name, version, got)
		}
	}
	for _, name := range []string{"futures", "trybuild", "serde_derive"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s came from a vendored crate: %v", name, got)
		}
	}
}

// vendoringRoot is a project vendoring into vendor/ whose lock pins each crate in locked.
func vendoringRoot(t *testing.T, proj, manifestExtra, configExtra string, locked ...string) {
	t.Helper()
	sinkFixture(t, proj, "Cargo.toml", "[package]\nname = \"my-app\"\nversion = \"0.1.0\"\n"+manifestExtra)
	sinkFixture(t, proj, "Cargo.lock", "version = 4\n"+lockEntry("my-app", "0.1.0", "")+strings.Join(locked, ""))
	sinkFixture(t, proj, ".cargo/config.toml", configExtra+vendorConfig("vendor"))
}

// TestCatalogDoesNotLetACargoMarkerHideOtherFiles: the marker is a repository file, so on its own it hides nothing.
func TestCatalogDoesNotLetACargoMarkerHideOtherFiles(t *testing.T) {
	proj := t.TempDir()
	vendoringRoot(t, proj, "", "",
		lockEntry("serde", "1.0.228", "cccc"), lockEntry("forged", "1.0.0", "ffff"),
		lockEntry("ws", "0.1.0", "wwww"),
		lockEntry("edited", "0.1.0", "eded"), lockEntry("optional", "0.1.0", "opop"),
		lockEntry("featured", "0.1.0", "fefe"), lockEntry("bumped", "0.1.0", "bubu"), lockEntry("bumpdep", "1.0.0", "b1b1"),
		lockEntry("ranged", "0.1.0", "rara"), lockEntry("rangedep", "1.4.0", "r1r1"))
	for rel, content := range map[string]string{
		// Beside an npm lockfile, the marker must not hide it.
		"packages/web/.cargo-checksum.json": `{"files":{},"package":"dddd"}`,
		"packages/web/package.json":         `{"name":"web","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`,
		"packages/web/package-lock.json": `{
  "name": "web", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "web", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "dependencies": {"is-odd": "3.0.1"}},
    "node_modules/is-odd": {"version": "3.0.1", "resolved": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"}
  }
}`,
		// A standalone project, and a lock elsewhere that names it with the marker's checksum.
		"backend/Cargo.toml":           "[package]\nname = \"backend\"\nversion = \"0.1.0\"\n\n[dependencies]\nevil = \"=6.6.6\"\n",
		"backend/Cargo.lock":           "version = 4\n" + lockEntry("backend", "0.1.0", "") + lockEntry("evil", "6.6.6", "6666"),
		"backend/.cargo-checksum.json": `{"files":{},"package":"xxxx"}`,
		"docs/examples/Cargo.toml":     "[package]\nname = \"example\"\nversion = \"0.1.0\"\n",
		"docs/examples/Cargo.lock":     "version = 4\n" + lockEntry("backend", "0.1.0", "xxxx") + lockEntry("decoyed", "0.1.0", "yyyy"),
		// A crate cargo replaces crates.io with a registry for, when run in its own directory.
		// A nested project whose two config files leave cargo's choice unclear.
		// A lockfile with no manifest beside it is no project.
		"vendor/Cargo.lock": "version = 4\n" + lockEntry("lonely", "0.1.0", "llll"),
		// A nested project whose vendor source is itself replaced, which cargo follows.
		// A config cargo reads through a symlink in the crate's own .cargo directory.
		// A nested project that does not vendor, under a config only its vendor directory reads.
		"nested-proj/Cargo.toml":                "[package]\nname = \"nested-proj\"\nversion = \"0.1.0\"\n",
		"nested-proj/Cargo.lock":                "version = 4\n" + lockEntry("nested-proj", "0.1.0", "") + lockEntry("unvendored", "0.1.0", "uuuu"),
		"nested-proj/vendor/.cargo/config.toml": vendorConfig("."),
	} {
		sinkFixture(t, proj, rel, content)
	}
	// Each is under vendor/ with a marker, but fails one part of the proof.
	vendoredCrate(t, proj, "vendor/forged", "1.0.0", "0000", "[dev-dependencies]\nforged-dep = \"=1.0.0\"\n")
	vendoredCrate(t, proj, "vendor/unlocked", "0.1.0", "eeee", "[dev-dependencies]\nunlocked-dep = \"=1.0.0\"\n")
	vendoredCrate(t, proj, "vendor/decoyed", "0.1.0", "yyyy", "[dev-dependencies]\ndecoy-dep = \"=1.0.0\"\n")
	vendoredCrate(t, proj, "vendor/ws", "0.1.0", "wwww", "[workspace]\n\n[dev-dependencies]\nws-dep = \"=1.0.0\"\n")
	vendoredCrate(t, proj, "vendor/lonely", "0.1.0", "llll", "[dev-dependencies]\nlonely-dep = \"=1.0.0\"\n")
	vendoredCrate(t, proj, "nested-proj/vendor/unvendored", "0.1.0", "uuuu", "[dev-dependencies]\nunvendored-dep = \"=1.0.0\"\n")
	// Proven but for a dependency the project's lock does not name, which cargo would resolve.
	vendoredCrate(t, proj, "vendor/edited", "0.1.0", "eded", "[dependencies]\nedit-dep = \"=1.0.0\"\n")
	// Its default features turn on an optional dependency the lock does not hold.
	vendoredCrate(t, proj, "vendor/featured", "0.1.0", "fefe", "[dependencies]\nevil-opt = { version = \"=1.0.0\", optional = true }\n\n[features]\ndefault = [\"fast\"]\nfast = [\"dep:evil-opt\"]\n\n[dev-dependencies]\nfeatured_dev = \"=1.0.0\"\n")
	// A locked name at a release the manifest no longer asks for, and one it still does.
	vendoredCrate(t, proj, "vendor/bumped", "0.1.0", "bubu", "[dependencies]\nbumpdep = \"=2.0.0\"\n\n[dev-dependencies]\nbumped_dev = \"=1.0.0\"\n")
	vendoredCrate(t, proj, "vendor/ranged", "0.1.0", "rara", "[dependencies]\nrangedep = \"1.2\"\n\n[dev-dependencies]\nranged_dev = \"=1.0.0\"\n")
	// An optional dependency may be unused, so it does not block the proof.
	vendoredCrate(t, proj, "vendor/optional", "0.1.0", "opop", "[dependencies]\nopt-dep = { version = \"=1.0.0\", optional = true }\n\n[dev-dependencies]\noptional_dev = \"=1.0.0\"\n")
	// Proven, so its own files are hidden but a manifest below it is not.
	vendoredCrate(t, proj, "vendor/serde", "1.0.228", "cccc", "[dev-dependencies]\nserde_derive = \"=1.0.228\"\n")
	// The hidden lock reached through a symlink is another file, so it stays visible.
	sinkFixture(t, proj, "vendor/serde/Cargo.lock", `{
  "name": "site", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "site", "version": "1.0.0", "dependencies": {"aliased-dep": "1.0.0"}},
    "node_modules/aliased-dep": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/aliased-dep/-/aliased-dep-1.0.0.tgz"}
  }
}`)
	// Symlinks need privileges on Windows, as in the other symlink tests.
	aliased := runtime.GOOS != "windows" && os.Symlink(filepath.Join(proj, "vendor/serde/Cargo.lock"), filepath.Join(proj, "package-lock.json")) == nil
	sinkFixture(t, proj, "vendor/serde/sub/Cargo.toml", "[package]\nname = \"sub\"\nversion = \"0.1.0\"\n\n[dependencies]\nnested-dep = \"=1.0.0\"\n")

	got := catalogNames(t, proj)
	for name, version := range map[string]string{
		"is-odd": "3.0.1", "evil": "6.6.6", "forged-dep": "1.0.0", "unlocked-dep": "1.0.0", "decoy-dep": "1.0.0",
		"ws-dep": "1.0.0", "unvendored-dep": "1.0.0", "lonely-dep": "1.0.0", "nested-dep": "1.0.0",
		"edit-dep": "1.0.0", "featured_dev": "1.0.0", "bumped_dev": "1.0.0",
	} {
		if v, ok := got[name]; !ok || v != version {
			t.Errorf("%s@%s hidden by a .cargo-checksum.json, got %v", name, version, got)
		}
	}
	if aliased && got["aliased-dep"] != "1.0.0" {
		t.Errorf("aliased-dep@1.0.0 hidden behind a symlink to a hidden file, got %v", got)
	}
	for _, name := range []string{"serde_derive", "optional_dev", "ranged_dev"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s came from a proven vendored crate: %v", name, got)
		}
	}
}

// TestCatalogReadsAProjectCrateThatLooksVendored: a crate the project builds by path is never hidden.
func TestCatalogReadsAProjectCrateThatLooksVendored(t *testing.T) {
	// A checkout path with glob characters must not change how member globs expand.
	proj := filepath.Join(t.TempDir(), "checkout[x]")
	// Each crate: its marker's checksum, its version, and a dev-dependency only it declares.
	crates := map[string][3]string{
		"itoa":      {"gggg", "1.0.15", "path-dep"},
		"inner":     {"iiii", "0.1.0", "transitive-dep"},
		"wsmember":  {"hhhh", "0.1.0", "member-dep"},
		"mlink":     {"mmmm", "0.1.0", "member-link-dep"},
		"memchr":    {"pppp", "2.7.4", "patch-dep"},
		"semver":    {"ssss", "1.0.26", "override-dep"},
		"aliased":   {"alal", "0.1.0", "alias-dep"},
		"ryu":       {"rrrr", "1.0.20", "case-dep"},
		"smallvec":  {"vvvv", "1.13.2", "sourceless-dep"},
		"hashbrown": {"kkkk", "0.15.0", "linked-dep"},
		"bk":        {"bkbk", "0.1.0", "bracket-dep"},
		"smlink":    {"smsm", "0.1.0", "symlinked-manifest-dep"},
		"esc":       {"eses", "0.1.0", "escape-dep"},
		"bsl":       {"bsbs", "0.1.0", "backslash-dep"},
		"café":      {"cfee", "0.1.0", "unicode-dep"},
	}
	var locked []string
	for name, c := range crates {
		deps := fmt.Sprintf("[dev-dependencies]\n%s = \"=1.0.0\"\n", c[2])
		if name == "itoa" {
			deps += "\n[dependencies]\ninner = { path = \"../inner\" }\n"
		}
		dir := "vendor/" + name
		if name == "café" {
			// Decomposed on disk, composed in the reference.
			dir = "vendor/café"
		}
		vendoredCrate(t, proj, dir, c[1], c[0], deps)
		locked = append(locked, lockEntry(path.Base(dir), c[1], c[0]))
	}
	vendoredCrate(t, proj, "vendor/serde", "1.0.228", "cccc", "[dev-dependencies]\nserde_derive = \"=1.0.228\"\n")
	// smallvec is also locked as a path crate, built from outside the scan.
	locked = append(locked, lockEntry("serde", "1.0.228", "cccc"), lockEntry("smallvec", "1.13.2", ""))
	vendoringRoot(t, proj, `
[workspace]
members = ["vendor/wsmem*", "crates/*"]

[dependencies]
itoa = { path = "vendor/itoa" }
ryu = { path = "Vendor/Ryu" }
hashbrown = { path = "link/hashbrown" }
bk = { path = "we[ird]/bk" }
esc = { path = "../another-checkout/vendor/esc" }
bsl = { path = 'vendor\bsl' }
cafe = { path = "vendor/caf`+"é"+`" }

[patch.crates-io]
memchr = { path = "vendor/memchr" }
`, "paths = [\"vendor/semver\"]\n\n", locked...)
	sinkFixture(t, proj, "tools/.cargo/config.toml", "[alias]\nvendored-test = \"test --manifest-path ../vendor/aliased/Cargo.toml\"\n")
	sinkFixture(t, proj, "templates/deep/app.toml", "[package]\nname = \"app2\"\nversion = \"0.1.0\"\n\n[dependencies]\nsmlink = { path = \"../vendor/smlink\" }\n")
	want := []string{"path-dep", "transitive-dep", "member-dep", "patch-dep", "override-dep", "alias-dep", "case-dep",
		"sourceless-dep", "escape-dep", "backslash-dep", "unicode-dep"}
	if err := os.MkdirAll(filepath.Join(proj, "crates"), 0o755); err != nil {
		t.Fatal(err)
	}
	links := map[string][2]string{
		"linked-dep":             {"vendor", "link"},
		"bracket-dep":            {"vendor", "we[ird]"},
		"member-link-dep":        {"vendor/mlink", "crates/linked"},
		"symlinked-manifest-dep": {"templates/deep/app.toml", "app/Cargo.toml"},
	}
	for dep, l := range links {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(proj, l[1])), 0o755)
		if runtime.GOOS != "windows" && os.Symlink(filepath.Join(proj, l[0]), filepath.Join(proj, l[1])) == nil {
			want = append(want, dep)
		}
	}

	got := catalogNames(t, proj)
	for _, name := range want {
		if v, ok := got[name]; !ok || v != "1.0.0" {
			t.Errorf("%s@1.0.0 hidden from a crate the project builds, got %v", name, got)
		}
	}
	if _, ok := got["serde_derive"]; ok {
		t.Errorf("serde_derive came from a proven vendored crate, so the filter never ran: %v", got)
	}
}

// TestCatalogReadsACrateAProjectAboveTheScanBuilds: cargo run in a scanned subdirectory reads the configs above it.
func TestCatalogReadsACrateAProjectAboveTheScanBuilds(t *testing.T) {
	repo := t.TempDir()
	proj := filepath.Join(repo, "svc")
	sinkFixture(t, repo, ".cargo/config.toml", "[patch.crates-io]\nx = { path = \"svc/vendor/x\" }\n")
	vendoredCrate(t, proj, "vendor/x", "0.1.0", "xxxx", "[dev-dependencies]\nabove-dep = \"=1.0.0\"\n")
	vendoredCrate(t, proj, "vendor/serde", "1.0.228", "cccc", "[dev-dependencies]\nserde_derive = \"=1.0.228\"\n")
	vendoringRoot(t, proj, "", "", lockEntry("x", "0.1.0", "xxxx"), lockEntry("serde", "1.0.228", "cccc"))

	got := catalogNames(t, proj)
	if got["above-dep"] != "1.0.0" {
		t.Errorf("above-dep@1.0.0 hidden from a crate a config above the scan builds, got %v", got)
	}
	if _, ok := got["serde_derive"]; ok {
		t.Errorf("serde_derive came from a proven vendored crate, so the filter never ran: %v", got)
	}
}

// TestCatalogHidesNothingWhenAPathCannotBePlaced: a reference or config the filter cannot place could name any crate.
func TestCatalogHidesNothingWhenAPathCannotBePlaced(t *testing.T) {
	mirror := "[source.crates-io]\nreplace-with = \"mirror\"\n\n[registries.mirror]\nindex = \"sparse+https://index.crates.io/\"\n"
	for name, c := range map[string]struct {
		manifest, config string
		files, links     map[string]string
	}{
		"class glob":           {manifest: "[workspace]\nmembers = [\"crates/[!_]x\"]\n"},
		"doublestar glob":      {manifest: "[workspace]\nmembers = [\"crates/**\"]\n"},
		"glob above the root":  {manifest: "[workspace]\nmembers = [\"../*\"]\n"},
		"path base":            {manifest: "[dependencies]\nx = { path = \"x\", base = \"b\" }\n"},
		"config include":       {config: "include = \"extra.toml\"\n"},
		"vendor alias":         {config: "[alias]\nvend = \"vendor\"\n\n"},
		"alias passing config": {config: "[alias]\nt = [\"test\", \"--config\", \"source.crates-io.replace-with='mirror'\"]\n\n"},
		"unparseable manifest": {files: map[string]string{"other/Cargo.toml": "[package\n"}},
		"oversized manifest":   {files: map[string]string{"other/Cargo.toml": "# " + strings.Repeat("x", maxManifestBytes) + "\n"}},
		// cargo run in another directory, through an alias or --manifest-path, reads that directory's config.
		"a level repointing crates.io": {files: map[string]string{"tools/.cargo/config.toml": mirror}},
		"a level with two configs":     {files: map[string]string{"tools/.cargo/config": "", "tools/.cargo/config.toml": ""}},
		"a config in another case":     {files: map[string]string{"tools/.cargo/Config.toml": ""}},
		// cargo follows a replace-with on the vendor source itself.
		"a chained replacement": {files: map[string]string{"vendor/serde/.cargo/config.toml": "[source.vendored-sources]\nreplace-with = \"mirror\"\n\n[registries.mirror]\nindex = \"sparse+https://index.crates.io/\"\n"}},
		"a symlinked repointing config": {
			files: map[string]string{"cfgs/up.toml": mirror},
			links: map[string]string{"vendor/serde/.cargo/config.toml": "cfgs/up.toml"},
		},
		// A file reached through a symlink out of the root has no place inside it.
		"a symlink out of the root": {links: map[string]string{"vendor/ext/Cargo.toml": "../outside/Cargo.toml"}},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			proj := filepath.Join(base, "proj")
			vendoredCrate(t, proj, "vendor/serde", "1.0.228", "cccc", "[dev-dependencies]\nserde_derive = \"=1.0.228\"\n")
			vendoringRoot(t, proj, c.manifest, c.config, lockEntry("serde", "1.0.228", "cccc"))
			for rel, content := range c.files {
				sinkFixture(t, proj, rel, content)
			}
			sinkFixture(t, base, "outside/Cargo.toml", "[package]\nname = \"ext\"\nversion = \"0.1.0\"\n")
			for link, target := range c.links {
				// Symlinks need privileges on Windows, as in the other symlink tests.
				if runtime.GOOS == "windows" {
					t.Skip("symlinks need privileges on Windows")
				}
				_ = os.MkdirAll(filepath.Dir(filepath.Join(proj, link)), 0o755)
				if err := os.Symlink(filepath.Join(proj, target), filepath.Join(proj, link)); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			if got := catalogNames(t, proj); got["serde_derive"] != "1.0.228" {
				t.Errorf("serde_derive@1.0.228 hidden although the filter could not place every path, got %v", got)
			}
		})
	}
}

// TestCatalogReadsAVendoredCrateScannedDirectly: scanning a vendored crate asks for that crate.
func TestCatalogReadsAVendoredCrateScannedDirectly(t *testing.T) {
	proj := cargoVendorFixture(t)

	pkgs, err := Catalog(context.Background(), filepath.Join(proj, "vendor", "anyhow"), Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	for _, p := range pkgs {
		if p.Name == "futures" && p.Version == "0.3.31" {
			return
		}
	}
	t.Fatalf("futures@0.3.31 from the scanned crate's Cargo.lock missing: %+v", pkgs)
}

func catalogNames(t *testing.T, proj string) map[string]string {
	t.Helper()
	// The filter reads CARGO_HOME's config, so keep the machine's out of the result.
	t.Setenv("CARGO_HOME", t.TempDir())
	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	return got
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

// TestParseCargoLockRefusesDeepNesting: brackets and dots in strings and comments neither count toward nor hide nesting.
func TestParseCargoLockRefusesDeepNesting(t *testing.T) {
	lock := "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n"
	n := maxProofNesting + 1
	open := strings.Repeat("[", n)
	deep := open + strings.Repeat("]", n)
	dotted, inline := "", ""
	for i := range n {
		dotted += fmt.Sprintf("k%d.workspace = true\n", i)
		inline += fmt.Sprintf("k%d.b = 1, ", i)
	}
	dotted += "x = {" + inline + "c = 1}\nfloats = [" + strings.Repeat("1.5, ", n) + "]\n"
	for _, tc := range []struct {
		name, extra string
		deep        bool
	}{
		{"brackets in strings and comments", "# " + open + "\n" + `x = ['` + open + `', "\"` + open + `", '''` + open + `'''', """` + open + `\""""]` + "\n", false},
		{"nesting past the bound", "x = " + deep + "\n", true},
		{"closers in strings between levels", "x = " + strings.Repeat(`["]]",`, n) + strings.Repeat("]", n) + "\n", true},
		{"a multi-line string ending in extra quotes", `x = ["""a"""", ` + deep + "]\n", true},
		{"six closing quotes after an escaped backslash", `x = ["""a\\"""""", ` + deep + "]\n", true},
		{"dots in strings and a short dotted header", "[target.'cfg(" + strings.Repeat("a.", n) + ")'.x]\n" + `y.z = "` + strings.Repeat("a.", n) + `"` + "\n", false},
		{"many short dotted keys", dotted, false},
		{"a dotted key at the bound, between floats", "f = 1.5\nx" + strings.Repeat(".a", maxProofNesting) + " = 1.5\n", false},
		{"a dotted key past the bound", "x" + strings.Repeat(".a", n) + " = 1\n", true},
		{"a dotted header past the bound", "[x" + strings.Repeat(".a", n-1) + "]\n", true},
		{"a line over the bound", `x = "` + strings.Repeat("a", maxProofLine) + "\"\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCargoLock([]byte(tc.extra + lock))
			if (err != nil) != tc.deep {
				t.Errorf("ParseCargoLock error = %v, want refused = %v", err, tc.deep)
			}
		})
	}
}

// TestCargoConfigAndManifestRefuseDeepOrLongInput: a config or vendored manifest gets the same guard as a proof lock.
func TestCargoConfigAndManifestRefuseDeepOrLongInput(t *testing.T) {
	manifest := "[package]\nname = \"a\"\nversion = \"1.0.0\"\n\n[[package.metadata.capi.install.include.asset]]\nfrom = \"a.h\"\n\n[target.'cfg(unix)'.dependencies.libc]\nversion = \"0.2\"\nfeatures = [\"std\"]\n"
	config := "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"\n"
	if name, version := CargoPackageID([]byte(manifest)); name != "a" || version != "1.0.0" {
		t.Fatalf("CargoPackageID = %q, %q, want a, 1.0.0", name, version)
	}
	if _, err := ParseCargoConfig([]byte(config)); err != nil {
		t.Fatalf("ParseCargoConfig: %v", err)
	}
	n := maxProofNesting + 1
	for name, extra := range map[string]string{
		"nested inline tables": "x = " + strings.Repeat("{a = ", n) + "1" + strings.Repeat("}", n) + "\n",
		"a dotted key":         "x" + strings.Repeat(".a", n) + " = 1\n",
		"a long line":          `x = "` + strings.Repeat("a", maxProofLine) + "\"\n",
		"six quotes":           `x = """a\\""""""` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, version := CargoPackageID([]byte(extra + manifest)); got != "" || version != "" {
				t.Errorf("CargoPackageID = %q, %q, want refused", got, version)
			}
			if _, err := ParseCargoConfig([]byte(extra + config)); err == nil {
				t.Error("ParseCargoConfig accepted it")
			}
		})
	}
}

// TestCargoVendorSourceRefusesDotDotAfterAName: cargo resolves ".." after symlinks, so only a leading one is placed.
func TestCargoVendorSourceRefusesDotDotAfterAName(t *testing.T) {
	for directory, want := range map[string]string{
		"vendor":            "app/vendor",
		"./vendor":          "app/vendor",
		"../app/vendor":     "app/vendor",
		"vendor/../tools":   "",
		"./vendor/../tools": "",
		`vendor\..\tools`:   "",
	} {
		config := map[string]any{"source": map[string]any{
			"crates-io":        map[string]any{"replace-with": "vendored-sources"},
			"vendored-sources": map[string]any{"directory": directory},
		}}
		configAt := func(dir string) (map[string]any, bool) {
			if dir == "app" {
				return config, true
			}
			return nil, true
		}
		if got := CargoVendorSource("app", configAt); got != want {
			t.Errorf("CargoVendorSource with directory %q = %q, want %q", directory, got, want)
		}
	}
}
