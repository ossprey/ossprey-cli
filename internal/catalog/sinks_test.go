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

// cargoVendorFixture vendors into vendor/ and third_party/rust, beside a path dependency under vendor/.
func cargoVendorFixture(t *testing.T) string {
	t.Helper()
	proj := t.TempDir()
	for rel, content := range map[string]string{
		"Cargo.toml": `[package]
name = "my-app"
version = "0.1.0"

[workspace]
members = ["crates/app"]

[dependencies]
anyhow = "=1.0.100"
patched = { path = "vendor/patched" }
`,
		"Cargo.lock": `version = 4

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "anyhow"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccc"
`,
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
		"vendor/anyhow/.cargo-checksum.json": `{"files":{},"package":"aaaa"}`,
		"vendor/anyhow/Cargo.toml": `[package]
name = "anyhow"
version = "1.0.100"

[dev-dependencies]
trybuild = "1.0.108"
`,
		"vendor/anyhow/Cargo.lock": `version = 4

[[package]]
name = "anyhow"
version = "1.0.100"

[[package]]
name = "futures"
version = "0.3.31"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"
`,
		"third_party/rust/serde/.cargo-checksum.json": `{"files":{},"package":"cccc"}`,
		"third_party/rust/serde/Cargo.toml": `[package]
name = "serde"
version = "1.0.228"

[dev-dependencies]
serde_derive = "=1.0.228"
`,
	} {
		sinkFixture(t, proj, rel, content)
	}
	return proj
}

// TestCatalogSkipsCargoVendorTrees: a vendored crate's own lockfile and dev-dependencies are not the project's.
func TestCatalogSkipsCargoVendorTrees(t *testing.T) {
	proj := cargoVendorFixture(t)

	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	// The root lock, a workspace member, and a path dependency with no marker.
	for name, version := range map[string]string{"anyhow": "1.0.100", "itoa": "1.0.15", "memchr": "2.7.4"} {
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

// TestCatalogDoesNotLetACargoMarkerHideOtherFiles: the marker is a repository file, so on its own it hides nothing.
func TestCatalogDoesNotLetACargoMarkerHideOtherFiles(t *testing.T) {
	proj := t.TempDir()
	for rel, content := range map[string]string{
		"Cargo.toml": `[package]
name = "my-app"
version = "0.1.0"

[dependencies]
anyhow = "=1.0.100"
`,
		"Cargo.lock": `version = 4

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "anyhow"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"
`,
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
		// A crate no lockfile outside it names is a project, not a vendored dependency.
		"tools/x/.cargo-checksum.json": `{"files":{},"package":"eeee"}`,
		"tools/x/Cargo.toml": `[package]
name = "x"
version = "0.1.0"
`,
		"tools/x/Cargo.lock": `version = 4

[[package]]
name = "unlocked-dep"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ffff"
`,
		// A locked crate whose marker records another checksum is not what cargo vendored.
		"vendor/anyhow/.cargo-checksum.json": `{"files":{},"package":"0000"}`,
		"vendor/anyhow/Cargo.toml": `[package]
name = "anyhow"
version = "1.0.100"

[dependencies]
forged-dep = "=1.0.0"
`,
	} {
		sinkFixture(t, proj, rel, content)
	}

	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	for name, version := range map[string]string{"is-odd": "3.0.1", "unlocked-dep": "9.9.9", "forged-dep": "1.0.0"} {
		if v, ok := got[name]; !ok || v != version {
			t.Errorf("%s@%s hidden by a .cargo-checksum.json, got %v", name, version, got)
		}
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
