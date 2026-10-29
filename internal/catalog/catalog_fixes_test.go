package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/source"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// catalogSet catalogues files offline and returns "type/name@version" keys.
func catalogSet(t *testing.T, files map[string]string) map[string]bool {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, files)
	pkgs, err := Catalog(context.Background(), dir, Options{NoExec: true, SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Type+"/"+strings.ToLower(p.Name)+"@"+p.Version] = true
	}
	return got
}

func hasName(got map[string]bool, typeName string) bool {
	for k := range got {
		if strings.HasPrefix(k, typeName+"@") {
			return true
		}
	}
	return false
}

// A yarn berry lock records the root project (and portal/link/file deps) as
// entries of their own; none is on the registry.
func TestCatalog_YarnBerryLocalEntriesAreNotComponents(t *testing.T) {
	got := catalogSet(t, map[string]string{"yarn.lock": "__metadata:\n  version: 6\n  cacheKey: 8\n\n" +
		"\"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: abc\n  languageName: node\n  linkType: hard\n\n" +
		"\"@acme/lib@portal:../lib::locator=app%40workspace%3A.\":\n  version: 0.0.0-use.local\n  resolution: \"@acme/lib@portal:../lib::locator=app%40workspace%3A.\"\n  languageName: node\n  linkType: soft\n\n" +
		"\"tool@file:./tool.tgz::locator=app%40workspace%3A.\":\n  version: 2.0.0\n  resolution: \"tool@file:./tool.tgz#./tool.tgz::hash=1&locator=app%40workspace%3A.\"\n  languageName: node\n  linkType: hard\n\n" +
		"\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  dependencies:\n    left-pad: \"npm:1.3.0\"\n  languageName: unknown\n  linkType: soft\n"})
	if !got["npm/left-pad@1.3.0"] {
		t.Errorf("registry dep missing: %v", got)
	}
	for _, name := range []string{"npm/app", "npm/@acme/lib", "npm/tool"} {
		if hasName(got, name) {
			t.Errorf("local yarn entry %s emitted as a component: %v", name, got)
		}
	}
}

func TestIsLocalYarnResolved(t *testing.T) {
	for in, want := range map[string]bool{
		"app@workspace:.":                       true,
		"@scope/app@workspace:packages/app":     true,
		"lib@portal:../lib::locator=x":          true,
		"lib@link:../lib::locator=x":            true,
		"file:../lib":                           true,
		"left-pad@npm:1.3.0":                    false,
		"@types/node@npm:20.0.0":                false,
		"resolve@patch:resolve@npm%3A1.22.1#~b": false,
		"https://registry.yarnpkg.com/@types/node/-/node-20.0.0.tgz#abc": false,
		"": false,
	} {
		if got := isLocalYarnResolved(in); got != want {
			t.Errorf("isLocalYarnResolved(%q) = %v, want %v", in, got, want)
		}
	}
}

// npm records a workspace link as {"resolved": "<relative path>", "link":
// true} with no version; it must not become a versionless component that is
// then looked up on the public registry.
func TestCatalog_NpmWorkspaceLinkIsNotAComponent(t *testing.T) {
	got := catalogSet(t, map[string]string{"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
 "":{"name":"app","version":"1.0.0","workspaces":["packages/*"]},
 "node_modules/my-internal-lib":{"resolved":"packages/my-internal-lib","link":true},
 "packages/my-internal-lib":{"name":"my-internal-lib","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}},
 "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`})
	if !got["npm/left-pad@1.3.0"] {
		t.Errorf("registry dep missing: %v", got)
	}
	if hasName(got, "npm/my-internal-lib") || hasName(got, "npm/packages/my-internal-lib") {
		t.Errorf("workspace member emitted as a component: %v", got)
	}
}

const v1NestedLock = `{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{
 "is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},
 "aliased":{"version":"npm:left-pad@1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
 "local":{"version":"file:../local"},
 "is-odd":{"version":"3.0.1","resolved":"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz","requires":{"is-number":"^6.0.0"},
  "dependencies":{"is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz"}}}}}`

// A v1 lockfile nests every dependency npm could not hoist; syft reads only
// the top level, so is-number@6.0.0 went missing.
func TestCatalog_PackageLockV1NestedDependencies(t *testing.T) {
	got := catalogSet(t, map[string]string{"package-lock.json": v1NestedLock})
	for _, want := range []string{"npm/is-number@7.0.0", "npm/is-odd@3.0.1", "npm/is-number@6.0.0", "npm/left-pad@1.3.0"} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	if hasName(got, "npm/local") {
		t.Errorf("file: dep emitted: %v", got)
	}
}

// npm-shrinkwrap.json is package-lock.json under another name; the npm
// resolve stands down for it, so it must be read.
func TestCatalog_NpmShrinkwrap(t *testing.T) {
	t.Run("v3", func(t *testing.T) {
		got := catalogSet(t, map[string]string{"npm-shrinkwrap.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
 "":{"name":"app","version":"1.0.0"},
 "node_modules/is-odd":{"version":"3.0.1","resolved":"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"},
 "node_modules/is-odd/node_modules/is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz"},
 "node_modules/injected":{"version":"4.1.2"},
 "node_modules/lib":{"resolved":"packages/lib","link":true},
 "packages/lib":{"name":"lib","version":"1.0.0"}}}`})
		for _, want := range []string{"npm/is-odd@3.0.1", "npm/is-number@6.0.0", "npm/injected@4.1.2"} {
			if !got[want] {
				t.Errorf("missing %s; got %v", want, got)
			}
		}
		for _, name := range []string{"npm/app", "npm/lib", "npm/packages/lib"} {
			if hasName(got, name) {
				t.Errorf("unpublished %s emitted: %v", name, got)
			}
		}
	})
	t.Run("v1", func(t *testing.T) {
		got := catalogSet(t, map[string]string{"npm-shrinkwrap.json": v1NestedLock})
		for _, want := range []string{"npm/is-number@7.0.0", "npm/is-odd@3.0.1", "npm/is-number@6.0.0"} {
			if !got[want] {
				t.Errorf("missing %s; got %v", want, got)
			}
		}
	})
}

// A requirement pinning no release ("requests", "flask>2.0") is a direct
// dependency like any unpinned manifest entry: reported versionless, to be
// defaulted to latest, never dropped. An exact pin syft cannot version (an
// epoch) still is, since latest would name a different release.
func TestCatalog_UnpinnedRequirementsAreReported(t *testing.T) {
	got := catalogSet(t, map[string]string{
		"requirements.txt":     "requests\nflask>2.0\nAttrs [x] ; python_version > '3'\ncee==1!2.0.0\n./local\nfoo @ https://x.invalid/foo.whl\n-r requirements-dev.txt\n",
		"requirements-dev.txt": "pytest\nclick==8.1.7\n",
	})
	for _, want := range []string{"pypi/requests@", "pypi/flask@", "pypi/attrs@", "pypi/pytest@", "pypi/click@8.1.7"} {
		if !got[want] {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	for _, name := range []string{"pypi/cee", "pypi/foo", "pypi/local", "pypi/click@"} {
		if got[name] || (name != "pypi/click@" && hasName(got, name)) {
			t.Errorf("%s should not be reported: %v", name, got)
		}
	}
}

// A line now reported versionless is not also called unparseable; one still
// dropped (the epoch pin) is.
func TestCatalog_UnpinnedRequirementsAreNotWarnedAbout(t *testing.T) {
	dir := t.TempDir()
	// Separate files: syft reports only the first bad line of each.
	writeTree(t, dir, map[string]string{"a/requirements.txt": "requests\n", "b/requirements.txt": "cee==1!2.0.0\n"})
	// Verbose: the headline is capped, and a long temp path (Windows) cuts the line off.
	ctx := warn.NewContext(context.Background(), true)
	if _, err := Catalog(ctx, dir, Options{NoExec: true, SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	out := warn.Drain(ctx)
	if strings.Contains(out, `"requests"`) {
		t.Errorf("reported requirement warned about as unparseable:\n%s", out)
	}
	if !strings.Contains(out, "cee==1!2.0.0") {
		t.Errorf("dropped epoch pin not warned about:\n%s", out)
	}
}

func TestUnpinnedRequirements(t *testing.T) {
	got := unpinnedRequirements([]byte("a\nb>=1,<2\nc~=1.4\nd!=1.0\ne (>=1.0)\nf==1.0\ng===1.0\nh==1.*\n-e ./x\ni @ https://x\n--index-url https://x\nj[x]\nthis is not a requirement at all !!!\nk >= 1.0 , != 1.5\n"))
	want := []string{"a", "b", "c", "d", "e", "j", "k"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("unpinnedRequirements = %v, want %v", got, want)
	}
}

// A requirements-dev.txt must reach the resolver too, not only syft's literal
// read: its transitives were otherwise never resolved.
func TestRequirementsVariantsAreResolved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}
	bin := t.TempDir()
	// Shell builtins only: PATH is this directory alone.
	writeScript(t, bin, "uv", "#!/bin/sh\n[ \"$1\" = \"--version\" ] && { echo 'uv 0.5.0'; exit 0; }\n"+
		"for a; do last=$a; done\ncase \"$last\" in *requirements-dev.txt) echo 'transitive-dep==1.0.0';; esac\nexit 0\n")
	t.Setenv("PATH", bin)

	dir := t.TempDir()
	writeFile(t, dir, "requirements-dev.txt", "pytest==8.0.0\n")
	pkgs, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	found := false
	for _, p := range pkgs {
		found = found || (p.Name == "transitive-dep" && p.Version == "1.0.0")
	}
	if !found {
		t.Errorf("requirements-dev.txt was not resolved: %+v", pkgs)
	}
}

// The no-resolver gate must see a tree whose only Python manifest is a
// requirements variant, or the scan says nothing about covering direct deps only.
func TestHasPythonManifestSeesRequirementsVariants(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements-dev.txt"), []byte("pytest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := newDirectorySource(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPythonManifest(resolver) {
		t.Error("requirements-dev.txt not counted as a Python manifest")
	}
}

// PEP 503: a versionless "typing_extensions" is the resolver's pinned
// "typing-extensions", not a second component.
func TestMergeVersionlessFoldsPEP503Spellings(t *testing.T) {
	got := mergeVersionless([]Package{
		{Name: "typing-extensions", Version: "4.0.0", Type: "pypi"},
		{Name: "typing_extensions", Type: "pypi"},
	})
	if len(got) != 1 {
		t.Errorf("got %+v, want one component", got)
	}
}

func TestIsLocalNpmVersion(t *testing.T) {
	for in, want := range map[string]bool{
		"link:../bar":         true,
		"file:../bar":         true,
		"file:./pkg.tgz":      true,
		"workspace:*":         true,
		"workspace:^1.2.3":    true,
		"portal:../lib":       true,
		"  link:../bar":       true, // leading space tolerated
		"1.3.0":               false,
		"^1.2.3":              false,
		"":                    false,
		"npm:left-pad@1.3.0":  false, // an alias resolves to a real release
		"git+https://x/y.git": false,
		"https://x/y.tgz":     false,
		"linkify@1.0.0":       false, // a name that merely starts with "link"
	} {
		if got := isLocalNpmVersion(in); got != want {
			t.Errorf("isLocalNpmVersion(%q) = %v, want %v", in, got, want)
		}
	}
}

// A package-lock.json entry whose "version" is a link:/file: protocol spec (no
// "resolved" field) is the project's own code; it must not reach the API as a
// component like pkg:npm/bar@link:../bar, while real registry deps still do.
func TestCatalog_NpmLockLocalVersionIsNotAComponent(t *testing.T) {
	for _, spec := range []string{"link:../bar", "file:../bar"} {
		got := catalogSet(t, map[string]string{"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{
 "":{"name":"app","version":"1.0.0"},
 "node_modules/bar":{"version":"` + spec + `"},
 "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`})
		if !got["npm/left-pad@1.3.0"] {
			t.Errorf("%s: registry dep missing: %v", spec, got)
		}
		if hasName(got, "npm/bar") {
			t.Errorf("%s: local entry emitted as a component: %v", spec, got)
		}
	}
}

// A package.json local/workspace dependency must not become a (versionless)
// component that then resolves the local name against the public registry.
func TestCatalog_PackageJsonLocalDepIsNotAComponent(t *testing.T) {
	for _, spec := range []string{"file:../bar", "link:../bar", "workspace:*", "portal:../bar"} {
		got := catalogSet(t, map[string]string{
			"package.json": `{"name":"app","version":"1.0.0","dependencies":{"bar":"` + spec + `","left-pad":"1.3.0"}}`,
		})
		if !got["npm/left-pad@1.3.0"] {
			t.Errorf("%s: registry dep missing: %v", spec, got)
		}
		if hasName(got, "npm/bar") {
			t.Errorf("%s: local dep emitted as a component: %v", spec, got)
		}
	}
}
