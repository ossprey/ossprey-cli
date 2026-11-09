package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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
		// Dependencies the direct-deps fallback does not emit still have
		// trees only a lock names.
		{"git dependency only", map[string]string{
			"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nfoo = { git = \"https://github.com/o/foo\" }\n",
		}, []string{"Cargo.toml"}},
		{"private-registry dev dependency only", map[string]string{
			"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dev-dependencies]\nfoo = { version = \"1\", registry = \"corp\" }\n",
		}, []string{"Cargo.toml"}},
		// cargo locks a member at its workspace root and ignores a Cargo.lock
		// beside the member (verified with cargo 1.99).
		{"member with its own lock under a workspace root with no lock", map[string]string{
			"Cargo.toml": root, "crates/core/Cargo.toml": member, "crates/core/Cargo.lock": validCargoLock,
		}, []string{"crates/core/Cargo.toml"}},
		{"member pointing at a locked root that is not its ancestor", map[string]string{
			"ws/Cargo.toml": "[workspace]\nmembers = [\"../crates/core\"]\n", "ws/Cargo.lock": validCargoLock,
			"crates/core/Cargo.toml": "[package]\nname = \"core\"\nversion = \"0.1.0\"\nworkspace = \"../../ws\"\n\n[dependencies]\nserde = \"=1.0.228\"\n",
		}, nil},
		{"manifest that does not parse", map[string]string{"Cargo.toml": "[package\nname = "}, []string{"Cargo.toml"}},
		{"manifest that does not parse beside a lock", map[string]string{"Cargo.toml": "[package\nname = ", "Cargo.lock": validCargoLock}, nil},
		{"manifest over the size limit", map[string]string{"Cargo.toml": crate + "# " + strings.Repeat("x", maxManifestBytes) + "\n"}, []string{"Cargo.toml"}},
		{"path dependency only", map[string]string{
			"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[target.'cfg(unix)'.dependencies]\nfoo = { path = \"../foo\" }\n",
		}, []string{"Cargo.toml"}},
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
		p             string
		fold          bool
		want          string
		ok            bool
		caseSensitive bool
	}{
		{filepath.Join(root, "a", "Cargo.toml"), false, filepath.Join("a", "Cargo.toml"), true, false},
		{sep + filepath.Join("users", "runneradmin", "temp", "scan", "Cargo.toml"), true, "Cargo.toml", true, false},
		{sep + filepath.Join("users", "runneradmin", "temp", "scan", "Cargo.toml"), false, "", false, true},
		{sep + filepath.Join("Users", "RunnerAdmin", "Temp", "scanner", "x"), true, "", false, false},
		{sep + filepath.Join("Users", "RunnerAdmin", "Temp", "other"), false, "", false, false},
	} {
		if tc.caseSensitive && runtime.GOOS == "windows" {
			continue // filepath.Rel already ignores case there
		}
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

// A crate an ancestor workspace excludes is not covered by that workspace's
// lock: cargo looks further up for its root, and here finds none. An
// explicit members entry wins over exclude, as in cargo's is_excluded.
func TestCargoExcludedCrateIsNotCoveredByTheRootLock(t *testing.T) {
	member := "[package]\nname = \"core\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n"
	excl := map[string]string{
		"Cargo.toml": "[workspace]\nmembers = []\nexclude = [\"crates/core\"]\n", "Cargo.lock": validCargoLock,
		"crates/core/Cargo.toml": member,
	}
	if got := unresolvedFor(t, excl); !slices.Equal(got, []string{"crates/core/Cargo.toml"}) {
		t.Errorf("excluded crate: unresolved = %v, want [crates/core/Cargo.toml]", got)
	}
	excl["Cargo.toml"] = "[workspace]\nmembers = [\"crates/core\"]\nexclude = [\"crates\"]\n"
	if got := unresolvedFor(t, excl); len(got) != 0 {
		t.Errorf("explicit member: unresolved = %v, want none", got)
	}
}

// A lockfile is read only when it is a regular file within a bound: one
// linked to /dev/zero covers nothing, and the scan does not hang on it.
func TestLockLinkedToADeviceCoversNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/zero")
	}
	cases := []struct {
		lock, manifest, body string
	}{
		{"Cargo.lock", "Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n"},
		{"uv.lock", "pyproject.toml", "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n"},
		{"package-lock.json", "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.lock, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{tc.manifest: tc.body})
			if err := os.Symlink("/dev/zero", filepath.Join(dir, tc.lock)); err != nil {
				t.Fatal(err)
			}
			if _, err := readBoundedFile(filepath.Join(dir, tc.lock), maxLockfileBytes); err == nil {
				t.Fatal("a device read as a lockfile")
			}
			switch tc.lock {
			case "Cargo.lock":
				if cargoLockCovers(filepath.Join(dir, tc.manifest), dir) {
					t.Error("covered")
				}
			case "uv.lock":
				if pyprojectLockCovered(filepath.Join(dir, tc.manifest)) {
					t.Error("covered")
				}
			default:
				if hasNpmLockfile(dir) {
					t.Error("covered")
				}
			}
		})
	}
}

// Poetry installs dev and group dependencies too, so a project declaring only
// those, with no poetry.lock, is still unresolved.
func TestPoetryDevDependenciesNeedTheLock(t *testing.T) {
	for name, pp := range map[string]string{
		"dev-dependencies": "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\n\n[tool.poetry.dev-dependencies]\npytest = \"^8\"\n",
		"group":            "[tool.poetry]\nname = \"app\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\n\n[tool.poetry.group.dev.dependencies]\npytest = \"^8\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := unresolvedFor(t, map[string]string{"pyproject.toml": pp}); !slices.Equal(got, []string{"pyproject.toml"}) {
				t.Errorf("unresolved = %v, want [pyproject.toml]", got)
			}
		})
	}
}

// A resolver whose temporary cache cannot be made records the manifests it
// would have resolved, rather than erroring past the accounting.
func TestResolverCacheFailureIsUnresolved(t *testing.T) {
	cases := map[string]struct {
		tools []string
		files map[string]string
		want  string
	}{
		"npm": {[]string{"npm", "node"}, map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`}, "package.json"},
		"uv":  {[]string{"uv", "python3"}, map[string]string{"requirements.txt": "requests>=2\n"}, "requirements.txt"},
		"pip": {[]string{"python3"}, map[string]string{"requirements.txt": "requests>=2\n"}, "requirements.txt"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			realToolsOnly(t, tc.tools...)
			if name == "pip" {
				requirePip(t)
			}
			proj := t.TempDir()
			writeTree(t, proj, tc.files)
			t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
			ctx := warn.NewContext(context.Background(), false)
			if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			if got := warn.Unresolved(ctx); !slices.Contains(got, tc.want) {
				t.Errorf("unresolved = %v, want %s in it\n%s", got, tc.want, warn.Drain(ctx))
			}
		})
	}
}

// A lockfile that parses but locks nothing is a stub, not a tree: it must not
// exempt a manifest that declares dependencies.
func TestStubLockCoversNothing(t *testing.T) {
	crate := "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n"
	pp := "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n"
	pj := `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`
	stubNpm := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"}}}`
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"Cargo.lock":                             {map[string]string{"Cargo.toml": crate, "Cargo.lock": "version = 3\n"}, "Cargo.toml"},
		"uv.lock":                                {map[string]string{"pyproject.toml": pp, "uv.lock": "version = 1\n"}, "pyproject.toml"},
		"poetry.lock":                            {map[string]string{"pyproject.toml": pp, "poetry.lock": "[metadata]\nlock-version = \"2.0\"\n"}, "pyproject.toml"},
		"package-lock.json":                      {map[string]string{"package.json": pj, "package-lock.json": stubNpm}, "package.json"},
		"Cargo.lock with an empty package":       {map[string]string{"Cargo.toml": crate, "Cargo.lock": "version = 3\n\n[[package]]\n"}, "Cargo.toml"},
		"Cargo.lock with a nameless package":     {map[string]string{"Cargo.toml": crate, "Cargo.lock": "version = 3\n\n[[package]]\nversion = \"1.0.0\"\n"}, "Cargo.toml"},
		"uv.lock with an empty package":          {map[string]string{"pyproject.toml": pp, "uv.lock": "version = 1\n\n[[package]]\n"}, "pyproject.toml"},
		"poetry.lock with a versionless package": {map[string]string{"pyproject.toml": pp, "poetry.lock": "[[package]]\nname = \"requests\"\n"}, "pyproject.toml"},
		"v1 package-lock.json":                   {map[string]string{"package.json": pj, "package-lock.json": `{"name":"app","lockfileVersion":1,"dependencies":{}}`}, "package.json"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := unresolvedFor(t, tc.files); !slices.Equal(got, []string{tc.want}) {
				t.Errorf("unresolved = %v, want [%s]", got, tc.want)
			}
		})
	}
	// A v1 lock (top-level "dependencies" only) that locks a package covers.
	v1 := `{"name":"app","lockfileVersion":1,"requires":true,"dependencies":{"left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`
	for _, lock := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		if got := unresolvedFor(t, map[string]string{"package.json": pj, lock: v1}); len(got) != 0 {
			t.Errorf("valid v1 %s: unresolved = %v, want none", lock, got)
		}
	}
	// A root-only npm lock still covers a package.json declaring nothing.
	if got := unresolvedFor(t, map[string]string{"package.json": `{"name":"app","version":"1.0.0"}`, "package-lock.json": stubNpm}); len(got) != 0 {
		t.Errorf("dependency-free project: unresolved = %v, want none", got)
	}
}

// optionalDependencies are installed by default, so a manifest declaring only
// those is not dependency-free: no npm leaves it unresolved, and a root-only
// lock does not cover it.
func TestNpmOptionalDependenciesNeedResolving(t *testing.T) {
	pj := `{"name":"app","version":"1.0.0","optionalDependencies":{"fsevents":"^2.3.0"}}`
	stub := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"}}}`
	if got := unresolvedFor(t, map[string]string{"package.json": pj}); !slices.Equal(got, []string{"package.json"}) {
		t.Errorf("no lock: unresolved = %v, want [package.json]", got)
	}
	if got := unresolvedFor(t, map[string]string{"package.json": pj, "package-lock.json": stub}); !slices.Equal(got, []string{"package.json"}) {
		t.Errorf("root-only lock: unresolved = %v, want [package.json]", got)
	}
}

// A dependency-free workspace root's root-only lock covers the root, not the
// members whose dependencies it never locked.
func TestRootOnlyLockDoesNotCoverWorkspaceMembers(t *testing.T) {
	root := `{"name":"mono","version":"1.0.0","workspaces":["packages/*"]}`
	member := `{"name":"web","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`
	stub := `{"name":"mono","lockfileVersion":3,"packages":{"":{"name":"mono"}}}`
	got := unresolvedFor(t, map[string]string{"package.json": root, "package-lock.json": stub, "packages/web/package.json": member})
	if want := []string{"packages/web/package.json"}; !slices.Equal(got, want) {
		t.Errorf("unresolved = %v, want %v", got, want)
	}
	// A lock with a real tree still covers its members.
	full := `{"name":"mono","lockfileVersion":3,"packages":{"":{"name":"mono"},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`
	if got := unresolvedFor(t, map[string]string{"package.json": root, "package-lock.json": full, "packages/web/package.json": member}); len(got) != 0 {
		t.Errorf("full lock: unresolved = %v, want none", got)
	}
}

// With no Python resolver at all, dependency groups and uv's dev-dependencies
// are dependencies too: a lockless pyproject declaring only those is not
// complete.
func TestPyprojectDependencyGroupsNeedResolving(t *testing.T) {
	for name, pp := range map[string]string{
		"dependency-groups":        "[project]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependency-groups]\ndev = [\"pytest>=8\"]\n",
		"tool.uv dev-dependencies": "[project]\nname = \"app\"\nversion = \"0.1.0\"\n\n[tool.uv]\ndev-dependencies = [\"pytest>=8\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := unresolvedFor(t, map[string]string{"pyproject.toml": pp}); !slices.Equal(got, []string{"pyproject.toml"}) {
				t.Errorf("unresolved = %v, want [pyproject.toml]", got)
			}
		})
	}
	// An empty group declares nothing.
	if got := unresolvedFor(t, map[string]string{"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependency-groups]\ndev = []\n"}); len(got) != 0 {
		t.Errorf("empty group: unresolved = %v, want none", got)
	}
}

// A resolver handed [project] alone leaves dependency groups and uv's
// dev-dependencies out, so a pyproject declaring them with no lock is not
// complete on either resolver path.
func TestResolversMarkUnlockedDependencyGroups(t *testing.T) {
	pp := "[project]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependency-groups]\ndev = [\"pytest>=8\"]\n"
	for name, tools := range map[string][]string{"uv": {"uv", "python3"}, "pip": {"python3"}} {
		t.Run(name, func(t *testing.T) {
			realToolsOnly(t, tools...)
			if name == "pip" {
				requirePip(t)
			}
			proj := t.TempDir()
			writeTree(t, proj, map[string]string{"pyproject.toml": pp})
			ctx := warn.NewContext(context.Background(), false)
			if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
				t.Fatal(err)
			}
			if got := warn.Unresolved(ctx); !slices.Equal(got, []string{"pyproject.toml"}) {
				t.Errorf("unresolved = %v, want [pyproject.toml]\n%s", got, warn.Drain(ctx))
			}
		})
	}
}

// The governing Cargo.lock is judged once per root for a whole catalogue.
func TestCargoLockCheckIsMemoizedPerRoot(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"Cargo.lock": validCargoLock})
	cache := &manifestCache{}
	if !cache.lockReadable(dir) {
		t.Fatal("a valid lock is not readable")
	}
	writeTree(t, dir, map[string]string{"Cargo.lock": "version = 3\n"})
	if !cache.lockReadable(dir) {
		t.Error("the lock was judged again")
	}
}

// A lock that fails the structural TOML guard covers nothing, whatever it
// also holds: the decoder recurses once per level of a deeply nested key.
func TestLockFailingTheTOMLGuardCoversNothing(t *testing.T) {
	deep := "\n[" + strings.Repeat("a.", maxProofNesting+4) + "b]\nx = 1\n"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"Cargo.lock": validCargoLock + deep,
		"uv.lock":    "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n" + deep,
	})
	if cargoLockReadable(dir) {
		t.Error("Cargo.lock: a guarded-out lock covers")
	}
	if pyprojectLockCovered(filepath.Join(dir, "pyproject.toml")) {
		t.Error("uv.lock: a guarded-out lock covers")
	}
}

// pyproject reads are bounded and guarded: an oversized or deeply nested
// file is an error, so the preflight refuses it rather than reading on.
func TestPyprojectReadsAreBounded(t *testing.T) {
	dir := t.TempDir()
	big := "[project]\nname = \"app\"\n" + strings.Repeat("# filler\n", maxManifestBytes/9+1)
	deep := "[project]\nname = \"app\"\n[" + strings.Repeat("a.", maxProofNesting+4) + "b]\nx = 1\n"
	for name, body := range map[string]string{"oversized": big, "nested": deep} {
		writeTree(t, dir, map[string]string{"pyproject.toml": body})
		p := filepath.Join(dir, "pyproject.toml")
		if _, err := readPyProject(p); err == nil {
			t.Errorf("%s: readPyProject read it", name)
		}
		if _, err := readUVLists(p); err == nil {
			t.Errorf("%s: readUVLists read it", name)
		}
		if err := uvProjectExpandsEnv(p, dir); err == nil {
			t.Errorf("%s: the preflight passed it", name)
		}
	}
	if runtime.GOOS != "windows" {
		writeTree(t, dir, map[string]string{"requirements.txt": "-e ./lib\n"})
		if err := os.MkdirAll(filepath.Join(dir, "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/dev/zero", filepath.Join(dir, "lib", "pyproject.toml")); err != nil {
			t.Fatal(err)
		}
		if err := uvExpandsEnv(context.Background(), filepath.Join(dir, "requirements.txt"), dir); err == nil {
			t.Error("a local project linked to /dev/zero passed")
		}
	}
}

// A uv workspace keeps one uv.lock at its root, and syft reads every
// member's tree from it.
func TestUVWorkspaceRootLockCoversMembers(t *testing.T) {
	uvLock := "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
	root := "[project]\nname = \"root\"\nversion = \"0.1.0\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\nexclude = [\"packages/skip\"]\n"
	member := "[project]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n"
	if got := unresolvedFor(t, map[string]string{"pyproject.toml": root, "uv.lock": uvLock, "packages/a/pyproject.toml": member}); len(got) != 0 {
		t.Errorf("member: unresolved = %v, want none", got)
	}
	// Not a member: excluded, or outside the globs, or no root lock.
	for name, files := range map[string]map[string]string{
		"excluded":   {"pyproject.toml": root, "uv.lock": uvLock, "packages/skip/pyproject.toml": member},
		"not listed": {"pyproject.toml": root, "uv.lock": uvLock, "tools/x/pyproject.toml": member},
		"no lock":    {"pyproject.toml": root, "packages/a/pyproject.toml": member},
	} {
		want := ""
		for k := range files {
			if k != "pyproject.toml" && k != "uv.lock" {
				want = k
			}
		}
		if got := unresolvedFor(t, files); !slices.Contains(got, want) {
			t.Errorf("%s: unresolved = %v, want %s in it", name, got, want)
		}
	}
}
