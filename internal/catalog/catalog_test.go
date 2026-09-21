package catalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// pkgKey collapses a package to "name@version" for set comparisons.
func pkgKey(p pkg.Package) string { return p.Name + "@" + p.Version }

func keySet(pkgs []pkg.Package) map[string]bool {
	out := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		out[pkgKey(p)] = true
	}
	return out
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestParsePackageJSONFile(t *testing.T) {
	dir := t.TempDir()
	body := `{
		"name": "myapp",
		"dependencies": {"lodash": "^4.17.21", "react": "18.2.0"},
		"devDependencies": {"jest": ">=29.0.0", "react": "18.2.0"},
		"peerDependencies": {"myapp": "1.0.0"}
	}`
	path := writeFile(t, dir, "package.json", body)

	got, err := parsePackageJSONFile(path, file.NewLocation("package.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := keySet(got)

	// exact pins kept (react), ranges/carets left versionless (lodash ^,
	// jest >=) so a resolver/lockfile or the backend fills the real version;
	// all dep groups merged
	for _, want := range []string{"lodash@", "react@18.2.0", "jest@"} {
		if !keys[want] {
			t.Errorf("missing dependency %q; got %v", want, keys)
		}
	}
	// root project name (myapp) skipped even when self-referenced
	if keys["myapp@1.0.0"] {
		t.Error("root project name should be skipped")
	}
	// react appears in both deps + devDeps but deduped
	if len(got) != 3 {
		t.Errorf("got %d packages, want 3 (deduped): %v", len(got), keys)
	}
	for _, p := range got {
		if p.Type != pkg.NpmPkg {
			t.Errorf("%s: type = %v, want NpmPkg", p.Name, p.Type)
		}
	}
}

// Reproduces the npm 405: bootstrap pinned with a multi-bound range
// ">=3.4.1 <4.0.0" produced pkg:npm/bootstrap@3.4.1 <4.0.0, which the npm
// registry rejects with 405. A range must be emitted versionless (not a bare
// range, not a guessed bound) so the npm lockfile cataloger / syft resolves the
// real installed version and mergeVersionless folds this entry into it.
func TestParsePackageJSONFile_RangeIsVersionless(t *testing.T) {
	dir := t.TempDir()
	body := `{
		"name": "myapp",
		"dependencies": {"bootstrap": ">=3.4.1 <4.0.0", "left-pad": "1.3.0"}
	}`
	path := writeFile(t, dir, "package.json", body)

	got, err := parsePackageJSONFile(path, file.NewLocation("package.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := keySet(got)

	if !keys["bootstrap@"] {
		t.Errorf("bootstrap range should be versionless; got %v", keys)
	}
	// an exact pin is the real installed version -> kept
	if !keys["left-pad@1.3.0"] {
		t.Errorf("left-pad@1.3.0 (exact) should be kept; got %v", keys)
	}
}

func TestParsePackageJSONFile_Missing(t *testing.T) {
	got, err := parsePackageJSONFile(filepath.Join(t.TempDir(), "nope.json"), file.NewLocation("nope.json"))
	if err != nil {
		t.Fatalf("missing file should be silent, got: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestParsePackageJSONFile_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "package.json", `{not json`)
	if _, err := parsePackageJSONFile(path, file.NewLocation("package.json")); err == nil {
		t.Error("expected error on invalid JSON")
	}
}

func TestParsePyProjectFile_PEP621(t *testing.T) {
	dir := t.TempDir()
	body := `
[project]
name = "myapp"
dependencies = ["requests==2.31.0", "flask>=3.0", "rich[jupyter]==13.0.0"]

[project.optional-dependencies]
test = ["pytest==8.0.0"]
`
	path := writeFile(t, dir, "pyproject.toml", body)

	got, err := parsePyProjectFile(path, file.NewLocation("pyproject.toml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := keySet(got)

	// exact pins (==) captured, ranges (>=) left versionless,
	// extras marker stripped from name, optional groups included
	for _, want := range []string{"requests@2.31.0", "flask@", "rich@13.0.0", "pytest@8.0.0"} {
		if !keys[want] {
			t.Errorf("missing %q; got %v", want, keys)
		}
	}
	for _, p := range got {
		if p.Type != pkg.PythonPkg {
			t.Errorf("%s: type = %v, want PythonPkg", p.Name, p.Type)
		}
	}
}

func TestParsePyProjectFile_Poetry(t *testing.T) {
	dir := t.TempDir()
	body := `
[tool.poetry]
name = "myapp"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
django = {version = ">=4.2", extras = ["bcrypt"]}

[tool.poetry.dev-dependencies]
black = "23.0.0"
`
	path := writeFile(t, dir, "pyproject.toml", body)

	got, err := parsePyProjectFile(path, file.NewLocation("pyproject.toml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := keySet(got)

	// caret/range constraints left versionless; only the exact pin (black) kept
	if !keys["requests@"] {
		t.Errorf("requests (^) should be versionless; got %v", keys)
	}
	if !keys["django@"] {
		t.Errorf("django (>= table form) should be versionless; got %v", keys)
	}
	if !keys["black@23.0.0"] {
		t.Errorf("missing dev-dependency black (exact pin); got %v", keys)
	}
	// python constraint must never become a package
	if _, ok := keys["python@3.11"]; ok {
		t.Error("python should be excluded from poetry deps")
	}
}

func TestParsePEP508(t *testing.T) {
	tests := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		{"requests==2.31.0", "requests", "2.31.0"},
		{"flask>=3.0", "flask", ""},
		{"django>=4.0,<5.0", "django", ""},
		{"rich[jupyter]==13.0.0", "rich", "13.0.0"},
		{`uvicorn>=0.30 ; python_version >= "3.8"`, "uvicorn", ""},
		{`anyio==4.2.0 ; python_version >= "3.8"`, "anyio", "4.2.0"},
		{"numpy", "numpy", ""},
		{"", "", ""},
		{"# comment", "", ""},
	}
	for _, tt := range tests {
		n, v := parsePEP508(tt.in)
		if n != tt.wantName || v != tt.wantVer {
			t.Errorf("parsePEP508(%q) = (%q,%q), want (%q,%q)", tt.in, n, v, tt.wantName, tt.wantVer)
		}
	}
}

func TestPoetryVersion(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"string caret -> versionless", "^2.31.0", ""},
		{"string exact", "2.31.0", "2.31.0"},
		{"string equality", "==2.31.0", "2.31.0"},
		{"string range -> versionless", ">=1.0,<2.0", ""},
		{"table range -> versionless", map[string]any{"version": ">=4.2"}, ""},
		{"table exact", map[string]any{"version": "4.2.0"}, "4.2.0"},
		{"table without version", map[string]any{"extras": []any{"x"}}, ""},
		{"unsupported type", 42, ""},
	}
	for _, tt := range tests {
		if got := poetryVersion(tt.in); got != tt.want {
			t.Errorf("%s: poetryVersion(%v) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestExactVersion(t *testing.T) {
	tests := map[string]string{
		// exact pins are kept (bare concrete version or equality operator)
		"1.2.3":   "1.2.3",
		"4.17.21": "4.17.21",
		"==3.0.0": "3.0.0",
		"=1.2.3":  "1.2.3", // npm loose exact
		"===1.0":  "1.0",   // PEP 440 arbitrary equality
		" 1.0.0 ": "1.0.0",
		// every range/caret/tilde/compatible-release -> versionless
		"^4.17.21":       "",
		"~1.2.3":         "",
		"~=1.4.2":        "",
		">=2.0":          "",
		">=3.4.1 <4.0.0": "",
		">=1.0,<2.0":     "",
		"<4.0.0":         "",
		"!=1.0.0":        "",
		// wildcards / tags / unpinnable -> versionless
		"*":      "",
		"1.x":    "",
		"latest": "",
		"":       "",
		// bare major is not a real release even as an exact-looking value
		"8": "",
	}
	for in, want := range tests {
		if got := exactVersion(in); got != want {
			t.Errorf("exactVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPinVersion(t *testing.T) {
	tests := map[string]string{
		// major-only constraints collapse to a bare major -> not a real
		// release, drop to versionless (the click@8 / rich@13 bug).
		"8":    "",
		"13":   "",
		"2024": "",
		"":     "",
		// multi-bound ranges that survive stripVersionOp's single-operator
		// strip must NOT pin -> these caused the bootstrap@"3.4.1 <4.0.0" 405.
		"3.4.1 <4.0.0": "",
		"1.0,<2.0":     "",
		"1.x":          "",
		"*":            "",
		// concrete releases (have a dot) are kept.
		"8.1.7":        "8.1.7",
		"4.2":          "4.2",
		"13.0.0":       "13.0.0",
		"1.0.0-beta.1": "1.0.0-beta.1",
	}
	for in, want := range tests {
		if got := pinVersion(in); got != want {
			t.Errorf("pinVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// Reproduces the QA bug seen in SBOM
// d7915d1fad17135784bdfb8c6223d0c605c32b9fbe1b1c48c6252fda9db3deee: a poetry
// manifest pinning only a major version (click = "^8", rich = ">=13") produced
// pkg:pypi/click@8 / pkg:pypi/rich@13, which 404 as NOT_FOUND. They must be
// emitted versionless so they resolve / fold into the unpinned sibling.
func TestParsePyProjectFile_MajorOnlyConstraintIsUnpinned(t *testing.T) {
	dir := t.TempDir()
	body := `
[tool.poetry]
name = "myapp"

[tool.poetry.dependencies]
python = "^3.11"
click = "^8"
rich = ">=13"
requests = "^2.31.0"
`
	path := writeFile(t, dir, "pyproject.toml", body)

	got, err := parsePyProjectFile(path, file.NewLocation("pyproject.toml"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys := keySet(got)

	// major-only constraints -> versionless (no spurious @8 / @13)
	if !keys["click@"] {
		t.Errorf("click should be versionless; got %v", keys)
	}
	if !keys["rich@"] {
		t.Errorf("rich should be versionless; got %v", keys)
	}
	if keys["click@8"] || keys["rich@13"] {
		t.Errorf("major-only pin leaked a bogus version: %v", keys)
	}
	// a caret constraint is a range, not an exact pin -> versionless (a
	// resolver/lockfile or the backend supplies the real version)
	if !keys["requests@"] {
		t.Errorf("requests (^) should be versionless; got %v", keys)
	}
	if keys["requests@2.31.0"] {
		t.Errorf("caret should not pin a guessed version: %v", keys)
	}
}

func TestNormalizeName(t *testing.T) {
	tests := map[string]string{
		"Requests": "requests",
		"  Flask ": "flask",
		"NumPy":    "numpy",
	}
	for in, want := range tests {
		if got := normalizeName(in); got != want {
			t.Errorf("normalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHasPEP621Project(t *testing.T) {
	dir := t.TempDir()

	withProject := writeFile(t, dir, "with.toml", "[project]\nname = \"x\"\n")
	if !hasPEP621Project(withProject) {
		t.Error("file with [project].name should report true")
	}

	withDeps := writeFile(t, dir, "deps.toml", "[project]\ndependencies = [\"requests\"]\n")
	if !hasPEP621Project(withDeps) {
		t.Error("file with [project].dependencies should report true")
	}

	noProject := writeFile(t, dir, "ruff.toml", "[tool.ruff]\nline-length = 100\n")
	if hasPEP621Project(noProject) {
		t.Error("file without [project] should report false")
	}

	if hasPEP621Project(filepath.Join(dir, "nope.toml")) {
		t.Error("missing file should report false")
	}

	bad := writeFile(t, dir, "bad.toml", "not = = valid")
	if hasPEP621Project(bad) {
		t.Error("unparseable file should report false")
	}
}

func TestParseUVOutput(t *testing.T) {
	out := []byte(`# this file was autogenerated
Requests==2.31.0
flask==3.0.0 ; python_version >= "3.8"

# comment line
requests==2.31.0
not-a-pinned-line
django>=4.0
`)
	got := parseUVOutput(out, file.NewLocation("pyproject.toml"))
	keys := keySet(got)

	// names lowercased, markers after ';' ignored
	if !keys["requests@2.31.0"] {
		t.Errorf("missing requests@2.31.0 (lowercased); got %v", keys)
	}
	if !keys["flask@3.0.0"] {
		t.Errorf("missing flask@3.0.0; got %v", keys)
	}
	// duplicate Requests/requests collapsed; unpinned/garbage lines dropped
	if len(got) != 2 {
		t.Errorf("got %d packages, want 2: %v", len(got), keys)
	}
	for _, p := range got {
		if p.Type != pkg.PythonPkg {
			t.Errorf("%s: type = %v, want PythonPkg", p.Name, p.Type)
		}
	}
}

func TestUVArgsForPyProject(t *testing.T) {
	// no uv.lock -> pip compile against pyproject.toml
	noLock := t.TempDir()
	args := uvArgsForPyProject(noLock)
	if len(args) < 2 || args[0] != "pip" || args[1] != "compile" {
		t.Errorf("without uv.lock want `pip compile ...`, got %v", args)
	}

	// uv.lock present -> export
	withLock := t.TempDir()
	writeFile(t, withLock, "uv.lock", "version = 1\n")
	args = uvArgsForPyProject(withLock)
	if len(args) == 0 || args[0] != "export" {
		t.Errorf("with uv.lock want `export ...`, got %v", args)
	}
}

func TestOssbomType(t *testing.T) {
	tests := []struct {
		in   pkg.Type
		want string
	}{
		{pkg.PythonPkg, "pypi"},
		{pkg.NpmPkg, "npm"},
		{pkg.RustPkg, "cargo"},
		// An ecosystem with no cataloger still maps to "", and Catalog drops it.
		{pkg.GemPkg, ""},
	}
	for _, tt := range tests {
		if got := ossbomType(tt.in); got != tt.want {
			t.Errorf("ossbomType(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDedupKey(t *testing.T) {
	// Same package, different name casing from two catalogers -> one key.
	syft := dedupKey("pypi", "PyYAML", "6.0")
	ours := dedupKey("pypi", "pyyaml", "6.0")
	if syft != ours {
		t.Errorf("case-mismatched names not collapsed: %q vs %q", syft, ours)
	}

	// Different version -> distinct keys.
	if dedupKey("pypi", "requests", "2.31.0") == dedupKey("pypi", "requests", "2.30.0") {
		t.Error("different versions should not collapse")
	}

	// Same name+version across ecosystems stays distinct.
	if dedupKey("pypi", "left-pad", "1.0.0") == dedupKey("npm", "left-pad", "1.0.0") {
		t.Error("different types should not collapse")
	}
}

func TestMergeVersionless(t *testing.T) {
	// click + requests each emitted versionless (pyproject) AND versioned (uv).
	in := []Package{
		{Name: "click", Version: "", Type: "pypi", Source: []string{"ossprey-pyproject-cataloger"}, Locations: []string{"pyproject.toml"}},
		{Name: "click", Version: "8.4.1", Type: "pypi", Source: []string{"ossprey-uv-cataloger"}, Locations: []string{"uv.lock"}},
		{Name: "requests", Version: "2.31.0", Type: "pypi", Source: []string{"ossprey-uv-cataloger"}},
		{Name: "requests", Version: "", Type: "pypi", Source: []string{"ossprey-pyproject-cataloger"}},
		// versionless with no versioned sibling stays.
		{Name: "lonely", Version: "", Type: "pypi", Source: []string{"ossprey-pyproject-cataloger"}},
	}

	out := mergeVersionless(in)

	byName := map[string]Package{}
	for _, p := range out {
		if _, dup := byName[p.Name]; dup {
			t.Errorf("duplicate entry for %q", p.Name)
		}
		byName[p.Name] = p
	}

	if len(out) != 3 {
		t.Fatalf("got %d packages, want 3: %v", len(out), out)
	}
	if byName["click"].Version != "8.4.1" {
		t.Errorf("click version = %q, want 8.4.1", byName["click"].Version)
	}
	// versionless source folded into the versioned entry.
	if got := byName["click"].Source; len(got) != 2 {
		t.Errorf("click sources = %v, want both catalogers merged", got)
	}
	if _, ok := byName["lonely"]; !ok {
		t.Error("versionless package with no versioned sibling should be kept")
	}
}

func TestMergeVersionless_CaseInsensitive(t *testing.T) {
	in := []Package{
		{Name: "PyYAML", Version: "6.0", Type: "pypi", Source: []string{"python-package-cataloger"}},
		{Name: "pyyaml", Version: "", Type: "pypi", Source: []string{"ossprey-pyproject-cataloger"}},
	}
	out := mergeVersionless(in)
	if len(out) != 1 {
		t.Fatalf("got %d, want 1 (case-insensitive merge): %v", len(out), out)
	}
	if len(out[0].Source) != 2 {
		t.Errorf("sources = %v, want both merged", out[0].Source)
	}
}

// withResolveLatest swaps resolveLatestFn for the duration of a test and
// restores it afterward.
func withResolveLatest(t *testing.T, fn func(ctx context.Context, ecosystem, name string) (string, error)) {
	t.Helper()
	old := resolveLatestFn
	resolveLatestFn = fn
	t.Cleanup(func() { resolveLatestFn = old })
}

func TestResolveVersionless(t *testing.T) {
	t.Setenv("OSSPREY_RESOLVE_LATEST", "") // default: enabled

	latest := map[string]string{
		"npm/lodash":    "4.17.21",
		"pypi/requests": "2.31.0",
	}
	var calls atomic.Int64 // resolveVersionless calls the resolver concurrently
	withResolveLatest(t, func(_ context.Context, eco, name string) (string, error) {
		calls.Add(1)
		if v, ok := latest[eco+"/"+name]; ok {
			return v, nil
		}
		return "", fmt.Errorf("no version for %s/%s", eco, name)
	})

	pkgs := []Package{
		{Name: "lodash", Version: "", Type: "npm"},               // versionless -> resolved
		{Name: "requests", Version: "", Type: "pypi"},            // versionless -> resolved
		{Name: "flask", Version: "3.0.0", Type: "pypi"},          // already pinned -> untouched
		{Name: "mycode", Version: "", Type: "pypi", Local: true}, // local -> skipped
		{Name: "ghost", Version: "", Type: "pypi"},               // resolver fails -> stays versionless
	}
	resolveVersionless(context.Background(), pkgs, Options{})

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if byName["lodash"].Version != "4.17.21" {
		t.Errorf("lodash version = %q, want 4.17.21", byName["lodash"].Version)
	}
	if byName["requests"].Version != "2.31.0" {
		t.Errorf("requests version = %q, want 2.31.0", byName["requests"].Version)
	}
	if byName["flask"].Version != "3.0.0" {
		t.Errorf("flask version = %q, want unchanged 3.0.0", byName["flask"].Version)
	}
	if byName["mycode"].Version != "" {
		t.Errorf("local package should be skipped, got version %q", byName["mycode"].Version)
	}
	if byName["ghost"].Version != "" {
		t.Errorf("failed resolution should stay versionless, got %q", byName["ghost"].Version)
	}
	// lodash, requests, ghost — flask (pinned) and mycode (local) never call out.
	if got := calls.Load(); got != 3 {
		t.Errorf("resolveLatestFn calls = %d, want 3", got)
	}
}

func TestResolveVersionless_Disabled(t *testing.T) {
	// Both the env var and the SkipVersionLookup flag must leave components
	// versionless without ever calling the registry.
	cases := map[string]struct {
		env  string
		opts Options
	}{
		"env var off":      {env: "0", opts: Options{}},
		"skip-lookup flag": {env: "", opts: Options{SkipVersionLookup: true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OSSPREY_RESOLVE_LATEST", tc.env)

			var calls int
			withResolveLatest(t, func(_ context.Context, _, _ string) (string, error) {
				calls++
				return "9.9.9", nil
			})

			pkgs := []Package{{Name: "lodash", Version: "", Type: "npm"}}
			resolveVersionless(context.Background(), pkgs, tc.opts)

			if calls != 0 {
				t.Errorf("resolution should be skipped; got %d calls", calls)
			}
			if pkgs[0].Version != "" {
				t.Errorf("version should stay empty, got %q", pkgs[0].Version)
			}
		})
	}
}

func TestResolveLatestEnabled(t *testing.T) {
	tests := map[string]bool{
		"":      true,
		"1":     true,
		"true":  true,
		"yes":   true,
		"0":     false,
		"false": false,
		"FALSE": false,
		"no":    false,
		"off":   false,
		" off ": false,
	}
	for in, want := range tests {
		t.Setenv("OSSPREY_RESOLVE_LATEST", in)
		if got := resolveLatestEnabled(); got != want {
			t.Errorf("OSSPREY_RESOLVE_LATEST=%q: enabled = %v, want %v", in, got, want)
		}
	}
}

func TestIsOspreyCataloger(t *testing.T) {
	for _, name := range []string{
		"ossprey-uv-cataloger",
		"ossprey-setuppy-cataloger",
		"ossprey-pyproject-cataloger",
		"ossprey-packagejson-cataloger",
	} {
		if !isOspreyCataloger(name) {
			t.Errorf("%q should be reported as an ossprey cataloger", name)
		}
	}
	if isOspreyCataloger("python-package-cataloger") {
		t.Error("syft cataloger misreported as ossprey cataloger")
	}
}

func TestIsRootManifestPackage(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"package.json", true},
		{"sub/dir/pyproject.toml", true},
		{"poetry.lock", false},
		{"requirements.txt", false},
	}
	for _, tt := range tests {
		p := pkg.Package{Locations: file.NewLocationSet(file.NewLocation(tt.path))}
		if got := isRootManifestPackage(p); got != tt.want {
			t.Errorf("isRootManifestPackage(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsUnpublishedNpmLockEntry(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", `{
		"name": "app",
		"version": "1.0.0",
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "app", "version": "1.0.0"},
			"node_modules/@ctrl/tinycolor": {"version": "4.1.2"},
			"node_modules/linked": {"resolved": "packages/linked", "link": true},
			"packages/linked": {"version": "2.0.0"}
		}
	}`)
	locks := newNpmLockClassifier(dir)
	lockLoc := file.NewLocationSet(file.NewLocation("package-lock.json"))

	// dep with a registry tarball -> published, keep
	dep := pkg.Package{Metadata: pkg.NpmPackageLockEntry{
		Resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
	}}
	if isUnpublishedNpmLockEntry(dep, locks) {
		t.Error("dep with resolved tarball should not be treated as unpublished")
	}
	// file:-resolved entry -> local code, drop
	local := pkg.Package{Metadata: pkg.NpmPackageLockEntry{Resolved: "file:../sibling"}}
	if !isUnpublishedNpmLockEntry(local, locks) {
		t.Error("file:-resolved entry should be unpublished")
	}
	// registry dep whose lock entry omits "resolved" (cache-installed or
	// injected lockfile) -> npm still installs it from the registry, keep
	injected := pkg.Package{
		Name: "@ctrl/tinycolor", Version: "4.1.2",
		Locations: lockLoc,
		Metadata:  pkg.NpmPackageLockEntry{Resolved: ""},
	}
	if isUnpublishedNpmLockEntry(injected, locks) {
		t.Error("registry dep without resolved URL should not be treated as unpublished")
	}
	// root project entry -> empty resolved and not a registry dep, drop
	root := pkg.Package{
		Name: "app", Version: "1.0.0",
		Locations: lockLoc,
		Metadata:  pkg.NpmPackageLockEntry{Resolved: ""},
	}
	if !isUnpublishedNpmLockEntry(root, locks) {
		t.Error("root project lock entry should be unpublished")
	}
	// workspace member surfaced via its path key -> drop
	member := pkg.Package{
		Name: "packages/linked", Version: "2.0.0",
		Locations: lockLoc,
		Metadata:  pkg.NpmPackageLockEntry{Resolved: ""},
	}
	if !isUnpublishedNpmLockEntry(member, locks) {
		t.Error("workspace member lock entry should be unpublished")
	}
	// non-lock package (e.g. our package.json cataloger output) -> not applicable
	other := pkg.Package{Metadata: pkg.NpmPackage{}}
	if isUnpublishedNpmLockEntry(other, locks) {
		t.Error("non-lock metadata should never be flagged")
	}
}

func TestNpmLockClassifier_V1Lockfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", `{
		"name": "app",
		"version": "1.0.0",
		"lockfileVersion": 1,
		"dependencies": {
			"lodash": {"version": "4.17.21"},
			"localdep": {"version": "file:../localdep"},
			"gitdep": {"version": "git+https://example.com/x.git#abc"}
		}
	}`)
	locks := newNpmLockClassifier(dir)
	lockLoc := file.NewLocationSet(file.NewLocation("package-lock.json"))

	entry := func(name, version string) pkg.Package {
		return pkg.Package{
			Name: name, Version: version,
			Locations: lockLoc,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: ""},
		}
	}
	if isUnpublishedNpmLockEntry(entry("lodash", "4.17.21"), locks) {
		t.Error("v1 registry dep without resolved should be kept")
	}
	if !isUnpublishedNpmLockEntry(entry("localdep", "file:../localdep"), locks) {
		t.Error("v1 file: dep should be unpublished")
	}
	if !isUnpublishedNpmLockEntry(entry("gitdep", "git+https://example.com/x.git#abc"), locks) {
		t.Error("v1 git dep should be unpublished")
	}
}

// TestCatalog_LockfileWithoutResolvedOrManifest is the end-to-end regression
// for the missed @ctrl/tinycolor: a package-lock.json sitting in a folder with
// no package.json, whose entries carry a version but no "resolved" URL. npm
// would still install these from the registry, so the scan must surface them.
func TestCatalog_LockfileWithoutResolvedOrManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", `{
		"name": "infected-project-lock",
		"version": "0.0.0",
		"lockfileVersion": 3,
		"requires": true,
		"packages": {
			"": {"name": "infected-project-lock", "version": "0.0.0"},
			"node_modules/@ctrl/tinycolor": {"version": "4.1.2"}
		},
		"dependencies": {
			"@ctrl/tinycolor": {"version": "4.1.2"}
		}
	}`)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	var found bool
	for _, p := range got {
		if p.Name == "infected-project-lock" {
			t.Errorf("root project leaked into the catalog: %+v", p)
		}
		if p.Name == "@ctrl/tinycolor" && p.Version == "4.1.2" && p.Type == "npm" {
			found = true
		}
	}
	if !found {
		t.Errorf("@ctrl/tinycolor@4.1.2 missing from catalog; got %+v", got)
	}
}

func TestLocations(t *testing.T) {
	p := pkg.Package{Locations: file.NewLocationSet(
		file.NewLocation("a/pyproject.toml"),
		file.NewLocation("b/uv.lock"),
	)}
	got := locations(p)
	if len(got) != 2 {
		t.Fatalf("got %d locations, want 2: %v", len(got), got)
	}
}

const cargoLockFixture = `version = 3

[[package]]
name = "my-workspace-crate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "tokio"
version = "1.38.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"
`

func TestCatalogCargoLock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.lock", cargoLockFixture)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}

	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}

	for _, want := range []struct{ name, version string }{
		{"serde", "1.0.200"},
		{"tokio", "1.38.0"},
	} {
		p, ok := byName[want.name]
		if !ok {
			t.Fatalf("%s missing from %v", want.name, byName)
		}
		if p.Type != "cargo" {
			t.Errorf("%s: type = %q, want cargo", p.Name, p.Type)
		}
		if p.Version != want.version {
			t.Errorf("%s: version = %q, want %q", p.Name, p.Version, want.version)
		}
	}

	// No `source` means a path member of this workspace, not a registry crate.
	// Emitting it would submit the project's own code as a dependency.
	if _, ok := byName["my-workspace-crate"]; ok {
		t.Errorf("workspace-local crate was emitted: %v", byName["my-workspace-crate"])
	}
}

const cargoTomlFixture = `[package]
name = "my-app"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.38", features = ["full"] }
pinned = "=2.4.1"
local-helper = { path = "../helper" }
from-git = { git = "https://github.com/x/y" }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"

[target.'cfg(windows)'.dependencies]
winapi = "0.3"

[target.'cfg(unix)'.build-dependencies]
nix = "0.29"

[dependencies.renamed-thing]
package = "real-crate"
version = "3.1"

[dependencies.private-dep]
version = "1.0"
registry = "company-internal"

[dependencies.inherited]
workspace = true
`

const cargoWorkspaceRootFixture = `[workspace]
members = ["crates/app"]

[workspace.dependencies]
never-used-by-any-member = "9.9"
`

func TestCatalogCargoTomlWithoutLockfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoTomlFixture)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}

	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}

	// A caret range is not a version. Emitting one would ship a component on a
	// version the crate never uses; versionless lets the backend resolve it.
	for _, name := range []string{"serde", "tokio", "criterion", "cc"} {
		p, ok := byName[name]
		if !ok {
			t.Fatalf("%s missing from %v", name, byName)
		}
		if p.Type != "cargo" {
			t.Errorf("%s: type = %q, want cargo", name, p.Type)
		}
		if p.Version != "" {
			t.Errorf("%s: version = %q, want empty for a range", name, p.Version)
		}
	}

	if p := byName["pinned"]; p.Version != "2.4.1" {
		t.Errorf("an exact =2.4.1 pin should carry its version, got %q", p.Version)
	}

	// Platform-gated deps still ship to whoever builds for that platform.
	for _, name := range []string{"winapi", "nix"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("%s: a [target.'cfg(...)'] dependency must still be catalogued", name)
		}
	}

	// `renamed-thing = { package = "real-crate" }`: the alias is not a crate.
	if _, ok := byName["renamed-thing"]; ok {
		t.Error("the alias was emitted; the registry has no such crate")
	}
	if _, ok := byName["real-crate"]; !ok {
		t.Error("the real package name should be emitted for a renamed dependency")
	}

	// A private registry is not crates.io, so resolving it there is wrong.
	if _, ok := byName["private-dep"]; ok {
		t.Error("an alternate-registry dependency should not be emitted as cargo")
	}

	// Inherited from a workspace whose pool this fixture does not have. The key
	// alone could name a path member or a rename alias, so it is not a crate we
	// can vouch for and must not be resolved against crates.io.
	if p, ok := byName["inherited"]; ok {
		t.Errorf("emitted %+v; the pool is unreachable, so the name is unvouched", p)
	}

	// Neither is on crates.io, so submitting them yields only NOT_FOUND.
	for _, name := range []string{"local-helper", "from-git", "my-app"} {
		if _, ok := byName[name]; ok {
			t.Errorf("%s should not be emitted", name)
		}
	}
}

func TestCatalogCargoLockWinsOverManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoTomlFixture)
	writeFile(t, dir, "Cargo.lock", cargoLockFixture)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}

	// serde is in both: versioned from the lock, versionless from the manifest.
	// The merge must collapse them rather than ship the crate twice.
	var serde []Package
	for _, p := range got {
		if p.Name == "serde" {
			serde = append(serde, p)
		}
	}
	if len(serde) != 1 {
		t.Fatalf("want one serde component, got %d: %v", len(serde), serde)
	}
	if serde[0].Version != "1.0.200" {
		t.Errorf("the lockfile version should win, got %q", serde[0].Version)
	}
}

func TestCatalogCargoWorkspacePoolIsNotADependencyList(t *testing.T) {
	// [workspace.dependencies] is an inheritance pool. Emitting it would invent
	// components no member actually depends on.
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoWorkspaceRootFixture)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	for _, p := range got {
		if p.Name == "never-used-by-any-member" {
			t.Fatalf("the workspace pool was emitted as a dependency: %+v", p)
		}
	}
}

const cargoInheritanceFixture = `[package]
name = "member"

[workspace.dependencies]
pinned-in-pool = "=1.2.3"
ranged-in-pool = "1.4"
renamed-in-pool = { package = "real-pool-crate", version = "=2.0.0" }
local-in-pool = { path = "../local" }

[dependencies]
pinned-in-pool = { workspace = true }
ranged-in-pool = { workspace = true }
renamed-in-pool = { workspace = true }
local-in-pool = { workspace = true }
absent-from-pool = { workspace = true }
two-component = "=1.0"
three-component = "=1.0.0"
bare-full = "1.0.0"
prerelease = "=1.0.0-alpha.1"
alt-index = { version = "=1.0.0", registry-index = "https://internal.example/index" }
`

func TestCatalogCargoWorkspaceInheritanceReadsThePool(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoInheritanceFixture)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}

	// The pin is in the same file, so inheriting must use it rather than leave
	// the crate versionless for the registry to answer with its latest release.
	if p := byName["pinned-in-pool"]; p.Version != "1.2.3" {
		t.Errorf("inherited pin: version = %q, want 1.2.3", p.Version)
	}
	if p, ok := byName["ranged-in-pool"]; !ok || p.Version != "" {
		t.Errorf("a pooled range is still a range, got %+v", p)
	}
	// The pool entry carries the rename, so the alias is not a crate.
	if _, ok := byName["renamed-in-pool"]; ok {
		t.Error("the alias was emitted; the registry has no such crate")
	}
	if p := byName["real-pool-crate"]; p.Version != "2.0.0" {
		t.Errorf("pooled rename: version = %q, want 2.0.0", p.Version)
	}
	// A pooled path dependency is not on crates.io any more than a direct one.
	if _, ok := byName["local-in-pool"]; ok {
		t.Error("a pooled path dependency should not be emitted")
	}
	// No pool entry means the key cannot be resolved to a real crate name.
	if p, ok := byName["absent-from-pool"]; ok {
		t.Errorf("emitted %+v; an inherit with no pool entry is unvouched", p)
	}
}

func TestCatalogCargoOnlyFullSemverIsAPin(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoInheritanceFixture)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}

	// crates.io releases are always three-component, so "=1.0" cannot name one.
	if p, ok := byName["two-component"]; !ok || p.Version != "" {
		t.Errorf("=1.0 is a range, not a release, got %+v", p)
	}
	if p := byName["three-component"]; p.Version != "1.0.0" {
		t.Errorf("three-component: version = %q, want 1.0.0", p.Version)
	}
	// Bare "1.0.0" is caret in Cargo, so it is a range despite looking exact.
	if p, ok := byName["bare-full"]; !ok || p.Version != "" {
		t.Errorf("a bare version is a caret range, got %+v", p)
	}
	if p := byName["prerelease"]; p.Version != "1.0.0-alpha.1" {
		t.Errorf("prerelease: version = %q, want 1.0.0-alpha.1", p.Version)
	}
	// registry-index names a private index just as registry names a private registry.
	if _, ok := byName["alt-index"]; ok {
		t.Error("a registry-index dependency should not be emitted as cargo")
	}
}

func TestCatalogCargoResolvesRangesToLatest(t *testing.T) {
	// The shipping path: version lookup is on by default, so every Cargo.toml
	// range reaches the registry. This pins current behaviour rather than
	// endorsing it: a latest release can fall outside the declared range.
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	var askedPinned atomic.Bool // resolveVersionless calls the resolver concurrently
	withResolveLatest(t, func(_ context.Context, _, name string) (string, error) {
		if name == "pinned-in-pool" {
			askedPinned.Store(true)
		}
		return "9.9.9", nil
	})

	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoInheritanceFixture)

	got, err := Catalog(context.Background(), dir, Options{NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}

	if p := byName["two-component"]; p.Version != "9.9.9" {
		t.Errorf("a range should resolve to the registry's latest, got %q", p.Version)
	}
	// A pin resolved from the pool is already concrete, so it must not be asked
	// for and must not be overwritten by whatever the registry calls latest.
	if p := byName["pinned-in-pool"]; p.Version != "1.2.3" {
		t.Errorf("an inherited pin must survive resolution, got %q", p.Version)
	}
	if askedPinned.Load() {
		t.Error("a pinned crate should not be looked up")
	}
}

const cargoWorkspaceRootPoolFixture = `[workspace]
members = ["crates/app"]

[workspace.dependencies]
pinned = "=1.2.3"
renamed = { package = "real-pool-crate", version = "=2.0.0" }
localdep = { path = "../local" }
privdep = { version = "=3.0.0", registry = "company-internal" }
ranged = "1.4"
`

const cargoWorkspaceMemberFixture = `[package]
name = "app"

[dependencies]
pinned = { workspace = true }
renamed = { workspace = true }
localdep = { workspace = true }
privdep = { workspace = true }
ranged = { workspace = true }
`

func TestCatalogCargoInheritsFromTheWorkspaceRoot(t *testing.T) {
	// The conventional layout: the pool lives in the root manifest and the
	// member holds only the opt-in, so reading the member alone finds nothing.
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoWorkspaceRootPoolFixture)
	if err := os.MkdirAll(filepath.Join(dir, "crates", "app"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, filepath.Join(dir, "crates", "app"), "Cargo.toml", cargoWorkspaceMemberFixture)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}

	if p := byName["pinned"]; p.Version != "1.2.3" {
		t.Errorf("root pin: version = %q, want 1.2.3", p.Version)
	}
	// Without the root's rename the alias goes out as a crate name, which is a
	// lookup against whatever happens to own that name on crates.io.
	if _, ok := byName["renamed"]; ok {
		t.Error("the alias was emitted; the registry has no such crate")
	}
	if p := byName["real-pool-crate"]; p.Version != "2.0.0" {
		t.Errorf("root rename: version = %q, want 2.0.0", p.Version)
	}
	// Both name something that is not on crates.io, so resolving them there is
	// the dependency-confusion surface this cataloguer must not open.
	for _, name := range []string{"localdep", "privdep"} {
		if _, ok := byName[name]; ok {
			t.Errorf("%s is not a crates.io crate and should not be emitted", name)
		}
	}
	if p, ok := byName["ranged"]; !ok || p.Version != "" {
		t.Errorf("a pooled range is still a range, got %+v", p)
	}
}

func TestCatalogCargoWorkspaceLookupStopsAtTheScanRoot(t *testing.T) {
	// Scanning a member alone puts its workspace root out of scope, so the pool
	// cannot be read and an inherited key could name a path member, a private
	// registry or a rename alias. Emitting it would resolve a name we cannot
	// vouch for against crates.io, which is the dependency-confusion surface.
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	var asked []string
	var mu sync.Mutex
	withResolveLatest(t, func(_ context.Context, eco, name string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, eco+"/"+name)
		return "6.6.6", nil
	})

	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", cargoWorkspaceRootPoolFixture)
	member := filepath.Join(dir, "crates", "app")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, member, "Cargo.toml", cargoWorkspaceMemberFixture)

	// Version lookup is deliberately left on: it is what turns a leaked key into
	// a live crates.io request, so disabling it would assert only the safe half.
	got, err := Catalog(context.Background(), member, Options{NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	for _, p := range got {
		if p.Type == "cargo" {
			t.Errorf("emitted %s@%s; the pool is outside the scan, so the name is unvouched", p.Name, p.Version)
		}
	}
	if len(asked) != 0 {
		t.Errorf("looked up %v on crates.io; those names never left the customer's repo", asked)
	}
}

func TestCatalogCargoRejectsNamesCratesIoCannotHave(t *testing.T) {
	// One component failing the API's name rule rejects the whole SBOM, taking
	// the repo's npm and pypi components down with it.
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", `[package]
name = "ok"

[dependencies]
"do not scan me" = "=1.0.0"
"pkg with emoji \u1F389" = "=1.0.0"
"`+strings.Repeat("a", 65)+`" = "=1.0.0"
"dots.are.not.allowed" = "=1.0.0"
aliased = { package = "not a crate!", version = "=1.0.0" }
serde = "=1.0.210"
`)

	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	var names []string
	for _, p := range got {
		names = append(names, p.Name)
	}
	if len(names) != 1 || names[0] != "serde" {
		t.Errorf("emitted %v, want only [serde]", names)
	}
}

func TestCatalogCargoVersionCannotExceedTheAPILimit(t *testing.T) {
	// A version the API rejects takes the whole SBOM down with it, so an
	// over-long one is dropped to versionless rather than emitted.
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", `[package]
name = "ok"

[dependencies]
longver = "=1.0.0-`+strings.Repeat("x", 300)+`"
`)
	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	for _, p := range got {
		if p.Version != "" {
			t.Errorf("emitted %d-character version; the API caps it at 256", len(p.Version))
		}
	}
}

func TestCatalogCargoExplicitDefaultRegistryIsStillPublic(t *testing.T) {
	// "crates-io" is Cargo's reserved name for the default registry, so naming
	// it is not the same as naming a private one.
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", `[package]
name = "ok"

[dependencies]
explicit-default = { version = "=1.0.0", registry = "crates-io" }
private = { version = "=9.0.0", registry = "company-internal" }
`)
	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}
	if p := byName["explicit-default"]; p.Version != "1.0.0" {
		t.Errorf("explicit crates-io: version = %q, want 1.0.0", p.Version)
	}
	if _, ok := byName["private"]; ok {
		t.Error("an alternate-registry dependency should not be emitted as cargo")
	}
}

func TestCatalogCargoReadsDeprecatedUnderscoreTables(t *testing.T) {
	// Cargo still accepts dev_dependencies and build_dependencies, so a crate
	// using them was catalogued as having none.
	dir := t.TempDir()
	writeFile(t, dir, "Cargo.toml", `[package]
name = "ok"

[dev_dependencies]
devcrate = "=2.0.0"

[build_dependencies]
buildcrate = "=3.0.0"

[target.'cfg(unix)'.dev_dependencies]
targetdev = "=4.0.0"
`)
	got, err := Catalog(context.Background(), dir, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	byName := map[string]Package{}
	for _, p := range got {
		byName[p.Name] = p
	}
	for name, want := range map[string]string{"devcrate": "2.0.0", "buildcrate": "3.0.0", "targetdev": "4.0.0"} {
		if p, ok := byName[name]; !ok || p.Version != want {
			t.Errorf("%s: got %+v, want version %s", name, p, want)
		}
	}
}
