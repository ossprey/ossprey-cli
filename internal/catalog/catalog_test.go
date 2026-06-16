package catalog

import (
	"os"
	"path/filepath"
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
		{pkg.RustPkg, ""},
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
	// dep with a registry tarball -> published, keep
	dep := pkg.Package{Metadata: pkg.NpmPackageLockEntry{
		Resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
	}}
	if isUnpublishedNpmLockEntry(dep) {
		t.Error("dep with resolved tarball should not be treated as unpublished")
	}
	// root project / file: / link: entry -> empty resolved, drop
	root := pkg.Package{Metadata: pkg.NpmPackageLockEntry{Resolved: ""}}
	if !isUnpublishedNpmLockEntry(root) {
		t.Error("lock entry with empty resolved should be unpublished")
	}
	// non-lock package (e.g. our package.json cataloger output) -> not applicable
	other := pkg.Package{Metadata: pkg.NpmPackage{}}
	if isUnpublishedNpmLockEntry(other) {
		t.Error("non-lock metadata should never be flagged")
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
