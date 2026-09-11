package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/anchore/syft/syft/file"
)

func TestParsePipReport(t *testing.T) {
	report := []byte(`{
	  "version": "1",
	  "install": [
	    {"metadata": {"name": "Requests", "version": "2.31.0"},
	     "download_info": {"url": "https://files.pythonhosted.org/packages/x/requests-2.31.0-py3-none-any.whl"}},
	    {"metadata": {"name": "idna", "version": "3.6"},
	     "download_info": {"url": "https://files.pythonhosted.org/packages/y/idna-3.6-py3-none-any.whl"}},
	    {"metadata": {"name": "mylib", "version": "0.1.0"},
	     "download_info": {"url": "file:///repo/libs/mylib"}},
	    {"metadata": {"name": "requests", "version": "2.31.0"},
	     "download_info": {"url": "https://files.pythonhosted.org/packages/x/requests-2.31.0.tar.gz"}},
	    {"metadata": {"name": "", "version": "9.9.9"}},
	    {"metadata": {"name": "nover", "version": ""}}
	  ]
	}`)

	pkgs, err := parsePipReport(report, file.NewLocation("requirements.txt"))
	if err != nil {
		t.Fatalf("parsePipReport: %v", err)
	}

	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	want := map[string]string{"requests": "2.31.0", "idna": "3.6"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for name, version := range want {
		if got[name] != version {
			t.Errorf("%s = %q, want %q", name, got[name], version)
		}
	}
	// A local path dependency is the repo's own code, not a registry package.
	if _, ok := got["mylib"]; ok {
		t.Errorf("file: URL entry leaked into the catalog: %v", got)
	}
}

func TestParsePipReportRejectsGarbage(t *testing.T) {
	if _, err := parsePipReport([]byte("not json"), file.NewLocation("requirements.txt")); err == nil {
		t.Fatal("expected an error for unparseable report JSON")
	}
}

func TestParsePipVersion(t *testing.T) {
	tests := map[string]struct {
		out  string
		want pipVersion
		ok   bool
	}{
		"standard":    {"pip 24.0 from /usr/lib/python3/dist-packages/pip (python 3.12)\n", pipVersion{24, 0}, true},
		"patch":       {"pip 22.0.2 from /x (python 3.10)", pipVersion{22, 0}, true},
		"prerelease":  {"pip 25.1b1 from /x (python 3.13)", pipVersion{}, false},
		"no minor":    {"pip 24 from /x (python 3.12)", pipVersion{}, false},
		"not pip":     {"uv 0.5.1", pipVersion{}, false},
		"empty":       {"", pipVersion{}, false},
		"one field":   {"pip", pipVersion{}, false},
		"leading gap": {"  pip 23.3.1 from /x", pipVersion{23, 3}, true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := parsePipVersion(tc.out)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got %v)", ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPipVersionOlderThan(t *testing.T) {
	tests := []struct {
		v, than pipVersion
		want    bool
	}{
		{pipVersion{22, 0}, pipMinimum, true},  // ubuntu 22.04's stock pip
		{pipVersion{22, 2}, pipMinimum, false}, // exactly the minimum
		{pipVersion{22, 3}, pipMinimum, false},
		{pipVersion{21, 9}, pipMinimum, true},
		{pipVersion{24, 0}, pipMinimum, false},
	}
	for _, tc := range tests {
		if got := tc.v.olderThan(tc.than); got != tc.want {
			t.Errorf("%v.olderThan(%v) = %v, want %v", tc.v, tc.than, got, tc.want)
		}
	}
}

func TestPyprojectRequirementSpecs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	writeFixture(t, dir, "pyproject.toml", `
[project]
name = "demo-proj"
version = "0.1.0"
dependencies = [
  "requests>=2,<3",
  "click",
  "tomli; python_version < '3.11'",
  "demo_proj",
]

[project.optional-dependencies]
dev = ["pytest==8.0.0", "requests>=2,<3"]

[tool.poetry.dependencies]
caret-dep = "^1.2.3"
`)

	got, err := pyprojectRequirementSpecs(path)
	if err != nil {
		t.Fatalf("pyprojectRequirementSpecs: %v", err)
	}

	want := []string{
		"requests>=2,<3",
		"click",
		"tomli; python_version < '3.11'",
		"pytest==8.0.0",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, spec := range got {
		// Poetry's caret shorthand is not PEP 508; handing it to pip would fail
		// the whole manifest.
		if strings.Contains(spec, "^") {
			t.Errorf("poetry-only dependency leaked into pip specs: %q", spec)
		}
	}
}

func TestPyprojectRequirementSpecsMissingFile(t *testing.T) {
	got, err := pyprojectRequirementSpecs(filepath.Join(t.TempDir(), "pyproject.toml"))
	if err != nil {
		t.Fatalf("a vanished manifest must not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want none", got)
	}
}

// TestResolverChoicePrefersUV pins the fallback contract: Catalog picks one
// Python resolver for the scan, and pip is not built at all where uv exists.
// Running both would double every scan's resolution cost for identical output.
func TestResolverChoicePrefersUV(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}

	binDir := t.TempDir()
	pythonRan := filepath.Join(t.TempDir(), "python-ran")
	writeScript(t, binDir, "uv", "#!/bin/sh\nexit 0\n")
	writeScript(t, binDir, "python3", "#!/bin/sh\necho ran >> "+pythonRan+"\nexit 0\n")
	t.Setenv("PATH", binDir)

	proj := t.TempDir()
	writeFixture(t, proj, "requirements.txt", "requests\n")

	if _, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if _, err := os.Stat(pythonRan); !os.IsNotExist(err) {
		t.Fatalf("pip resolver ran with uv on PATH (stat err = %v)", err)
	}
}

// TestPipCatalogerResolvesTransitives drives the whole pip path against a fake
// interpreter: no uv, no network. It is the regression for a uv-less host
// silently reporting direct dependencies only.
func TestPipCatalogerResolvesTransitives(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}

	binDir := t.TempDir()
	writeScript(t, binDir, "python3", fakePythonScript)
	t.Setenv("PATH", binDir)

	proj := t.TempDir()
	writeFixture(t, proj, "pyproject.toml", "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2,<3\"]\n")

	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}

	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Type+"/"+p.Name] = p
	}

	// The direct dep is pinned to what pip resolved, not left versionless...
	direct, ok := got["pypi/requests"]
	if !ok {
		t.Fatalf("requests missing from catalog: %+v", pkgs)
	}
	if direct.Version != "2.31.0" {
		t.Errorf("requests version = %q, want 2.31.0", direct.Version)
	}
	// ...and the transitive tree the manifest never names is there too.
	transitive, ok := got["pypi/idna"]
	if !ok {
		t.Fatalf("transitive dep idna missing from catalog: %+v", pkgs)
	}
	if transitive.Version != "3.6" {
		t.Errorf("idna version = %q, want 3.6", transitive.Version)
	}
	if len(direct.Source) == 0 || direct.Source[0] != "ossprey-pip-cataloger" {
		t.Errorf("requests source = %v, want ossprey-pip-cataloger", direct.Source)
	}
}

// TestPipCatalogerWarnsWithNoResolver covers the silence that let a customer's
// CI ship manifest-only SBOMs unnoticed: with neither uv nor a usable pip, the
// scan must say so.
func TestPipCatalogerWarnsWithNoResolver(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}

	binDir := t.TempDir()
	// A Python whose pip predates --dry-run/--report.
	writeScript(t, binDir, "python3", "#!/bin/sh\n"+
		"[ \"$1\" = \"-c\" ] && exit 0\n"+
		"echo 'pip 22.0.2 from /fake (python 3.10)'\nexit 0\n")
	t.Setenv("PATH", binDir)

	proj := t.TempDir()
	writeFixture(t, proj, "requirements.txt", "requests\n")

	stderr := captureStderr(t, func() {
		if _, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true}); err != nil {
			t.Fatalf("Catalog: %v", err)
		}
	})

	if !strings.Contains(stderr, "direct Python dependencies only") {
		t.Errorf("expected a coverage warning on stderr, got %q", stderr)
	}
	if !strings.Contains(stderr, "22.0") {
		t.Errorf("expected the warning to name the too-old pip, got %q", stderr)
	}
}

// TestPipCatalogerQuietWithoutPythonManifests keeps a pure JavaScript repo from
// being told about a Python resolver it has no use for.
func TestPipCatalogerQuietWithoutPythonManifests(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}

	t.Setenv("PATH", t.TempDir()) // no uv, no python, no npm

	proj := t.TempDir()
	writeFixture(t, proj, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`)

	stderr := captureStderr(t, func() {
		if _, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true}); err != nil {
			t.Fatalf("Catalog: %v", err)
		}
	})
	if strings.Contains(stderr, "direct Python dependencies only") {
		t.Errorf("JavaScript-only repo got a Python resolver warning: %q", stderr)
	}
}

// fakePythonScript answers the three invocations the pip cataloger makes: the
// interpreter probe, the pip version query, and the resolve itself — the last by
// writing a canned installation report to the --report path.
//
// Shell builtins only. PATH is the fake bin directory alone (so the real uv
// stays invisible), which the script inherits, so `cat` and friends are not
// there to call.
const fakePythonScript = `#!/bin/sh
if [ "$1" = "-c" ]; then exit 0; fi
if [ "$3" = "--version" ]; then
  echo "pip 24.0 from /fake (python 3.12)"
  exit 0
fi
report=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--report" ]; then report="$arg"; fi
  prev="$arg"
done
[ -n "$report" ] || exit 1
{
  echo '{"version": "1", "install": ['
  echo '  {"metadata": {"name": "requests", "version": "2.31.0"},'
  echo '   "download_info": {"url": "https://files.pythonhosted.org/packages/x/requests-2.31.0-py3-none-any.whl"}},'
  echo '  {"metadata": {"name": "idna", "version": "3.6"},'
  echo '   "download_info": {"url": "https://files.pythonhosted.org/packages/y/idna-3.6-py3-none-any.whl"}}'
  echo ']}'
} > "$report"
exit 0
`

func writeScript(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written. It also resets warnOnce so each test sees the first warning of a scan.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	warnOnce = sync.Once{}
	t.Cleanup(func() { warnOnce = sync.Once{} })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	fn()

	os.Stderr = orig
	w.Close()
	out := <-done
	r.Close()
	return out
}
