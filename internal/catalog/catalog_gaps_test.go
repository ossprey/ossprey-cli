package catalog

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anchore/syft/syft/source"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// TestCatalogEveryDocumentedLockfile walks the docs/ecosystems.md table: every
// file it names must catalogue to name@version without a resolver.
func TestCatalogEveryDocumentedLockfile(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  []string // type/name@version; "@" alone means versionless
	}{
		{
			name:  "requirements.txt",
			files: map[string]string{"requirements.txt": "requests==2.31.0\n"},
			want:  []string{"pypi/requests@2.31.0"},
		},
		{
			name: "Pipfile.lock",
			files: map[string]string{"Pipfile.lock": `{"_meta": {"hash": {"sha256": "x"}, "pipfile-spec": 6, "requires": {}, "sources": []},
 "default": {"requests": {"version": "==2.31.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}}`},
			want: []string{"pypi/requests@2.31.0"},
		},
		{
			name: "poetry.lock",
			files: map[string]string{"poetry.lock": `[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = "*"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "x"
`},
			want: []string{"pypi/requests@2.31.0"},
		},
		{
			name: "uv.lock",
			files: map[string]string{"uv.lock": `version = 1
requires-python = ">=3.12"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
`},
			want: []string{"pypi/requests@2.31.0"},
		},
		{
			name: "pdm.lock",
			files: map[string]string{"pdm.lock": `[metadata]
groups = ["default"]
lock_version = "4.4"
content_hash = "sha256:x"

[[package]]
name = "requests"
version = "2.31.0"
requires_python = ">=3.7"
summary = "x"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:aa"},
]
`},
			want: []string{"pypi/requests@2.31.0"},
		},
		{
			name:  "setup.py",
			files: map[string]string{"setup.py": "from setuptools import setup\nsetup(name='app', install_requires=['requests==2.31.0'])\n"},
			want:  []string{"pypi/requests@2.31.0"},
		},
		{
			name:  "pyproject.toml PEP 621",
			files: map[string]string{"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\", \"click>=8\"]\n[project.optional-dependencies]\ndev = [\"pytest==8.0.0\"]\n"},
			want:  []string{"pypi/requests@2.31.0", "pypi/click@", "pypi/pytest@8.0.0"},
		},
		{
			name:  "pyproject.toml poetry only",
			files: map[string]string{"pyproject.toml": "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\nclick = \"^8.1\"\n"},
			want:  []string{"pypi/requests@2.31.0", "pypi/click@"},
		},
		{
			name: "package-lock.json v1",
			files: map[string]string{"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{
 "left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
 "is-odd":{"version":"3.0.1","resolved":"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"}}}`},
			want: []string{"npm/left-pad@1.3.0", "npm/is-odd@3.0.1"},
		},
		{
			name: "package-lock.json v2",
			files: map[string]string{"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":2,"requires":true,
 "packages":{"":{"name":"app","version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}},
 "dependencies":{"left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`},
			want: []string{"npm/left-pad@1.3.0"},
		},
		{
			name: "yarn.lock classic",
			files: map[string]string{"yarn.lock": "# yarn lockfile v1\n\nleft-pad@^1.3.0:\n" +
				"  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc\"\n"},
			want: []string{"npm/left-pad@1.3.0"},
		},
		{
			name: "yarn.lock berry",
			files: map[string]string{"yarn.lock": "__metadata:\n  version: 6\n  cacheKey: 8\n\n" +
				"\"left-pad@npm:1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: abc\n  languageName: node\n  linkType: hard\n"},
			want: []string{"npm/left-pad@1.3.0"},
		},
		{
			name: "pnpm-lock.yaml v9",
			files: map[string]string{"pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\n" +
				"packages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n"},
			want: []string{"npm/left-pad@1.3.0"},
		},
		{
			// No lockfile and no resolver: direct deps, unpinned ones versionless.
			name:  "package.json without a lockfile",
			files: map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0","is-odd":"^3.0.0"}}`},
			want:  []string{"npm/left-pad@1.3.0", "npm/is-odd@"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, tc.files)
			pkgs, err := Catalog(context.Background(), dir, Options{NoExec: true, SkipVersionLookup: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			got := map[string]bool{}
			for _, p := range pkgs {
				got[p.Type+"/"+strings.ToLower(p.Name)+"@"+p.Version] = true
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %s; got %v", w, got)
				}
			}
			// The project itself is never a component.
			if got["npm/app@1.0.0"] || got["pypi/app@0.1.0"] || got["pypi/app@"] {
				t.Errorf("root project emitted as a component: %v", got)
			}
		})
	}
}

// A versionless sighting folded into its pinned sibling must carry its
// recorded source along: trust needs every sighting trusted.
func TestMergeVersionlessFoldsRegistries(t *testing.T) {
	got := mergeVersionless([]Package{
		{Name: "acme", Version: "1.0.0", Type: "pypi", Registries: []string{"https://internal/"}},
		{Name: "Acme", Version: "", Type: "pypi", Registries: []string{"https://public/"}},
	})
	if len(got) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(got), got)
	}
	if !slices.Equal(got[0].Registries, []string{"https://internal/", "https://public/"}) {
		t.Errorf("Registries = %v, want both sightings", got[0].Registries)
	}
}

func TestPinnedRequirementsGaps(t *testing.T) {
	cases := []struct {
		name string
		body string
		want map[string][]string
	}{
		// "!" is outside the version class: an epoch is left to the resolvers.
		{"epoch is not corrected", "cee==1!2.0.0\n", map[string][]string{}},
		{"arbitrary equality with a local segment", "dee===1.0+abc\n", map[string][]string{"dee": {"1.0+abc"}}},
		{"marker without spaces", "bee==2.0.0-rc.1;python_version<'3.9'\n", map[string][]string{"bee": {"2.0.0-rc.1"}}},
		{"editable vcs line pins nothing", "-e git+https://x.invalid/r.git#egg=foo==1.0\n", map[string][]string{}},
		{"long-form include pins nothing", "--requirement base.txt\n--constraint c.txt\n", map[string][]string{}},
		{
			"extras, marker and hash split across continuations",
			"aaa[x,y]==1.0.0-beta.1 ; python_version > \"3\" \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nbee==2.0.0\n",
			map[string][]string{"aaa": {"1.0.0-beta.1"}, "bee": {"2.0.0"}},
		},
		// pip starts a comment only after whitespace; a tab counts.
		{"comment after whitespace", "bee==2.0.0.post1\t# why\n", map[string][]string{"bee": {"2.0.0.post1"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pinnedRequirements([]byte(tc.body))
			if len(got) != len(tc.want) {
				t.Fatalf("pinnedRequirements() = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if !slices.Equal(got[k], v) {
					t.Errorf("pinnedRequirements()[%s] = %v, want %v", k, got[k], v)
				}
			}
		})
	}
}

// End to end through syft: the corrector and syft's parser agree on the
// awkward shapes, and an epoch syft cannot version is warned about, not
// silently reported under a wrong version.
func TestCatalog_RequirementsAwkwardShapes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt",
		"aaa[x]==1.0.0-beta.1 ; python_version > \"3\" \\\n    --hash=sha256:abc\n"+
			"bee==2.0.0.post1 # trailing\n"+
			"-e ./local\n"+
			"cee==1!2.0.0\n"+
			"dee===1.0+abc\n")

	ctx := warn.NewContext(context.Background(), false)
	pkgs, err := Catalog(ctx, dir, Options{NoExec: true, SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	for name, v := range map[string]string{"aaa": "1.0.0-beta.1", "bee": "2.0.0.post1", "dee": "1.0+abc"} {
		if got[name] != v {
			t.Errorf("%s = %q, want %q (all: %v)", name, got[name], v, got)
		}
	}
	if v, ok := got["cee"]; ok {
		t.Errorf("epoch pin reported as cee@%q; it names a different release", v)
	}
	if out := warn.Drain(ctx); !strings.Contains(out, "cee==1!2.0.0") {
		t.Errorf("unversionable epoch line not reported:\n%s", out)
	}
}

func TestResolverTimeoutFromEnv(t *testing.T) {
	cases := map[string]time.Duration{
		"":       2 * time.Minute,
		"30s":    30 * time.Second,
		" 5m ":   5 * time.Minute,
		"0":      2 * time.Minute, // zero would kill every resolve at once
		"-1s":    2 * time.Minute,
		"banana": 2 * time.Minute,
		"30":     2 * time.Minute, // a unitless number is not a duration
	}
	for in, want := range cases {
		t.Setenv("OSSPREY_RESOLVE_TIMEOUT", in)
		if got := resolverTimeout(); got != want {
			t.Errorf("OSSPREY_RESOLVE_TIMEOUT=%q: resolverTimeout() = %s, want %s", in, got, want)
		}
	}
}

// hangingNpm puts a fake npm on PATH (alone) that never returns.
func hangingNpm(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	bin := t.TempDir()
	// exec, so the context kill lands on the process holding the pipe.
	writeScript(t, bin, "npm", "#!/bin/sh\nexec "+sleep+" 60\n")
	t.Setenv("PATH", bin)
}

// One hung manifest must cost OSSPREY_RESOLVE_TIMEOUT, not the scan: the
// resolve is abandoned with a warning naming the knob, and the direct-deps
// fallback still reports the manifest.
func TestNpmResolveTimeoutIsBoundedAndActionable(t *testing.T) {
	hangingNpm(t)
	t.Setenv("OSSPREY_RESOLVE_TIMEOUT", "300ms")

	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`)

	ctx := warn.NewContext(context.Background(), false)
	start := time.Now()
	pkgs, err := Catalog(ctx, dir, Options{SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if el := time.Since(start); el > 30*time.Second {
		t.Errorf("Catalog took %s; the resolve timeout did not bound it", el)
	}
	out := warn.Drain(ctx)
	if !strings.Contains(out, "timed out after 300ms") || !strings.Contains(out, "OSSPREY_RESOLVE_TIMEOUT") {
		t.Errorf("warning should name the timeout and the knob:\n%s", out)
	}
	found := false
	for _, p := range pkgs {
		found = found || p.Name == "left-pad"
	}
	if !found {
		t.Errorf("direct dep lost when the resolve timed out: %+v", pkgs)
	}
}

// The resolve stands down for declared workspace members (the root lock
// covers them) and runs for everything else, including a non-member under the
// same root and a member pruned by a "!" exclusion. Yarn's object form.
func TestNpmResolveStandsDownOnlyForWorkspaceMembers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}
	log := filepath.Join(t.TempDir(), "resolved")
	bin := t.TempDir()
	// Shell builtins only: PATH is this directory alone.
	writeScript(t, bin, "npm", "#!/bin/sh\n"+
		"while IFS= read -r l || [ -n \"$l\" ]; do echo \"$l\" >> "+log+"; done < package.json\n"+
		"echo '"+fakeLock+"' > package-lock.json\nexit 0\n")
	t.Setenv("PATH", bin)

	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"package.json":                 `{"name":"root-app","workspaces":{"packages":["packages/*","!packages/legacy"],"nohoist":["**/x"]}}`,
		"yarn.lock":                    "",
		"packages/member/package.json": `{"name":"member-pkg"}`,
		"packages/legacy/package.json": `{"name":"legacy-pkg"}`,
		"examples/demo/package.json":   `{"name":"demo-pkg"}`,
	})

	ctx := warn.NewContext(context.Background(), false)
	if _, err := Catalog(ctx, root, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	data, _ := os.ReadFile(log)
	got := string(data)
	for _, want := range []string{"demo-pkg", "legacy-pkg"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s was not resolved; resolved manifests:\n%s", want, got)
		}
	}
	for _, skip := range []string{"member-pkg", "root-app"} {
		if strings.Contains(got, skip) {
			t.Errorf("%s was resolved although a lockfile covers it:\n%s", skip, got)
		}
	}
}

// Syft walks the symlink-resolved root but anchors exclusions to the path as
// given, so a sink under a symlinked root (macOS /var) must still be excluded.
func TestDirectorySourceSkipsPackageSinksUnderSymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	real := t.TempDir()
	for _, rel := range []string{"package.json", "node_modules/left-pad/package.json", ".venv/lib/x/package.json"} {
		sinkFixture(t, real, rel, `{"name":"x","version":"1.0.0"}`)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink: %v", err)
	}

	src, err := newDirectorySource(link)
	if err != nil {
		t.Fatalf("newDirectorySource: %v", err)
	}
	defer src.Close()
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	locs, err := resolver.FilesByGlob("**/package.json")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range locs {
		got = append(got, l.RealPath)
	}
	if len(got) != 1 || strings.Contains(got[0], "node_modules") || strings.Contains(got[0], ".venv") {
		t.Errorf("indexed %v under a symlinked root, want only the project's package.json", got)
	}
}

// pipCatalogEnv sets PATH to a bin dir holding only the given scripts.
func pipCatalogEnv(t *testing.T, scripts map[string]string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}
	bin := t.TempDir()
	for name, body := range scripts {
		writeScript(t, bin, name, body)
	}
	t.Setenv("PATH", bin)
}

// The no-resolver warning names why, and is one line for the whole scan
// however many Python manifests the tree has.
func TestPipCatalogerNoResolverReasons(t *testing.T) {
	cases := []struct {
		name    string
		scripts map[string]string
		reason  string
	}{
		{"no interpreter", nil, "no Python interpreter on PATH"},
		{"interpreter without pip", map[string]string{
			"python3": "#!/bin/sh\n[ \"$1\" = \"-c\" ] && exit 0\necho 'No module named pip' >&2\nexit 1\n",
		}, "has no usable pip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pipCatalogEnv(t, tc.scripts)
			proj := t.TempDir()
			writeTree(t, proj, map[string]string{
				"a/requirements.txt": "requests==2.31.0\n",
				"b/requirements.txt": "flask==3.0.0\n",
				"c/pyproject.toml":   "[project]\nname = \"c\"\nversion = \"0.1.0\"\ndependencies = [\"click\"]\n",
			})
			var pkgs []Package
			stderr := captureStderr(t, func() {
				var err error
				if pkgs, err = Catalog(context.Background(), proj, Options{SkipVersionLookup: true}); err != nil {
					t.Fatalf("Catalog: %v", err)
				}
			})
			if n := strings.Count(stderr, "no Python resolver available"); n != 1 {
				t.Errorf("warning printed %d times, want once:\n%s", n, stderr)
			}
			if !strings.Contains(stderr, tc.reason) {
				t.Errorf("warning should say %q:\n%s", tc.reason, stderr)
			}
			// Degrades to direct deps, never to nothing.
			names := map[string]bool{}
			for _, p := range pkgs {
				names[p.Name] = true
			}
			for _, want := range []string{"requests", "flask", "click"} {
				if !names[want] {
					t.Errorf("direct dep %s missing: %+v", want, pkgs)
				}
			}
		})
	}
}

// pip must run as `python -m pip` (a `pip` on PATH may be a shim that re-enters
// ossprey), with --dry-run, and a pyproject is handed over as parsed
// requirement strings in a temp file, never as the project directory (which
// would execute its build backend).
func TestPipCatalogerInvocationIsSafe(t *testing.T) {
	argLog := filepath.Join(t.TempDir(), "args")
	pipRan := filepath.Join(t.TempDir(), "pip-ran")
	python := strings.Replace(fakePythonScript, "report=\"\"\n", "echo \"$@\" >> "+argLog+"\nreport=\"\"\n", 1)
	pipCatalogEnv(t, map[string]string{
		"python3": python,
		"pip":     "#!/bin/sh\necho ran >> " + pipRan + "\nexit 0\n",
	})

	proj := t.TempDir()
	writeTree(t, proj, map[string]string{
		"pyproject.toml": "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests>=2\"]\n",
		"setup.py":       "raise SystemExit('build backend executed')\n",
	})
	if _, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if _, err := os.Stat(pipRan); err == nil {
		t.Error("the pip binary on PATH was executed; it may be an ossprey shim")
	}
	data, err := os.ReadFile(argLog)
	if err != nil {
		t.Fatalf("pip resolve never ran: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		args := strings.Fields(line)
		if len(args) < 3 || args[0] != "-m" || args[1] != "pip" || args[2] != "install" {
			t.Errorf("unexpected invocation %q", line)
			continue
		}
		if !slices.Contains(args, "--dry-run") || !slices.Contains(args, "--ignore-installed") {
			t.Errorf("resolve without --dry-run/--ignore-installed: %q", line)
		}
		i := slices.Index(args, "-r")
		if i < 0 || i+1 >= len(args) {
			t.Errorf("no -r requirements file: %q", line)
			continue
		}
		if req := args[i+1]; strings.HasPrefix(req, proj) || req == "." {
			t.Errorf("pip pointed at the project tree (%s), which builds it", req)
		}
		if slices.Contains(args, ".") || slices.Contains(args, proj) {
			t.Errorf("project directory passed to pip: %q", line)
		}
	}
}
