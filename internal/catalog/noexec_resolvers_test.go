package catalog

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/shim"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// evilSdist writes evilpkg-1.0.tar.gz into dir: an sdist with no wheel whose
// in-tree PEP 517 backend writes marker the moment it is imported. It needs no
// build dependencies, so a resolver that builds it can do so offline.
func evilSdist(t *testing.T, dir, marker string) {
	t.Helper()
	files := evilProject(marker)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{Name: "evilpkg-1.0/" + name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evilpkg-1.0.tar.gz"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// wheelNamingSdist writes wheelpkg-1.0, a wheel whose only dependency is
// evilpkg by direct reference to the sdist evilSdist writes beside it.
func wheelNamingSdist(t *testing.T, dir string) {
	t.Helper()
	sdist := "file://" + filepath.ToSlash(filepath.Join(dir, "evilpkg-1.0.tar.gz"))
	files := map[string]string{
		"wheelpkg/__init__.py":            "",
		"wheelpkg-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: wheelpkg\nVersion: 1.0\nRequires-Dist: evilpkg @ " + sdist + "\n",
		"wheelpkg-1.0.dist-info/WHEEL":    "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		"wheelpkg-1.0.dist-info/RECORD":   "",
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wheelpkg-1.0-py3-none-any.whl"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func evilProject(marker string) map[string]string {
	return map[string]string{
		"pyproject.toml": "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n",
		"backend.py":     "open(" + pyString(marker) + ", \"w\").write(\"ran\")\n",
		"PKG-INFO":       "Metadata-Version: 2.1\nName: evilpkg\nVersion: 1.0\n",
	}
}

func pyString(s string) string { return "r'" + s + "'" }

// realToolsOnly puts only the named real tools on PATH, so the scan picks its
// resolver from them alone. Skips when one is missing.
func realToolsOnly(t *testing.T, names ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlinked tool PATH")
	}
	bin := t.TempDir()
	for _, n := range names {
		p, err := shim.LookPathReal(n)
		if err != nil {
			t.Skipf("no %s on PATH", n)
		}
		if err := os.Symlink(p, filepath.Join(bin, n)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
}

func requirePip(t *testing.T) {
	t.Helper()
	python, ok := findPython(context.Background())
	if !ok {
		t.Skip("no Python")
	}
	if v, ok := pipReportVersion(context.Background(), python); !ok || v.olderThan(pipMinimum) {
		t.Skip("no pip with --dry-run --report")
	}
}

func assertNotRun(t *testing.T, marker string) {
	t.Helper()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the scan ran dependency code: the build backend's marker exists")
	}
}

// Every way a requirements file or pyproject can ask pip or uv to build — an
// sdist-only dependency, --no-binary inside the file, a local directory, an
// editable, a direct URL — must leave the backend unrun and the manifest
// reported unresolved.
func TestResolversNeverBuild(t *testing.T) {
	cases := map[string]map[string]string{
		"sdist only": {
			"requirements.txt": "--no-index\n--find-links DIST\nevilpkg==1.0\n",
		},
		"no-binary in the file": {
			"requirements.txt": "--no-index\n--find-links DIST\n--no-binary :all:\nevilpkg==1.0\n",
		},
		"included file": {
			"requirements.txt":  "-r sub/more.txt\n",
			"sub/more.txt":      "--no-index\n--find-links DIST\n--no-binary=:all:\nevilpkg==1.0\n",
			"sub/.placeholder":  "",
			"dist/.placeholder": "",
		},
		// A wheel's own metadata naming an sdist by URL: pip builds it
		// whatever --only-binary says, so no repository index reaches pip.
		"wheel naming an sdist": {
			"requirements.txt": "--no-index\n--find-links DIST\nwheelpkg==1.0\n",
		},
		"local directory": {
			"requirements.txt": "--no-index\n./local\n",
		},
		"editable": {
			"requirements.txt": "--no-index\n-e ./local\n",
		},
		"direct url": {
			"requirements.txt": "--no-index\nevilpkg @ file://LOCAL\n",
		},
		"pyproject direct reference": {
			"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"evilpkg @ file://LOCAL\"]\n",
		},
	}
	resolvers := map[string][]string{
		"pip": {"python3"},
		"uv":  {"uv", "python3"},
	}
	for rname, tools := range resolvers {
		for name, files := range cases {
			t.Run(rname+"/"+name, func(t *testing.T) {
				realToolsOnly(t, tools...)
				if rname == "pip" {
					requirePip(t)
				}
				proj := t.TempDir()
				marker := filepath.Join(t.TempDir(), "marker")
				evilSdist(t, filepath.Join(proj, "dist"), marker)
				wheelNamingSdist(t, filepath.Join(proj, "dist"))
				for n, body := range evilProject(marker) {
					writeTree(t, proj, map[string]string{"local/" + n: body})
				}
				tree := map[string]string{}
				for n, body := range files {
					body = strings.ReplaceAll(body, "DIST", filepath.Join(proj, "dist"))
					tree[n] = strings.ReplaceAll(body, "LOCAL", filepath.ToSlash(filepath.Join(proj, "local")))
				}
				writeTree(t, proj, tree)

				ctx := warn.NewContext(context.Background(), false)
				if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
					t.Fatalf("Catalog: %v", err)
				}
				assertNotRun(t, marker)
				manifest := "requirements.txt"
				if _, ok := files["pyproject.toml"]; ok {
					manifest = "pyproject.toml"
				}
				if got := warn.Unresolved(ctx); !slices.Contains(got, manifest) {
					t.Errorf("unresolved = %v, want %s in it\nwarnings:\n%s", got, manifest, warn.Drain(ctx))
				}
			})
		}
	}
}

// A setup.py is never run to resolve it: it is reported unresolved instead.
func TestSetupPyIsNeverRun(t *testing.T) {
	realToolsOnly(t, "uv", "python3")
	proj := t.TempDir()
	marker := filepath.Join(t.TempDir(), "marker")
	writeFixture(t, proj, "setup.py", "open("+pyString(marker)+", 'w').write('ran')\nfrom setuptools import setup\nsetup(name='app', install_requires=['requests==2.31.0'])\n")

	ctx := warn.NewContext(context.Background(), false)
	pkgs, err := Catalog(ctx, proj, Options{SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	assertNotRun(t, marker)
	if got := warn.Unresolved(ctx); !slices.Equal(got, []string{"setup.py"}) {
		t.Errorf("unresolved = %v, want [setup.py]", got)
	}
	found := false
	for _, p := range pkgs {
		found = found || p.Name == "requests"
	}
	if !found {
		t.Errorf("direct dependency from syft's setup.py parser lost: %+v", pkgs)
	}
}

// pip runs in the manifest's directory, so a pip.py planted there would be
// what `python -m pip` imports without -I.
func TestPlantedPipModuleDoesNotRun(t *testing.T) {
	realToolsOnly(t, "python3")
	requirePip(t)
	proj := t.TempDir()
	marker := filepath.Join(t.TempDir(), "marker")
	writeTree(t, proj, map[string]string{
		"app/requirements.txt": "--no-index\n",
		"app/pip.py":           "open(" + pyString(marker) + ", 'w').write('ran')\n",
		"app/pip/__init__.py":  "open(" + pyString(marker) + ", 'w').write('ran')\n",
		"app/pip/__main__.py":  "open(" + pyString(marker) + ", 'w').write('ran')\n",
	})
	// The probes run from the working directory, the resolve from the manifest's.
	t.Chdir(filepath.Join(proj, "app"))
	if _, err := Catalog(warn.NewContext(context.Background(), false), proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	assertNotRun(t, marker)
}

// No resolver subprocess may see an Ossprey credential: what they resolve is
// the tree under scan.
func TestResolverEnvHasNoOsspreySecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}
	envLog := filepath.Join(t.TempDir(), "env")
	dump := "#!/bin/sh\n/usr/bin/env >> " + envLog + "\n"
	bin := t.TempDir()
	writeScript(t, bin, "uv", dump+"[ \"$1\" = \"--version\" ] && exit 0\nexit 1\n")
	writeScript(t, bin, "npm", dump+"exit 1\n")
	writeScript(t, bin, "python3", strings.Replace(fakePythonScript, "#!/bin/sh\n", dump, 1))
	t.Setenv("PATH", bin)
	t.Setenv("OSSPREY_API_KEY", "secret-key")
	t.Setenv("API_KEY", "secret-key")
	t.Setenv("OSSPREY_MONITOR_ID", "secret-monitor")
	t.Setenv("ossprey_api_key", "secret-key")

	proj := t.TempDir()
	writeTree(t, proj, map[string]string{
		"package.json":         `{"name":"a","dependencies":{"left-pad":"^1.3.0"}}`,
		"py/requirements.txt":  "requests\n",
		"uvp/pyproject.toml":   "[project]\nname = \"d\"\nversion = \"0.1.0\"\ndependencies = [\"click\"]\n",
		"uvp/requirements.txt": "click\n",
	})
	ctx := warn.NewContext(context.Background(), false)
	if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	// And once more with uv gone, so pip is the resolver.
	if err := os.Remove(filepath.Join(bin, "uv")); err != nil {
		t.Fatal(err)
	}
	if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	data, err := os.ReadFile(envLog)
	if err != nil {
		t.Fatalf("no resolver ran: %v", err)
	}
	out := string(data)
	if strings.Contains(out, "secret-") {
		t.Errorf("a resolver subprocess saw an Ossprey credential:\n%s", out)
	}
	if !strings.Contains(out, shim.BypassEnv+"=1") {
		t.Errorf("shim bypass missing from the resolver environment:\n%s", out)
	}
}

func TestIsOsspreySecret(t *testing.T) {
	for kv, want := range map[string]bool{
		"OSSPREY_API_KEY=x":     true,
		"API_KEY=x":             true,
		"OSSPREY_MONITOR_ID=x":  true,
		"ossprey_config_dir=x":  true,
		"OSSPREY_SHIM_BYPASS=1": false,
		"OSSPREY_SHIM_DEPTH=2":  false,
		"MY_API_KEY=x":          false,
		"PATH=/bin":             false,
		"PIP_INDEX_URL=x":       false,
	} {
		if got := isOsspreySecret(kv); got != want {
			t.Errorf("isOsspreySecret(%q) = %v, want %v", kv, got, want)
		}
	}
}

func TestPipSafeRequirement(t *testing.T) {
	for line, want := range map[string]string{
		"requests":                             "requests",
		"requests==2.31.0":                     "requests==2.31.0",
		"Flask[async] >=2,<4":                  "Flask[async] >=2,<4",
		"click~=8.1 ; python_version >= '3.8'": "click~=8.1 ; python_version >= '3.8'",
		"foo==1.0 --hash=sha256:abc":           "foo==1.0",
		"foo (>=1.0)":                          "foo (>=1.0)",
		"./local":                              "",
		"local/":                               "",
		"evil @ file:///x":                     "",
		"evil@https://x/e.tar.gz":              "",
		"git+https://github.com/x/y":           "",
		"evilpkg-1.0.tar.gz":                   "",
		"wheel-1.0-py3-none-any.whl":           "",
		"C:\\pkgs\\x":                          "",
		"${PKG}":                               "",
	} {
		got, ok := pipSafeRequirement(line)
		if want == "" {
			if ok {
				t.Errorf("pipSafeRequirement(%q) kept %q", line, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("pipSafeRequirement(%q) = %q, %v; want %q", line, got, ok, want)
		}
	}
}

// Index and find-links options are recognised but never passed: a wheel
// there can name an sdist pip builds, so the file is refused (ownIndex).
func TestPipSanitizerRefusesIndexOptionsKeepsIncludes(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"requirements.txt": "-i https://idx/simple\n--extra-index-url=https://x/simple\n" +
			"--find-links wheels\n--no-binary :all:\n-e .\n--use-pep517\n" +
			"-r sub/a.txt\n-c https://remote/c.txt\nrequests==2.31.0 \\\n  --hash=sha256:aa\n",
		"sub/a.txt":    "-r ../requirements.txt\nidna\n",
		"wheels/.keep": "",
	})
	s := newPipSanitizer(context.Background(), t.TempDir(), src)
	out, err := s.file(filepath.Join(src, "requirements.txt"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out)
	got := string(data)
	if !s.ownIndex {
		t.Error("index options did not refuse the file")
	}
	for _, want := range []string{"requests==2.31.0\n", "--requirement "} {
		if !strings.Contains(got, want) {
			t.Errorf("copy lacks %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"no-binary", "\n-e", "pep517", "hash", "remote", "index-url", "find-links"} {
		if strings.Contains(got, bad) {
			t.Errorf("copy keeps %q:\n%s", bad, got)
		}
	}
	if !slices.Contains(s.dropped, "an editable (-e)") || !slices.Contains(s.dropped, "a remote include (-c <url>)") {
		t.Errorf("dropped = %v", s.dropped)
	}
	incTok, _ := shlexSplit(strings.SplitN(strings.SplitAfter(got, "--requirement ")[1], "\n", 2)[0])
	sub, _ := os.ReadFile(incTok[0])
	if !strings.Contains(string(sub), "idna") || !strings.Contains(string(sub), "--requirement "+shlexQuote(out)) {
		t.Errorf("include copy wrong (cycle should point back at %s):\n%s", out, sub)
	}
}

// An sdist-only dependency reached through the machine's own pip
// configuration, which no sanitizer touches: only --only-binary keeps pip
// from building it.
func TestPipOnlyBinaryHoldsForTrustedConfig(t *testing.T) {
	realToolsOnly(t, "python3")
	requirePip(t)
	dist := t.TempDir()
	marker := filepath.Join(t.TempDir(), "marker")
	evilSdist(t, dist, marker)
	t.Setenv("PIP_NO_INDEX", "1")
	t.Setenv("PIP_FIND_LINKS", dist)
	proj := t.TempDir()
	writeTree(t, proj, map[string]string{"requirements.txt": "evilpkg==1.0\n"})

	ctx := warn.NewContext(context.Background(), false)
	if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	assertNotRun(t, marker)
	if got := warn.Unresolved(ctx); !slices.Equal(got, []string{"requirements.txt"}) {
		t.Errorf("unresolved = %v, want [requirements.txt]\n%s", got, warn.Drain(ctx))
	}
}

// writeWheel writes a pure-Python wheel name-version into dir with the given
// Requires-Dist lines.
func writeWheel(t *testing.T, dir, name, version string, requires ...string) {
	t.Helper()
	meta := "Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\n"
	for _, r := range requires {
		meta += "Requires-Dist: " + r + "\n"
	}
	info := name + "-" + version + ".dist-info/"
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, body := range map[string]string{
		name + "/__init__.py": "",
		info + "METADATA":     meta,
		info + "WHEEL":        "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
		info + "RECORD":       "",
	} {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+"-"+version+"-py3-none-any.whl"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// An unlocked pyproject's extras are resolved with their trees, since their
// direct names reach the scan anyway. An extra that cannot resolve without a
// build keeps the base tree and leaves the manifest unresolved.
func TestUVResolvesOptionalDependencies(t *testing.T) {
	realToolsOnly(t, "uv", "python3")
	dist := t.TempDir()
	marker := filepath.Join(t.TempDir(), "marker")
	writeWheel(t, dist, "basepkg", "1.0")
	writeWheel(t, dist, "extrapkg", "1.0", "transdep==1.0")
	writeWheel(t, dist, "transdep", "1.0")
	evilSdist(t, dist, marker)
	t.Setenv("UV_NO_INDEX", "1")
	t.Setenv("UV_FIND_LINKS", dist)
	pp := func(extra string) string {
		return "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.8\"\ndependencies = [\"basepkg==1.0\"]\n" +
			"[project.optional-dependencies]\ncli = [\"" + extra + "\"]\n"
	}
	for name, tc := range map[string]struct {
		extra      string
		want       []string
		unresolved []string
	}{
		"extra resolves":      {"extrapkg==1.0", []string{"basepkg", "extrapkg", "transdep"}, nil},
		"extra needs a build": {"evilpkg==1.0", []string{"basepkg"}, []string{"pyproject.toml"}},
	} {
		t.Run(name, func(t *testing.T) {
			proj := t.TempDir()
			writeTree(t, proj, map[string]string{"pyproject.toml": pp(tc.extra)})
			ctx := warn.NewContext(context.Background(), false)
			pkgs, err := Catalog(ctx, proj, Options{SkipVersionLookup: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			assertNotRun(t, marker)
			got := map[string]string{}
			for _, p := range pkgs {
				got[p.Name] = p.Version
			}
			for _, w := range tc.want {
				if got[w] != "1.0" {
					t.Errorf("%s not resolved to 1.0: %v", w, got)
				}
			}
			if u := warn.Unresolved(ctx); !slices.Equal(u, tc.unresolved) {
				t.Errorf("unresolved = %v, want %v\n%s", u, tc.unresolved, warn.Drain(ctx))
			}
		})
	}
}
