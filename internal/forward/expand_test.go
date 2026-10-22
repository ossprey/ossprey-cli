package forward

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/trust"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// expressTree is what `npm install express` brings in, shortened: the named
// package and two dependencies.
func expressTree(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
	return []catalog.Resolved{
		{Name: "express", Version: "5.1.0", Registry: "https://registry.npmjs.org/express/-/express-5.1.0.tgz"},
		{Name: "accepts", Version: "2.0.0", Registry: "https://registry.npmjs.org/accepts/-/accepts-2.0.0.tgz"},
		{Name: "body-parser", Version: "2.2.0", Registry: "https://registry.npmjs.org/body-parser/-/body-parser-2.2.0.tgz"},
	}, nil
}

// verboseOutput is quietOutput with OSSPREY_VERBOSE set, for asserting on
// the narration a clean install prints only then.
func verboseOutput(t *testing.T, ctx context.Context, opts Options) (string, error) {
	t.Helper()
	for _, k := range []string{"FORCE_COLOR", "CLICOLOR_FORCE", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE"} {
		t.Setenv(k, "")
	}
	t.Setenv("OSSPREY_VERBOSE", "1")
	var buf bytes.Buffer
	oldErr, oldProg := errOut, progressOut
	errOut, progressOut = &buf, &buf
	t.Cleanup(func() { errOut, progressOut = oldErr, oldProg })
	err := Run(ctx, opts)
	return buf.String(), err
}

func checkedSpecs(t *testing.T) (*[]check.Spec, func(context.Context, check.Options) (*ossbom.SBOM, error)) {
	t.Helper()
	var got []check.Spec
	return &got, func(_ context.Context, opts check.Options) (*ossbom.SBOM, error) {
		got = opts.Specs
		s := ossbom.New(ossbom.Environment{})
		for _, sp := range opts.Specs {
			s.AddComponent(ossbom.Component{Name: sp.Name, Version: sp.Version, Type: sp.Ecosystem})
		}
		return s, nil
	}
}

// The case the issue opens with: a named install checks what the manager
// installs, not the one package typed, and the named package is checked at
// the release the resolver picked rather than the registry's latest.
func TestRun_NamedInstall_ChecksTheResolvedTree(t *testing.T) {
	ex := &stubExec{}
	got, chk := checkedSpecs(t)
	swap(t, ex.fn, chk)
	swapExpand(t, expressTree)

	out, err := verboseOutput(t, context.Background(), Options{
		Bin: "npm", Args: []string{"install", "express"},
		ResolveLatest: func(context.Context, string, string) (string, error) {
			t.Error("the registry was asked for a version the resolver already picked")
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []check.Spec{
		{Ecosystem: "npm", Name: "express", Version: "5.1.0"},
		{Ecosystem: "npm", Name: "accepts", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "body-parser", Version: "2.2.0"},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("checked %+v, want %+v", *got, want)
	}
	if !ex.called {
		t.Error("clean install was not forwarded")
	}
	if !strings.Contains(out, "no malware found in 3 packages (1 requested + 2 dependencies), forwarding to npm") {
		t.Errorf("verdict does not say what it covered:\n%s", out)
	}
}

// A malicious package planted as a dependency blocks the install that never
// named it.
func TestRun_NamedInstall_MalwareInADependencyBlocks(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
		s := ossbom.New(ossbom.Environment{})
		s.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:npm/body-parser@2.2.0", "bad"))
		return s, nil
	})
	swapExpand(t, expressTree)

	out, err := quietOutput(t, context.Background(), Options{Bin: "npm", Args: []string{"install", "express"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("blocked install ran the manager")
	}
	if !strings.Contains(out, "body-parser:2.2.0 contains malware") {
		t.Errorf("block does not name the dependency:\n%s", out)
	}
}

// When the dry run cannot be had, the install goes ahead on the named
// packages alone — resolved as before — and one line says so even when
// quiet: a fail-open must never also be silent.
func TestRun_NamedInstall_ExpansionFailsOpenOutLoud(t *testing.T) {
	ex := &stubExec{}
	got, chk := checkedSpecs(t)
	swap(t, ex.fn, chk)
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return nil, errors.New("npm: timed out after 2m0s")
	})

	out, err := quietOutput(t, warn.NewContext(context.Background(), false), Options{
		Bin: "npm", Args: []string{"install", "express"},
		ResolveLatest: func(context.Context, string, string) (string, error) { return "5.1.0", nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := []check.Spec{{Ecosystem: "npm", Name: "express", Version: "5.1.0"}}; !reflect.DeepEqual(*got, want) {
		t.Errorf("checked %+v, want %+v", *got, want)
	}
	if !ex.called {
		t.Error("install was not forwarded")
	}
	want := "ossprey: warning: could not resolve the dependencies of express (npm: timed out after 2m0s); checking the named packages only\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// Verbose, the fallback's verdict says the tree was not resolved.
func TestRun_NamedInstall_UnexpandedVerdictSaysSo(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
		s := ossbom.New(ossbom.Environment{})
		s.AddComponent(ossbom.Component{Name: "express", Version: "5.1.0", Type: "npm"})
		return s, nil
	})
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return nil, errors.New("no resolver on PATH (npm)")
	})
	out, err := verboseOutput(t, context.Background(), Options{
		Bin: "npm", Args: []string{"install", "express@5.1.0"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "no malware found in 1 package (1 requested; dependencies not resolved), forwarding to npm") {
		t.Errorf("verdict does not say the tree was not resolved:\n%s", out)
	}
}

// A dependency the project's lockfile already pinned is not what this install
// brings in; a package from a trusted source is neither checked nor sent,
// now that the resolver has said where it comes from.
func TestResolveNamed_SkipsLockedAndTrustedDependencies(t *testing.T) {
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return []catalog.Resolved{
			{Name: "express", Version: "5.1.0", Locked: true},
			{Name: "accepts", Version: "2.0.0", Locked: true},
			{Name: "@acme/core", Version: "1.0.0", Registry: "https://npm.acme.internal/@acme/core/-/core-1.0.0.tgz"},
			{Name: "mime", Version: "2.0.0", Registry: "https://npm.acme.internal/mime/-/mime-2.0.0.tgz"},
			{Name: "body-parser", Version: "2.2.0"},
		}, nil
	})
	m, _ := Lookup("npm")
	parsed := ParseSpecs(m, []string{"express"})
	ctx := warn.NewContext(context.Background(), true)
	set := resolveNamed(ctx, m, Options{
		Trust: trust.Policy{NpmScopes: []string{"@acme"}, Registries: []string{"https://npm.acme.internal/"}},
	}, 1, parsed, nil)

	want := []check.Spec{
		{Ecosystem: "npm", Name: "express", Version: "5.1.0"},
		{Ecosystem: "npm", Name: "body-parser", Version: "2.2.0"},
	}
	if !reflect.DeepEqual(set.specs, want) {
		t.Errorf("specs = %+v, want %+v", set.specs, want)
	}
	if set.named != 1 || set.deps != 1 || !set.expanded {
		t.Errorf("counts = %+v", set)
	}
	if drained := warn.Drain(ctx); !strings.Contains(drained, "@acme/core@1.0.0") || !strings.Contains(drained, "mime@2.0.0") {
		t.Errorf("trusted dependencies not recorded:\n%s", drained)
	}
}

// A named package the resolver did not report (a tree with nothing to say
// about it) still gets checked, resolved as before.
func TestResolveNamed_NamedPackageMissingFromTreeIsResolved(t *testing.T) {
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "urllib3", Version: "2.3.0"}}, nil
	})
	m, _ := Lookup("pip")
	parsed := ParseSpecs(m, []string{"Requests"})
	asked := ""
	set := resolveNamed(context.Background(), m, Options{}, 1, parsed, func(_ context.Context, _, name, _ string) (string, error) {
		asked = name
		return "2.32.3", nil
	})
	if asked != "Requests" {
		t.Errorf("registry asked for %q, want Requests", asked)
	}
	want := []check.Spec{
		{Ecosystem: "pypi", Name: "urllib3", Version: "2.3.0"},
		{Ecosystem: "pypi", Name: "Requests", Version: "2.32.3"},
	}
	if !reflect.DeepEqual(set.specs, want) {
		t.Errorf("specs = %+v, want %+v", set.specs, want)
	}
	if set.named != 1 || set.deps != 1 {
		t.Errorf("counts = %+v", set)
	}
}

// PyPI names match canonically: pip reports `pyyaml` for `PyYAML`.
func TestResolveNamed_PyPINamesMatchCanonically(t *testing.T) {
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "typing-extensions", Version: "4.12.0"}}, nil
	})
	m, _ := Lookup("pip")
	parsed := ParseSpecs(m, []string{"Typing_Extensions>=4"})
	set := resolveNamed(context.Background(), m, Options{}, 1, parsed, func(context.Context, string, string, string) (string, error) {
		t.Error("the registry was asked for a package the resolver reported")
		return "", nil
	})
	if set.named != 1 || set.deps != 0 || len(set.specs) != 1 {
		t.Errorf("set = %+v", set)
	}
}

// A tool run fetches one package and runs it, dependencies included, so it
// is expanded like any named install: `npx cowsay` checks cowsay and what
// cowsay pulls in, and a malicious dependency blocks the run.
func TestRun_ToolRun_ExpandsTheFetchedPackage(t *testing.T) {
	ex := &stubExec{}
	got, chk := checkedSpecs(t)
	swap(t, ex.fn, chk)
	var seen installArgs
	swapExpand(t, func(_ context.Context, _ *Manager, _ []string, _ int, parsed installArgs) ([]catalog.Resolved, error) {
		seen = parsed
		return []catalog.Resolved{
			{Name: "cowsay", Version: "1.6.0"},
			{Name: "yargs", Version: "15.4.1"},
		}, nil
	})
	if err := Run(context.Background(), Options{Bin: "npx", Args: []string{"cowsay@1.6.0", "moo"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !seen.ToolRun {
		t.Error("the expansion was not told this is a tool run")
	}
	want := []check.Spec{
		{Ecosystem: "npm", Name: "cowsay", Version: "1.6.0"},
		{Ecosystem: "npm", Name: "yargs", Version: "15.4.1"},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("checked %+v, want %+v", *got, want)
	}
	if !ex.called {
		t.Error("clean run was not forwarded")
	}
}

func TestRun_ToolRun_MalwareInADependencyBlocks(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
		s := ossbom.New(ossbom.Environment{})
		s.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:npm/yargs@15.4.1", "bad"))
		return s, nil
	})
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"}, {Name: "yargs", Version: "15.4.1"}}, nil
	})
	err := Run(context.Background(), Options{Bin: "npx", Args: []string{"cowsay", "moo"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("blocked run ran npx")
	}
}

// A tool run resolves with no project context — npx installs into its own
// cache, never into the project beside it — and none of the program's own
// argv is read as a resolver flag.
func TestExpandInstall_ToolRunHasNoProjectContext(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(cwd) })
	os.WriteFile("package.json", []byte("{}"), 0o644)
	os.WriteFile("package-lock.json", []byte(`{"lockfileVersion":3,"packages":{}}`), 0o644)

	var gotDir, gotConfig string
	var gotSpecs, gotFlags []string
	old, oldCached := resolveNpmFn, npxCachedFn
	resolveNpmFn = func(_ context.Context, projectDir, configDir string, specs, flags []string) ([]catalog.Resolved, error) {
		gotDir, gotConfig, gotSpecs, gotFlags = projectDir, configDir, specs, flags
		return nil, nil
	}
	var cacheDir string
	var cachePackages []string
	npxCachedFn = func(dir string, packages []string) ([]catalog.Resolved, error) {
		cacheDir, cachePackages = dir, packages
		return nil, nil
	}
	t.Cleanup(func() { resolveNpmFn, npxCachedFn = old, oldCached })

	m, _ := Lookup("npm")
	args := []string{"exec", "cowsay@1.6.0", "--", "--legacy-peer-deps", "--registry", "https://evil.example", "moo"}
	start, ok := m.toolRunAt(args)
	if !ok {
		t.Fatal("npm exec not seen as a tool run")
	}
	parsed := m.parseRun(args[start:])
	parsed.ToolRun = true
	if _, err := expandInstall(context.Background(), m, args, start, parsed); err != nil {
		t.Fatal(err)
	}
	if gotDir != "" {
		t.Errorf("project context %q, want none", gotDir)
	}
	// No project context, but npm reads this project's .npmrc for the run.
	if !sameDir(t, gotConfig, dir) {
		t.Errorf("config dir %q, want %q", gotConfig, dir)
	}
	if !reflect.DeepEqual(gotSpecs, []string{"cowsay@1.6.0"}) {
		t.Errorf("specs = %v", gotSpecs)
	}
	if gotFlags != nil {
		t.Errorf("flags = %v, want none from the program's argv", gotFlags)
	}

	// The .npmrc npm reads follows its global mode and --prefix, as npm's own
	// parse reports them; the other resolution options npm attributes to
	// itself reach the dry run too, and the program's `--before` does not.
	for _, tt := range []struct {
		args       []string
		wantConfig string
		wantFlags  []string
	}{
		{[]string{"exec", "-g", "cowsay@1.6.0"}, "", nil},
		{[]string{"exec", "--location=global", "cowsay@1.6.0"}, "", nil},
		{[]string{"exec", "--prefix", "../other", "cowsay@1.6.0"}, absPath("../other"), nil},
		{[]string{"--omit=dev", "exec", "--before=2024-01-01", "--tag", "beta", "--legacy-peer-deps", "cowsay@1.6.0", "--", "--before=x"},
			dir, []string{"--before=2024-01-01", "--legacy-peer-deps", "--omit=dev", "--tag=beta"}},
		{[]string{"exec", "--globalconfig", "corp.npmrc", "cowsay@1.6.0"}, dir, []string{"--globalconfig=" + absPath("corp.npmrc")}},
	} {
		gotConfig, gotFlags = "unset", nil
		parsed := m.parseRun(tt.args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), m, tt.args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if tt.wantConfig == "" || gotConfig == "" {
			if gotConfig != tt.wantConfig {
				t.Errorf("%v: config dir %q, want %q", tt.args, gotConfig, tt.wantConfig)
			}
		} else if gotConfig != tt.wantConfig && !sameDir(t, gotConfig, tt.wantConfig) {
			t.Errorf("%v: config dir %q, want %q", tt.args, gotConfig, tt.wantConfig)
		}
		if !reflect.DeepEqual(gotFlags, tt.wantFlags) {
			t.Errorf("%v: flags = %v, want %v", tt.args, gotFlags, tt.wantFlags)
		}
	}

	// The npx cache is looked up under the packages as typed (the --package
	// values, else the command) in npm's cache: --cache, with nopt's home
	// expansion, else the default.
	home, _ := os.UserHomeDir()
	for _, tt := range []struct {
		args         []string
		wantCache    string
		wantPackages []string
	}{
		{[]string{"exec", "cowsay@1.6.0", "--", "moo"}, filepath.Join(home, ".npm"), []string{"cowsay@1.6.0"}},
		{[]string{"exec", "--cache", "~/c", "--package=cowsay@1.6.0", "--package", "left-pad", "--", "cowsay"}, filepath.Join(home, "c"), []string{"cowsay@1.6.0", "left-pad"}},
	} {
		cacheDir, cachePackages = "", nil
		parsed := m.parseRun(tt.args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), m, tt.args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && cacheDir != tt.wantCache {
			t.Errorf("%v: npx cache looked up in %q, want %q", tt.args, cacheDir, tt.wantCache)
		}
		if !reflect.DeepEqual(cachePackages, tt.wantPackages) {
			t.Errorf("%v: npx cache keyed by %v, want %v", tt.args, cachePackages, tt.wantPackages)
		}
	}

	// A home path in an npm option is nopt's: `~/x` is the home directory.
	args = []string{"exec", "--userconfig=~/u.npmrc", "--globalconfig", "~/g.npmrc", "cowsay@1.6.0"}
	parsed = m.parseRun(args)
	parsed.ToolRun = true
	if _, err := expandInstall(context.Background(), m, args, 0, parsed); err != nil {
		t.Fatal(err)
	}
	if want := []string{"--globalconfig=" + filepath.Join(home, "g.npmrc"), "--userconfig", filepath.Join(home, "u.npmrc")}; !reflect.DeepEqual(gotFlags, want) {
		t.Errorf("home paths: flags = %v, want %v", gotFlags, want)
	}

	// An explicit tag on the spec is what npm fetches, whatever --tag says,
	// so the dry run sees the token as typed.
	for _, args := range [][]string{
		{"exec", "--tag=beta", "cowsay@latest", "--", "moo"},
		{"exec", "--tag=beta", "--package=cowsay@latest", "--", "cowsay"},
	} {
		gotSpecs, gotFlags = nil, nil
		parsed := m.parseRun(args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), m, args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotSpecs, []string{"cowsay@latest"}) || !reflect.DeepEqual(gotFlags, []string{"--tag=beta"}) {
			t.Errorf("%v: specs = %v, flags = %v", args, gotSpecs, gotFlags)
		}
	}

	// A registry npm itself reads is the one the dry run resolves against:
	// npx fetches from it, so a check against the default registry would
	// check a different package. npm's own parse decides which --registry is
	// npm's; the program's is behind the "--" npx inserts before the command.
	npx, _ := Lookup("npx")
	args = []string{"--registry=https://npm.acme.internal/", "cowsay", "--registry", "https://evil.example"}
	parsed = npx.parseRun(args)
	parsed.ToolRun = true
	if _, err := expandInstall(context.Background(), npx, args, 0, parsed); err != nil {
		t.Fatal(err)
	}
	if want := []string{"--registry", "https://npm.acme.internal/"}; !reflect.DeepEqual(gotFlags, want) {
		t.Errorf("flags = %v, want %v", gotFlags, want)
	}
	if !reflect.DeepEqual(gotSpecs, []string{"cowsay"}) {
		t.Errorf("specs = %v", gotSpecs)
	}

	// A --userconfig npm reads is made absolute for the dry run, which runs
	// in another directory.
	args = []string{"--userconfig", "./x.npmrc", "cowsay"}
	parsed = npx.parseRun(args)
	parsed.ToolRun = true
	if _, err := expandInstall(context.Background(), npx, args, 0, parsed); err != nil {
		t.Fatal(err)
	}
	if want := []string{"--userconfig", filepath.Join(dir, "x.npmrc")}; !reflect.DeepEqual(gotFlags, want) {
		t.Errorf("flags = %v, want %v", gotFlags, want)
	}
}

// For uvx, only the flags before the command reach the resolver: an index
// named there matters, `--no-deps` in the program's own argv does not.
func TestExpandInstall_ToolRunReadsOnlyLeadingFlags(t *testing.T) {
	var gotSpecs, gotUV, gotPip []string
	gotDir := "unset"
	old := resolvePythonFn
	resolvePythonFn = func(_ context.Context, dir string, specs, uvFlags, pipFlags []string) ([]catalog.Resolved, error) {
		gotDir, gotSpecs, gotUV, gotPip = dir, specs, uvFlags, pipFlags
		return []catalog.Resolved{{Name: "ruff", Version: "0.6.0"}}, nil
	}
	t.Cleanup(func() { resolvePythonFn = old })

	m, _ := Lookup("uvx")
	args := []string{"--index-url", "https://i.example", "--with", "ruff-lsp", "-q", "ruff@0.6.0", "--no-deps", "--index-url", "x"}
	parsed := parseToolRun(m, args)
	parsed.ToolRun = true
	tree, err := expandInstall(context.Background(), m, args, 0, parsed)
	if err != nil || len(tree) != 1 {
		t.Fatalf("tree = %v, err = %v", tree, err)
	}
	if !reflect.DeepEqual(gotSpecs, []string{"ruff-lsp", "ruff==0.6.0"}) {
		t.Errorf("specs = %v", gotSpecs)
	}
	// uvx reads no project configuration, so neither does the resolver: it
	// runs with no directory, i.e. nowhere a uv.toml could be found.
	if gotDir != "" {
		t.Errorf("resolver dir = %q, want none", gotDir)
	}
	if want := []string{"--index-url", "https://i.example"}; !reflect.DeepEqual(gotUV, want) {
		t.Errorf("uv flags = %v, want %v", gotUV, want)
	}
	// The pip fallback, for a host with no working uv, resolves against the
	// same index, in pip's spelling.
	if want := []string{"--index-url", "https://i.example"}; !reflect.DeepEqual(gotPip, want) {
		t.Errorf("pip flags = %v, want %v", gotPip, want)
	}

	// --default-index replaces the default index, as pip's --index-url does,
	// and --constraints is pip's --constraint, so the fallback gets them in
	// pip's spelling. Paths are made absolute, since the resolver runs
	// elsewhere; a --find-links URL is left alone.
	args = []string{"--default-index", "https://d.example", "--constraints", "c.txt", "-f", "https://w.example/", "ruff"}
	parsed = parseToolRun(m, args)
	parsed.ToolRun = true
	if _, err := expandInstall(context.Background(), m, args, 0, parsed); err != nil {
		t.Fatal(err)
	}
	if want := []string{"--index-url", "https://d.example", "--constraint", absPath("c.txt"), "-f", "https://w.example/"}; !reflect.DeepEqual(gotPip, want) {
		t.Errorf("pip flags = %v, want %v", gotPip, want)
	}
	if want := []string{"--default-index", "https://d.example", "--constraints", absPath("c.txt"), "-f", "https://w.example/"}; !reflect.DeepEqual(gotUV, want) {
		t.Errorf("uv flags = %v, want %v", gotUV, want)
	}
}

// A uv command whose flags pip cannot honour is resolved by uv alone. An
// added index: uv takes a package from the first index that has it, pip the
// best version across every index, so pip's dry run could check a release
// uv does not install — or resolve a private-only name from PyPI, where a
// squatted copy may wait. --overrides, --resolution and the like change the
// pick and have no pip spelling. With no working uv such a command is not
// resolved at all, and the names are checked with the warning.
func TestExpandInstall_UVOnlyFlagsAreResolvedByUVOnly(t *testing.T) {
	var gotUV []string
	pipCalled := false
	old, oldUV := resolvePythonFn, resolveWithUVFn
	resolvePythonFn = func(_ context.Context, _ string, _, _, _ []string) ([]catalog.Resolved, error) {
		pipCalled = true
		return []catalog.Resolved{{Name: "ruff", Version: "0.6.0"}}, nil
	}
	resolveWithUVFn = func(_ context.Context, _ string, _, uvFlags []string) ([]catalog.Resolved, error) {
		gotUV = uvFlags
		return nil, catalog.ErrNeedsUV
	}
	t.Cleanup(func() { resolvePythonFn, resolveWithUVFn = old, oldUV })

	uvx, _ := Lookup("uvx")
	uv, _ := Lookup("uv")
	tests := []struct {
		name   string
		m      *Manager
		args   []string
		wantUV []string
	}{
		{"uvx --index", uvx, []string{"--index", "https://i.example", "--default-index", "https://d.example", "ruff"},
			[]string{"--index", "https://i.example", "--default-index", "https://d.example"}},
		{"uvx --extra-index-url", uvx, []string{"--extra-index-url=https://i.example", "ruff"},
			[]string{"--extra-index-url=https://i.example"}},
		{"uv pip install --index", uv, []string{"pip", "install", "--index", "https://i.example", "ruff"},
			[]string{"--index", "https://i.example"}},
		{"uv add --extra-index-url", uv, []string{"add", "--extra-index-url", "https://i.example", "ruff"},
			[]string{"--extra-index-url", "https://i.example"}},
		{"uvx --overrides", uvx, []string{"--overrides", "o.txt", "ruff"},
			[]string{"--overrides", absPath("o.txt")}},
		{"uvx --resolution", uvx, []string{"--resolution=lowest", "ruff"},
			[]string{"--resolution=lowest"}},
		{"uv pip install --exclude-newer", uv, []string{"pip", "install", "--exclude-newer", "2024-01-01", "ruff"},
			[]string{"--exclude-newer", "2024-01-01"}},
	}
	for _, tt := range tests {
		gotUV, pipCalled = nil, false
		var parsed installArgs
		start := 0
		if tt.m == uvx {
			parsed = parseToolRun(tt.m, tt.args)
			parsed.ToolRun = true
		} else {
			start, _ = tt.m.installAt(tt.args)
			parsed = ParseSpecs(tt.m, tt.args[start:])
		}
		tree, err := expandInstall(context.Background(), tt.m, tt.args, start, parsed)
		if !errors.Is(err, catalog.ErrNeedsUV) || tree != nil {
			t.Errorf("%s: tree = %v, err = %v, want ErrNeedsUV", tt.name, tree, err)
		}
		if pipCalled {
			t.Errorf("%s: pip fallback was offered", tt.name)
		}
		if !reflect.DeepEqual(gotUV, tt.wantUV) {
			t.Errorf("%s: uv flags = %v, want %v", tt.name, gotUV, tt.wantUV)
		}
	}

	// An index the command does not add stays on the fallback path: pip's
	// own --extra-index-url is pip's rule, and --index-url replaces the
	// default for both.
	pip, _ := Lookup("pip")
	for _, tt := range []struct {
		m    *Manager
		args []string
	}{
		{pip, []string{"install", "--extra-index-url", "https://i.example", "ruff"}},
		{uv, []string{"pip", "install", "--index-url", "https://i.example", "ruff"}},
	} {
		pipCalled = false
		start, _ := tt.m.installAt(tt.args)
		_, err := expandInstall(context.Background(), tt.m, tt.args, start, ParseSpecs(tt.m, tt.args[start:]))
		if err != nil || !pipCalled {
			t.Errorf("%s %v: err = %v, pip fallback called = %v", tt.m.Bin, tt.args, err, pipCalled)
		}
	}
}

// The resolver gets the packages as the user wrote them — a range, extras, a
// marker — since the parsed spec keeps only a name and an exact pin. uv's
// and poetry's `name@version` is not PEP 508, so it is rewritten.
func TestSpecTokens(t *testing.T) {
	tests := []struct {
		bin  string
		args []string
		want []string
	}{
		{"npm", []string{"express@^4", "@types/node", "lodash@4.17.21", "x@npm:evil@1.0.0"},
			[]string{"express@^4", "@types/node", "lodash@4.17.21", "x@npm:evil@1.0.0"}},
		{"pip", []string{"requests[socks]>=2,<3", "Flask==3.0.0", "pyyaml; python_version>'3'"},
			[]string{"requests[socks]>=2,<3", "Flask==3.0.0", "pyyaml; python_version>'3'"}},
		{"poetry", []string{"flask@^3.0", "requests@2.32.3", "httpx"},
			[]string{"flask", "requests==2.32.3", "httpx"}},
		{"uv", []string{"httpx@latest"}, []string{"httpx"}},
	}
	for _, tt := range tests {
		m, _ := Lookup(tt.bin)
		got := specTokens(m, ParseSpecs(m, tt.args))
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s %v: tokens = %v, want %v", tt.bin, tt.args, got, tt.want)
		}
	}
}

// A spec reconstructed from its parts, for a token the parse did not keep.
func TestReconstructToken(t *testing.T) {
	for _, tt := range []struct {
		spec check.Spec
		want string
	}{
		{check.Spec{Ecosystem: "npm", Name: "a", Version: "1.0.0"}, "a@1.0.0"},
		{check.Spec{Ecosystem: "npm", Name: "a", Constraint: "^1"}, "a@^1"},
		{check.Spec{Ecosystem: "npm", Name: "a"}, "a"},
		{check.Spec{Ecosystem: "pypi", Name: "a", Version: "1.0"}, "a==1.0"},
		{check.Spec{Ecosystem: "pypi", Name: "a"}, "a"},
	} {
		if got := reconstructToken(tt.spec); got != tt.want {
			t.Errorf("%+v: got %q, want %q", tt.spec, got, tt.want)
		}
	}
}

// Only the flags that change what is resolved are handed to the resolver,
// with the values the manager would read, renamed where the resolver spells
// them differently.
func TestResolverFlags(t *testing.T) {
	npm, _ := Lookup("npm")
	pnpm, _ := Lookup("pnpm")
	pip, _ := Lookup("pip")
	uv, _ := Lookup("uv")

	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{"npm keeps peer and omit flags, drops the rest",
			npmResolveFlags(npm, []string{"--save-dev", "--legacy-peer-deps", "--omit", "dev", "--registry=https://r.example", "-w", "web", "express"}),
			[]string{"--legacy-peer-deps", "--omit", "dev", "--registry=https://r.example"}},
		{"pnpm passes nothing to npm",
			npmResolveFlags(pnpm, []string{"--filter", "web", "--save-dev", "express"}), nil},
		{"pip to pip keeps index and constraint flags",
			pipResolveFlags(pip, []string{"--pre", "-i", "https://i.example", "-c", "c.txt", "-t", "vendor", "--trusted-host", "i.example", "flask"}),
			[]string{"--pre", "-i", "https://i.example", "-c", "c.txt", "--trusted-host", "i.example"}},
		{"pip to uv renames trusted-host",
			uvResolveFlags(pip, []string{"--trusted-host", "i.example", "--platform", "manylinux", "flask"}),
			[]string{"--allow-insecure-host", "i.example"}},
		{"uv to uv keeps its own",
			uvResolveFlags(uv, []string{"--index", "https://i.example", "--prerelease=allow", "--dev", "httpx"}),
			[]string{"--index", "https://i.example", "--prerelease=allow"}},
		{"uv to pip renames the default index and constraints, drops what pip cannot honour",
			pipResolveFlags(uv, []string{"--index", "https://i.example", "--extra-index-url", "https://e.example", "--default-index=https://d.example", "--resolution", "lowest", "--constraints", "c.txt", "--overrides=o.txt", "httpx"}),
			[]string{"--index-url=https://d.example", "--constraint", "c.txt"}},
		{"npm makes --userconfig and --globalconfig absolute",
			npmResolveFlags(npm, []string{"--userconfig", "u.npmrc", "--userconfig=./v.npmrc", "--globalconfig", "g.npmrc", "express"}),
			[]string{"--userconfig", absPath("u.npmrc"), "--userconfig=" + absPath("v.npmrc"), "--globalconfig", absPath("g.npmrc")}},
	}
	for _, tt := range tests {
		if !reflect.DeepEqual(tt.got, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

// `--no-deps` installs the names alone, so there is no tree to resolve.
func TestExpandInstall_NoDepsResolvesNothing(t *testing.T) {
	for _, bin := range []string{"pip", "uv"} {
		m, _ := Lookup(bin)
		args := []string{"install", "--no-deps", "flask"}
		if bin == "uv" {
			args = []string{"pip", "install", "--no-deps", "flask"}
		}
		start, _ := m.installAt(args)
		tree, err := expandInstall(context.Background(), m, args, start, ParseSpecs(m, args[start:]))
		if tree != nil || err != nil {
			t.Errorf("%s: got (%v, %v), want nothing to resolve", bin, tree, err)
		}
	}
}

// The project is the context for an npm-side resolve only when the install
// will update its lockfile and npm can read that lockfile.
func TestNpmProjectDir(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(cwd) })

	npm, _ := Lookup("npm")
	pnpm, _ := Lookup("pnpm")
	if got := npmProjectDir(npm, []string{"install", "express"}); got != "" {
		t.Errorf("no package.json: got %q, want none", got)
	}
	os.WriteFile("package.json", []byte("{}"), 0o644)
	if got := npmProjectDir(npm, []string{"install", "express"}); got != "." {
		t.Errorf("project here: got %q, want .", got)
	}
	if got := npmProjectDir(npm, []string{"install", "-g", "express"}); got != "" {
		t.Errorf("global: got %q, want none", got)
	}
	if got := npmProjectDir(npm, []string{"--prefix", "../other", "install", "express"}); got != "" {
		t.Errorf("redirected: got %q, want none", got)
	}
	os.WriteFile("pnpm-lock.yaml", []byte(""), 0o644)
	if got := npmProjectDir(pnpm, []string{"add", "express"}); got != "" {
		t.Errorf("pnpm lockfile npm cannot read: got %q, want none", got)
	}
}

// Passive, the fallback line still prints when quiet — a fail-open is never
// silent — but only once the manager has exited, since from the moment it
// starts the terminal is its.
func TestRun_PassiveNamedInstall_ExpansionFallbackPrintsAfterTheManager(t *testing.T) {
	printedBeforeManager := ""
	execFn := func(context.Context, string, []string) error {
		printedBeforeManager = errOut.(*bytes.Buffer).String()
		return nil
	}
	swap(t, execFn, cleanSBOM)
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return nil, errors.New("no resolver on PATH (uv or python)")
	})

	out, err := quietOutput(t, warn.NewContext(context.Background(), false), Options{
		Bin: "pip", Args: []string{"install", "flask"}, Passive: true,
		ResolveLatest: func(context.Context, string, string) (string, error) { return "3.0.0", nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if printedBeforeManager != "" {
		t.Errorf("printed beside the manager:\n%s", printedBeforeManager)
	}
	want := "ossprey: warning: could not resolve the dependencies of flask (no resolver on PATH (uv or python)); checking the named packages only\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}

// The dry run stages the .npmrc npm itself would read as project
// configuration: none in global mode, the --prefix when given, else the one
// at npm's local prefix — the nearest directory up from the working
// directory with a package.json or node_modules, so a run from a project
// subdirectory gets the project's file, not the subdirectory's.
func TestNpmConfigDir(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, "proj")
	sub := filepath.Join(proj, "sub")
	bare := filepath.Join(root, "bare")
	for _, d := range []string{sub, bare} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(proj, "package.json"), []byte("{}"), 0o644)
	npm, _ := Lookup("npm")
	pnpm, _ := Lookup("pnpm")

	tests := []struct {
		name string
		cwd  string
		m    *Manager
		args []string
		want string
	}{
		{"project root", proj, npm, []string{"install", "x"}, proj},
		{"project subdirectory", sub, npm, []string{"install", "x"}, proj},
		{"no project at all", bare, npm, []string{"install", "x"}, bare},
		{"global", sub, npm, []string{"install", "-g", "x"}, ""},
		{"--global", sub, npm, []string{"install", "--global", "x"}, ""},
		{"--location=global", sub, npm, []string{"install", "--location=global", "x"}, ""},
		{"--location global", sub, npm, []string{"install", "--location", "global", "x"}, ""},
		{"--location=project", sub, npm, []string{"install", "--location=project", "x"}, proj},
		{"--prefix", sub, npm, []string{"--prefix", "..", "install", "x"}, proj},
		{"-C after the verb", bare, npm, []string{"install", "-C", "../proj", "x"}, proj},
		// npm's last-wins and negation rules: these are local installs.
		{"--global=false", sub, npm, []string{"install", "--global=false", "x"}, proj},
		{"--global then --no-global", sub, npm, []string{"install", "--global", "--no-global", "x"}, proj},
		{"--location overridden", sub, npm, []string{"install", "--location=global", "--location=project", "x"}, proj},
		{"--no-global then -g", sub, npm, []string{"install", "--no-global", "-g", "x"}, ""},
		{"pnpm reads the project's", sub, pnpm, []string{"add", "x"}, proj},
	}
	for _, tt := range tests {
		t.Chdir(tt.cwd)
		got := npmConfigDir(tt.m, tt.args)
		if tt.want == "" || got == "" {
			if got != tt.want {
				t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
			}
			continue
		}
		if !sameDir(t, got, tt.want) {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestAbsFlagValues(t *testing.T) {
	got := absFlagValues([]string{"-c", "c.txt", "--overrides=o.txt", "-f", "https://w.example/", "--pre", "--index-url", "https://i.example"},
		flagSet("-c", "--overrides", "-f"), ".")
	want := []string{"-c", absPath("c.txt"), "--overrides=" + absPath("o.txt"), "-f", "https://w.example/", "--pre", "--index-url", "https://i.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// Against another base, as a command under --directory resolves; an
	// absolute path is left alone.
	got = absFlagValues([]string{"-c", "c.txt", "--overrides=" + absPath("o.txt")}, flagSet("-c", "--overrides"), "sub")
	want = []string{"-c", absPath("sub/c.txt"), "--overrides=" + absPath("o.txt")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// uv's global options sit before the verb and change what a resolve finds:
// they reach the resolver, --config-file and --offline make the command
// uv-only, and --directory/--project set where a named install resolves. A
// path-shaped interpreter is made absolute for a tool run, a version or a
// name left alone.
func TestExpandInstall_UVGlobalOptionsAndInterpreterPaths(t *testing.T) {
	var gotDir, gotUV []string
	uvOnly := false
	old, oldUV := resolvePythonFn, resolveWithUVFn
	resolvePythonFn = func(_ context.Context, dir string, _, uvFlags, _ []string) ([]catalog.Resolved, error) {
		gotDir, gotUV, uvOnly = []string{dir}, uvFlags, false
		return nil, nil
	}
	resolveWithUVFn = func(_ context.Context, dir string, _, uvFlags []string) ([]catalog.Resolved, error) {
		gotDir, gotUV, uvOnly = []string{dir}, uvFlags, true
		return nil, nil
	}
	t.Cleanup(func() { resolvePythonFn, resolveWithUVFn = old, oldUV })

	uv, _ := Lookup("uv")
	uvx, _ := Lookup("uvx")
	tests := []struct {
		name       string
		m          *Manager
		args       []string
		wantDir    string
		wantUV     []string
		wantUVOnly bool
	}{
		{"config file before tool run", uv, []string{"--config-file", "alt.toml", "tool", "run", "ruff"},
			"", []string{"--config-file", absPath("alt.toml")}, true},
		{"no-config and offline before pip install", uv, []string{"--no-config", "--offline", "pip", "install", "ruff"},
			".", []string{"--no-config", "--offline"}, true},
		{"no-config alone keeps the pip fallback", uv, []string{"--no-config", "pip", "install", "ruff"},
			".", []string{"--no-config"}, false},
		{"--directory before the verb", uv, []string{"--directory", "sub", "pip", "install", "ruff"},
			absPath("sub"), nil, false},
		{"interpreter path", uvx, []string{"-p", ".venv/bin/python", "ruff"},
			"", []string{"-p", absPath(".venv/bin/python")}, true},
		{"interpreter version", uvx, []string{"--python=3.12", "ruff"},
			"", []string{"--python=3.12"}, true},
		{"interpreter name", uvx, []string{"--python", "pypy", "ruff"},
			"", []string{"--python", "pypy"}, true},
		// --directory moves the run before anything else, so its relative
		// paths are read there; the resolver still runs in its scratch dir.
		{"tool run paths under --directory", uvx, []string{"--directory", "sub", "--constraints", "c.txt", "ruff"},
			"", []string{"--constraints", absPath("sub/c.txt")}, false},
		{"global --directory before tool run", uv, []string{"--directory", "sub", "--config-file", "u.toml", "tool", "run", "-c", "c.txt", "ruff"},
			"", []string{"--config-file", absPath("sub/u.toml"), "-c", absPath("sub/c.txt")}, true},
		// --project names a project, not a directory: a tool run reads no
		// project configuration so it is dropped, a named install passes it.
		{"tool run drops --project", uvx, []string{"--project", "p", "-c", "c.txt", "ruff"},
			"", []string{"-c", absPath("c.txt")}, false},
		{"named install passes --project", uv, []string{"--project", "p", "pip", "install", "ruff"},
			".", []string{"--project", absPath("p")}, false},
		{"named install --project after the verb", uv, []string{"pip", "install", "--project", "p", "ruff"},
			".", []string{"--project", absPath("p")}, false},
		// The global part is gathered without touching args: an append into
		// its backing array would overwrite the verb the real uv is given.
		{"global part leaves args intact", uv, []string{"--no-config", "tool", "run", "--with", "httpx", "--with", "rich", "ruff"},
			"", []string{"--no-config"}, false},
		// A short option's value may be attached, as clap and argparse read
		// it; the program's own attached option past the command is not.
		{"attached index", uvx, []string{"-ihttps://i.example", "ruff"},
			"", []string{"-i", "https://i.example"}, false},
		{"attached constraints", uvx, []string{"-cc.txt", "ruff"},
			"", []string{"-c", absPath("c.txt")}, false},
		{"attached interpreter", uvx, []string{"-p3.12", "ruff"},
			"", []string{"-p", "3.12"}, true},
		{"attached option after the command is the program's", uvx, []string{"ruff", "-ihttps://evil.example"},
			"", nil, false},
		{"attached index on a named install", uv, []string{"pip", "install", "-ihttps://i.example", "ruff"},
			".", []string{"-i", "https://i.example"}, false},
		{"attached global cache dir is not a resolver flag", uv, []string{"--no-config", "pip", "install", "-qq", "ruff"},
			".", []string{"--no-config"}, false},
	}
	for _, tt := range tests {
		gotDir, gotUV, uvOnly = nil, nil, false
		var parsed installArgs
		start := 0
		if tt.m == uvx {
			parsed = parseToolRun(tt.m, tt.args)
			parsed.ToolRun = true
		} else if s, ok := tt.m.toolRunAt(tt.args); ok {
			start = s
			parsed = parseToolRun(tt.m, tt.args[start:])
			parsed.ToolRun = true
		} else {
			start, _ = tt.m.installAt(tt.args)
			parsed = ParseSpecs(tt.m, tt.args[start:])
		}
		before := slices.Clone(tt.args)
		if _, err := expandInstall(context.Background(), tt.m, tt.args, start, parsed); err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if !reflect.DeepEqual(tt.args, before) {
			t.Errorf("%s: args changed to %v", tt.name, tt.args)
		}
		if gotDir == nil || gotDir[0] != tt.wantDir {
			t.Errorf("%s: dir = %v, want %q", tt.name, gotDir, tt.wantDir)
		}
		if !reflect.DeepEqual(gotUV, tt.wantUV) {
			t.Errorf("%s: uv flags = %v, want %v", tt.name, gotUV, tt.wantUV)
		}
		if uvOnly != tt.wantUVOnly {
			t.Errorf("%s: uv-only = %v, want %v", tt.name, uvOnly, tt.wantUVOnly)
		}
	}
}

// An attached short value is read everywhere the manager's own parse would
// read it: `-wrich` names a package for a tool run, `-cc.txt` is a
// constraints file and not a package for a named install.
func TestSplitAttachedShorts(t *testing.T) {
	got := splitAttachedShorts([]string{"-cc.txt", "-c=d.txt", "-qq", "--with=x", "-w", "rich", "ruff", "-ievil"}, toolRunValueFlags)
	want := []string{"-c", "c.txt", "-c", "d.txt", "-qq", "--with=x", "-w", "rich", "ruff", "-i", "evil"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	uvx, _ := Lookup("uvx")
	parsed := parseToolRun(uvx, []string{"-wrich", "ruff", "-wnot-a-package"})
	if want := []check.Spec{{Ecosystem: "pypi", Name: "rich"}, {Ecosystem: "pypi", Name: "ruff"}}; !reflect.DeepEqual(parsed.Specs, want) {
		t.Errorf("uvx -wrich ruff: specs = %+v, want %+v", parsed.Specs, want)
	}
	uv, _ := Lookup("uv")
	parsed = ParseSpecs(uv, []string{"-cc.txt", "ruff"})
	if want := []check.Spec{{Ecosystem: "pypi", Name: "ruff"}}; !reflect.DeepEqual(parsed.Specs, want) {
		t.Errorf("uv pip install -cc.txt ruff: specs = %+v, want %+v", parsed.Specs, want)
	}
}

// npm records an optional dependency in the lock whatever the omit policy,
// and leaves it out of an install run with --omit=optional: the check must
// not block such a run on a package it never installs. --include=optional
// restores it.
func TestExpandInstall_NpmOmitOptional(t *testing.T) {
	old, oldInc, oldCached := resolveNpmFn, npmConfigIncludesFn, npxCachedFn
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) { return nil, nil }
	resolveNpmFn = func(context.Context, string, string, []string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "needed", Version: "1.0.0"}, {Name: "extra", Version: "2.0.0", Optional: true},
			{Name: "devonly", Version: "3.0.0", Dev: true}, {Name: "both", Version: "4.0.0", DevOptional: true},
			{Name: "peer", Version: "5.0.0", Peer: true}}, nil
	}
	// npm's configuration includes nothing unless a case says otherwise;
	// asked is how often npm had to be consulted.
	var configured []string
	var configErr error
	asked := 0
	var askedFlags []string
	npmConfigIncludesFn = func(_ context.Context, _ string, flags []string) ([]string, error) {
		asked++
		askedFlags = flags
		return configured, configErr
	}
	t.Cleanup(func() { resolveNpmFn, npmConfigIncludesFn, npxCachedFn = old, oldInc, oldCached })
	m, _ := Lookup("npm")

	names := func(tree []catalog.Resolved) []string {
		var out []string
		for _, r := range tree {
			out = append(out, r.Name)
		}
		return out
	}
	for _, tt := range []struct {
		args    []string
		toolRun bool
		want    []string
	}{
		{[]string{"exec", "cowsay@1.6.0"}, true, []string{"needed", "extra", "devonly", "both", "peer"}},
		{[]string{"exec", "--omit=optional", "cowsay@1.6.0"}, true, []string{"needed", "devonly", "both", "peer"}},
		{[]string{"exec", "--no-optional", "cowsay@1.6.0"}, true, []string{"needed", "devonly", "both", "peer"}},
		{[]string{"exec", "--omit=optional", "--include=optional", "cowsay@1.6.0"}, true, []string{"needed", "extra", "devonly", "both", "peer"}},
		// The boolean's last value wins, --optional counts as an include,
		// and an explicit value is read as nopt reads it, negation included.
		{[]string{"exec", "--no-optional", "--optional", "cowsay@1.6.0"}, true, []string{"needed", "extra", "devonly", "both", "peer"}},
		{[]string{"exec", "--omit=optional", "--optional", "cowsay@1.6.0"}, true, []string{"needed", "extra", "devonly", "both", "peer"}},
		{[]string{"exec", "--optional", "--no-optional", "cowsay@1.6.0"}, true, []string{"needed", "devonly", "both", "peer"}},
		{[]string{"exec", "--optional=false", "cowsay@1.6.0"}, true, []string{"needed", "devonly", "both", "peer"}},
		{[]string{"exec", "--no-optional=false", "cowsay@1.6.0"}, true, []string{"needed", "extra", "devonly", "both", "peer"}},
		// A devOptional package is reached both ways: only omitting both
		// leaves it out. Peers go with --omit=peer.
		{[]string{"exec", "--omit=dev", "cowsay@1.6.0"}, true, []string{"needed", "extra", "both", "peer"}},
		{[]string{"exec", "--omit=dev", "--omit=optional", "cowsay@1.6.0"}, true, []string{"needed", "peer"}},
		{[]string{"exec", "--omit=peer", "cowsay@1.6.0"}, true, []string{"needed", "extra", "devonly", "both"}},
		// A named install reads the whole command, options before the verb
		// included: --include there still wins over --omit after it.
		{[]string{"install", "--omit", "optional", "cowsay"}, false, []string{"needed", "devonly", "both", "peer"}},
		{[]string{"install", "--omit=optional", "--optional", "cowsay"}, false, []string{"needed", "extra", "devonly", "both", "peer"}},
		{[]string{"install", "--optional=false", "cowsay"}, false, []string{"needed", "devonly", "both", "peer"}},
		{[]string{"install", "--no-optional=false", "--omit=optional", "cowsay"}, false, []string{"needed", "extra", "devonly", "both", "peer"}},
		{[]string{"--include=optional", "install", "--omit=optional", "cowsay"}, false, []string{"needed", "extra", "devonly", "both", "peer"}},
		{[]string{"install", "cowsay"}, false, []string{"needed", "extra", "devonly", "both", "peer"}},
	} {
		var parsed installArgs
		start := 0
		if tt.toolRun {
			parsed = m.parseRun(tt.args)
			parsed.ToolRun = true
		} else {
			start, _ = m.installAt(tt.args)
			parsed = ParseSpecs(m, tt.args[start:])
		}
		tree, err := expandInstall(context.Background(), m, tt.args, start, parsed)
		if err != nil {
			t.Fatalf("%v: %v", tt.args, err)
		}
		if got := names(tree); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%v: tree = %v, want %v", tt.args, got, tt.want)
		}
	}

	// An include from npm's configuration wins over an --omit on the line,
	// so npm is asked — only when the line omits something — and when it
	// cannot answer nothing is dropped. The location flags make it read the
	// same project configuration as the command.
	run := func(args []string, toolRun bool) []string {
		var parsed installArgs
		start := 0
		if toolRun {
			parsed = m.parseRun(args)
			parsed.ToolRun = true
		} else {
			start, _ = m.installAt(args)
			parsed = ParseSpecs(m, args[start:])
		}
		tree, err := expandInstall(context.Background(), m, args, start, parsed)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return names(tree)
	}
	asked = 0
	run([]string{"exec", "cowsay@1.6.0"}, true)
	run([]string{"install", "cowsay"}, false)
	if asked != 0 {
		t.Errorf("npm asked about includes %d times for commands that omit nothing", asked)
	}
	configured = []string{"optional", "dev"}
	if got := run([]string{"exec", "--omit=optional", "cowsay@1.6.0"}, true); !reflect.DeepEqual(got, []string{"needed", "extra", "devonly", "both", "peer"}) {
		t.Errorf("configured include=optional over --omit=optional: tree = %v", got)
	}
	if got := run([]string{"install", "--omit=dev", "--omit=peer", "cowsay"}, false); !reflect.DeepEqual(got, []string{"needed", "extra", "devonly", "both"}) {
		t.Errorf("configured include=dev over --omit=dev, peer still omitted: tree = %v", got)
	}
	configured, configErr = nil, errors.New("no npm")
	if got := run([]string{"exec", "--omit=optional", "cowsay@1.6.0"}, true); !reflect.DeepEqual(got, []string{"needed", "extra", "devonly", "both", "peer"}) {
		t.Errorf("npm unavailable: tree = %v, want everything kept", got)
	}
	configErr = nil
	run([]string{"exec", "-g", "--omit=optional", "cowsay@1.6.0"}, true)
	if !slices.Contains(askedFlags, "-g") {
		t.Errorf("global exec asked with flags %v, want -g", askedFlags)
	}
	run([]string{"--prefix", "../o", "install", "--omit=optional", "cowsay"}, false)
	if !slices.Contains(askedFlags, absPath("../o")) {
		t.Errorf("--prefix install asked with flags %v, want the prefix", askedFlags)
	}
}

// npm reuses what an earlier run of the same packages left in its npx cache,
// with the dependencies resolved back then: the check covers that tree as
// well as today's resolution, deduplicated.
func TestExpandInstall_ToolRunCoversTheNpxCache(t *testing.T) {
	old, oldCached := resolveNpmFn, npxCachedFn
	resolveNpmFn = func(context.Context, string, string, []string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"}, {Name: "get-stdin", Version: "8.0.0"}}, nil
	}
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"}, {Name: "get-stdin", Version: "7.0.0"}}, nil
	}
	t.Cleanup(func() { resolveNpmFn, npxCachedFn = old, oldCached })

	m, _ := Lookup("npm")
	args := []string{"exec", "cowsay@1.6.0"}
	parsed := m.parseRun(args)
	parsed.ToolRun = true
	tree, err := expandInstall(context.Background(), m, args, 0, parsed)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range tree {
		got = append(got, r.Name+"@"+r.Version)
	}
	if want := []string{"cowsay@1.6.0", "get-stdin@8.0.0", "get-stdin@7.0.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tree = %v, want %v", got, want)
	}

	// A cache that cannot be read adds nothing and fails nothing.
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) { return nil, errors.New("unreadable") }
	if tree, err := expandInstall(context.Background(), m, args, 0, parsed); err != nil || len(tree) != 2 {
		t.Errorf("unreadable cache: tree = %v, err = %v", tree, err)
	}
}
