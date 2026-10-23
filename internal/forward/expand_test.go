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
	// npm's configuration names no cache unless a case says so; configAsked
	// records the flags npm was asked with.
	oldGet := npmConfigGetFn
	configured := ""
	asked := false
	var configAsked []string
	npmConfigGetFn = func(_ context.Context, _, key string, flags []string) (string, error) {
		if key != "cache" {
			t.Errorf("npm config get %s asked", key)
		}
		asked, configAsked = true, flags
		if configured == "" {
			return "", errors.New("no npm")
		}
		return configured, nil
	}
	t.Cleanup(func() { resolveNpmFn, npxCachedFn, npmConfigGetFn = old, oldCached, oldGet })

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
		// The cache policy and the cache it reads decide what npm resolves
		// against, so they reach the dry run, the path made absolute.
		{[]string{"exec", "--offline", "--prefer-offline", "--cache", "~/c", "cowsay@1.6.0"}, dir,
			[]string{"--cache=" + absPath(expandHome("~/c")), "--offline", "--prefer-offline"}},
		{[]string{"exec", "--prefer-online", "cowsay@1.6.0"}, dir, []string{"--prefer-online"}},
		// A release-age policy picks an older eligible release, like --before.
		{[]string{"exec", "--min-release-age=7", "--min-release-age-exclude", "left-pad", "cowsay@1.6.0"}, dir,
			[]string{"--min-release-age=7", "--min-release-age-exclude=left-pad"}},
		// Workspaces decide where configuration is read, never what the
		// scratch dry run is told: `npm install --workspaces` there fails.
		{[]string{"exec", "--workspaces", "--package=cowsay@1.6.0", "--", "cowsay"}, dir, nil},
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
	// expansion, else what npm's configuration files say, read with the
	// command's own config-file flags, else the default.
	home, _ := os.UserHomeDir()
	for _, tt := range []struct {
		args         []string
		configured   string
		wantCache    string
		wantAsked    bool
		wantFlags    []string
		wantPackages []string
	}{
		{[]string{"exec", "cowsay@1.6.0", "--", "moo"}, "", filepath.Join(home, ".npm"), true, []string{"--prefix", dir}, []string{"cowsay@1.6.0"}},
		{[]string{"exec", "--cache", "~/c", "--package=cowsay@1.6.0", "--package", "left-pad", "--", "cowsay"}, "", filepath.Join(home, "c"), false, nil, []string{"cowsay@1.6.0", "left-pad"}},
		{[]string{"exec", "--userconfig", "~/u.npmrc", "cowsay@1.6.0"}, filepath.Join(home, "custom-cache"), filepath.Join(home, "custom-cache"),
			true, []string{"--userconfig", filepath.Join(home, "u.npmrc"), "--prefix", dir}, []string{"cowsay@1.6.0"}},
		{[]string{"exec", "-g", "cowsay@1.6.0"}, filepath.Join(home, "custom-cache"), filepath.Join(home, "custom-cache"),
			true, []string{"-g"}, []string{"cowsay@1.6.0"}},
	} {
		cacheDir, cachePackages, asked, configAsked, configured, gotFlags = "", nil, false, nil, tt.configured, nil
		parsed := m.parseRun(tt.args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), m, tt.args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && cacheDir != tt.wantCache {
			t.Errorf("%v: npx cache looked up in %q, want %q", tt.args, cacheDir, tt.wantCache)
		}
		// A cache npm's configuration names reaches the dry run, which runs
		// elsewhere: a relative one would resolve differently there.
		if tt.configured != "" && !slices.Contains(gotFlags, tt.configured) {
			t.Errorf("%v: dry run flags = %v, want the configured cache %q among them", tt.args, gotFlags, tt.configured)
		}
		if !reflect.DeepEqual(cachePackages, tt.wantPackages) {
			t.Errorf("%v: npx cache keyed by %v, want %v", tt.args, cachePackages, tt.wantPackages)
		}
		if asked != tt.wantAsked || (asked && len(configAsked) != len(tt.wantFlags)) || (len(tt.wantFlags) > 0 && !reflect.DeepEqual(configAsked, tt.wantFlags)) {
			t.Errorf("%v: npm config get cache asked = %v with %v, want %v with %v", tt.args, asked, configAsked, tt.wantAsked, tt.wantFlags)
		}
	}

	configured = ""

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
	// The host's own uv cache and installed tools are read even when the
	// resolution fails; here they must hold nothing.
	t.Setenv("UV_CACHE_DIR", t.TempDir())
	t.Setenv("UV_TOOL_DIR", t.TempDir())
	t.Setenv("UV_CONFIG_FILE", "")

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
		// Building from source is what pip's dry run is told never to do.
		{"uvx --no-binary", uvx, []string{"--no-binary", "ruff"}, []string{"--no-binary"}},
		{"uvx --no-binary-package", uvx, []string{"--no-binary-package", "ruff", "ruff"}, []string{"--no-binary-package", "ruff"}},
		{"uvx --torch-backend", uvx, []string{"--torch-backend", "cpu", "--with", "torch", "jupyter"}, []string{"--torch-backend", "cpu"}},
		{"uv pip install --torch-backend", uv, []string{"pip", "install", "--torch-backend=cu128", "torch"}, []string{"--torch-backend=cu128"}},
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
// A relative UV_CONFIG_FILE is read where the run runs, so the resolver
// (which then must be uv) and the cache probe are told the file by its
// absolute path; an absolute one, or a run naming its own configuration,
// needs nothing.
func TestExpandInstall_ToolRunNamesARelativeEnvConfigFile(t *testing.T) {
	var gotUV, gotSelectors []string
	pipCalled := false
	old, oldUV, oldDir, oldCached, oldToolDir, oldInstalled := resolvePythonFn, resolveWithUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn
	resolvePythonFn = func(_ context.Context, _ string, _, uvFlags, _ []string) ([]catalog.Resolved, error) {
		pipCalled, gotUV = true, uvFlags
		return nil, nil
	}
	resolveWithUVFn = func(_ context.Context, _ string, _, uvFlags []string) ([]catalog.Resolved, error) {
		gotUV = uvFlags
		return nil, nil
	}
	uvCacheDirFn = func(_ context.Context, flags []string) (string, error) {
		gotSelectors = flags
		return "", errors.New("none")
	}
	uvCachedFn = func(string, map[string]string) ([]catalog.Resolved, error) { return nil, nil }
	uvToolDirFn = func(context.Context, []string) (string, error) { return "", errors.New("none") }
	uvInstalledFn = func(string, string) ([]catalog.Resolved, error) { return nil, nil }
	t.Cleanup(func() {
		resolvePythonFn, resolveWithUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn = old, oldUV, oldDir, oldCached, oldToolDir, oldInstalled
	})
	t.Setenv("UV_CACHE_DIR", "")
	uvx, _ := Lookup("uvx")
	for _, tt := range []struct {
		env           string
		args          []string
		wantUV        []string
		wantSelectors []string
		wantPip       bool
	}{
		{"custom.toml", []string{"--directory", "sub", "ruff@0.6.0"}, []string{"--config-file", absPath("sub/custom.toml")}, []string{"--config-file", absPath("sub/custom.toml")}, false},
		{"custom.toml", []string{"--config-file", "mine.toml", "ruff@0.6.0"}, []string{"--config-file", absPath("mine.toml")}, []string{"--config-file", absPath("mine.toml")}, false},
		{"custom.toml", []string{"--no-config", "ruff@0.6.0"}, []string{"--no-config"}, []string{"--no-config"}, true},
		// An absolute one reads the same from anywhere, and still keeps
		// the run off the pip fallback, which reads none of it.
		{absPath("custom.toml"), []string{"ruff@0.6.0"}, []string{"--config-file", absPath("custom.toml")}, []string{"--config-file", absPath("custom.toml")}, false},
	} {
		t.Setenv("UV_CONFIG_FILE", tt.env)
		gotUV, gotSelectors, pipCalled = nil, nil, false
		parsed := parseToolRun(uvx, tt.args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), uvx, tt.args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotUV, tt.wantUV) || pipCalled != tt.wantPip {
			t.Errorf("%s %v: uv flags = %v (pip %v), want %v (pip %v)", tt.env, tt.args, gotUV, pipCalled, tt.wantUV, tt.wantPip)
		}
		if len(gotSelectors) != len(tt.wantSelectors) || (len(tt.wantSelectors) > 0 && !reflect.DeepEqual(gotSelectors, tt.wantSelectors)) {
			t.Errorf("%s %v: cache probe selectors = %v, want %v", tt.env, tt.args, gotSelectors, tt.wantSelectors)
		}
	}
}

// uv's configuration outside the command line — a UV_INDEX_URL, an index in
// the user's uv.toml — shapes the real run as a flag would, and pip reads
// none of it, so such a command is uv-only: for a tool run and a named
// install alike. Configuration that does not touch the resolution leaves the
// pip fallback in place.
func TestExpandInstall_ConfiguredIndexesAreResolvedByUVOnly(t *testing.T) {
	uvCalled, pipCalled := false, false
	old, oldUV, oldNeeds := resolvePythonFn, resolveWithUVFn, uvConfigNeedsUVFn
	resolvePythonFn = func(context.Context, string, []string, []string, []string) ([]catalog.Resolved, error) {
		pipCalled = true
		return nil, nil
	}
	resolveWithUVFn = func(context.Context, string, []string, []string) ([]catalog.Resolved, error) {
		uvCalled = true
		return nil, nil
	}
	t.Cleanup(func() { resolvePythonFn, resolveWithUVFn, uvConfigNeedsUVFn = old, oldUV, oldNeeds })
	t.Setenv("UV_CACHE_DIR", t.TempDir())
	t.Setenv("UV_TOOL_DIR", t.TempDir())
	t.Setenv("UV_CONFIG_FILE", "")
	uvx, _ := Lookup("uvx")
	uv, _ := Lookup("uv")
	for _, tt := range []struct {
		name   string
		m      *Manager
		args   []string
		shapes bool
		wantUV bool
	}{
		{"uvx, index configured", uvx, []string{"ruff"}, true, true},
		{"uvx, nothing configured", uvx, []string{"ruff"}, false, false},
		{"uv pip install, index configured", uv, []string{"pip", "install", "ruff"}, true, true},
		{"uv pip install, nothing configured", uv, []string{"pip", "install", "ruff"}, false, false},
	} {
		var askedFlags []string
		askedDir := "unset"
		uvConfigNeedsUVFn = func(flags []string, dir string) bool {
			askedFlags, askedDir = flags, dir
			return tt.shapes
		}
		uvCalled, pipCalled = false, false
		start := 0
		var parsed installArgs
		if tt.m == uvx {
			parsed = parseToolRun(uvx, tt.args)
			parsed.ToolRun = true
		} else {
			start = 2
			parsed = ParseSpecs(uv, tt.args[start:])
		}
		if _, err := expandInstall(context.Background(), tt.m, tt.args, start, parsed); err != nil {
			t.Fatal(err)
		}
		if uvCalled != tt.wantUV || pipCalled == tt.wantUV {
			t.Errorf("%s: uv %v, pip %v, want uv-only %v", tt.name, uvCalled, pipCalled, tt.wantUV)
		}
		// A tool run reads no project configuration; a named install reads
		// the project's at its directory.
		if wantDir := map[bool]string{true: "", false: "."}[tt.m == uvx]; askedDir != wantDir || askedFlags == nil && tt.m == uv {
			t.Errorf("%s: configuration asked for dir %q with %v, want dir %q", tt.name, askedDir, askedFlags, wantDir)
		}
	}
}

// uv's path-valued variables (UV_CONSTRAINT, UV_OVERRIDE, …) are read
// against the directory uv runs in, and a tool run's resolver runs in
// scratch, where UV_CONSTRAINT=requirements.txt would name the resolver's
// own input: a relative entry is handed over as the equivalent flag,
// absolute against the run's directory, one flag per entry. A flag on the
// line already replaces the variable; an absolute path or a URL reads the
// same from anywhere.
func TestExpandInstall_ToolRunNamesRelativeEnvPaths(t *testing.T) {
	var gotUV []string
	old, oldUV, oldNeeds, oldDir, oldCached, oldToolDir, oldInstalled := resolvePythonFn, resolveWithUVFn, uvConfigNeedsUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn
	resolvePythonFn = func(_ context.Context, _ string, _, uvFlags, _ []string) ([]catalog.Resolved, error) {
		gotUV = uvFlags
		return nil, nil
	}
	resolveWithUVFn = func(_ context.Context, _ string, _, uvFlags []string) ([]catalog.Resolved, error) {
		gotUV = uvFlags
		return nil, nil
	}
	uvConfigNeedsUVFn = func([]string, string) bool { return false }
	uvCacheDirFn = func(context.Context, []string) (string, error) { return "", errors.New("none") }
	uvCachedFn = func(string, map[string]string) ([]catalog.Resolved, error) { return nil, nil }
	uvToolDirFn = func(context.Context, []string) (string, error) { return "", errors.New("none") }
	uvInstalledFn = func(string, string) ([]catalog.Resolved, error) { return nil, nil }
	t.Cleanup(func() {
		resolvePythonFn, resolveWithUVFn, uvConfigNeedsUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn = old, oldUV, oldNeeds, oldDir, oldCached, oldToolDir, oldInstalled
	})
	for _, v := range []string{"UV_CACHE_DIR", "UV_CONFIG_FILE", "UV_CONSTRAINT", "UV_OVERRIDE", "UV_BUILD_CONSTRAINT", "UV_FIND_LINKS", "UV_PYTHON", "UV_NO_CACHE"} {
		t.Setenv(v, "")
	}
	uvx, _ := Lookup("uvx")
	for _, tt := range []struct {
		env, value string
		args       []string
		wantUV     []string
	}{
		{"UV_CONSTRAINT", "c.txt", []string{"ruff"}, []string{"--constraints", absPath("c.txt")}},
		{"UV_CONSTRAINT", "c.txt", []string{"--directory", "sub", "ruff"}, []string{"--constraints", absPath("sub/c.txt")}},
		{"UV_CONSTRAINT", "c.txt", []string{"--constraints", "mine.txt", "ruff"}, []string{"--constraints", absPath("mine.txt")}},
		{"UV_CONSTRAINT", "c.txt", []string{"-c", "mine.txt", "ruff"}, []string{"-c", absPath("mine.txt")}},
		{"UV_CONSTRAINT", absPath("c.txt"), []string{"ruff"}, nil},
		{"UV_CONSTRAINT", "a.txt " + absPath("b.txt"), []string{"ruff"}, []string{"--constraints", absPath("a.txt"), "--constraints", absPath("b.txt")}},
		{"UV_OVERRIDE", "o.txt", []string{"ruff"}, []string{"--overrides", absPath("o.txt")}},
		// Any non-URL entry of a file-valued variable is a path, whatever
		// its spelling.
		{"UV_CONSTRAINT", "constraints", []string{"ruff"}, []string{"--constraints", absPath("constraints")}},
		{"UV_CONSTRAINT", "constraints.lock", []string{"ruff"}, []string{"--constraints", absPath("constraints.lock")}},
		{"UV_FIND_LINKS", "wheels", []string{"ruff"}, []string{"--find-links", absPath("wheels")}},
		{"UV_BUILD_CONSTRAINT", "b.txt", []string{"ruff"}, []string{"--build-constraints", absPath("b.txt")}},
		{"UV_FIND_LINKS", "https://w.example/simple ./wheels", []string{"ruff"}, []string{"--find-links", "https://w.example/simple", "--find-links", absPath("wheels")}},
		{"UV_FIND_LINKS", "https://w.example/simple", []string{"ruff"}, nil},
		{"UV_PYTHON", ".venv/bin/python", []string{"ruff"}, []string{"--python", absPath(".venv/bin/python")}},
		{"UV_PYTHON", "3.12", []string{"ruff"}, nil},
	} {
		t.Setenv(tt.env, tt.value)
		gotUV = nil
		parsed := parseToolRun(uvx, tt.args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), uvx, tt.args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotUV, tt.wantUV) {
			t.Errorf("%s=%q %v: uv flags = %v, want %v", tt.env, tt.value, tt.args, gotUV, tt.wantUV)
		}
		t.Setenv(tt.env, "")
	}
}

// UV_NO_CACHE is --no-cache from the environment: the persistent cache is
// neither probed nor read, while an installed tool, which the setting does
// not govern, is still read.
func TestExpandInstall_UVNoCacheEnvSkipsTheCache(t *testing.T) {
	old, oldUV, oldNeeds, oldDir, oldCached, oldToolDir, oldInstalled := resolvePythonFn, resolveWithUVFn, uvConfigNeedsUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn
	fresh := func(context.Context, string, []string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "6.1"}}, nil
	}
	resolvePythonFn = func(ctx context.Context, dir string, specs, uvFlags, _ []string) ([]catalog.Resolved, error) {
		return fresh(ctx, dir, specs, uvFlags)
	}
	resolveWithUVFn = fresh
	uvConfigNeedsUVFn = func([]string, string) bool { return false }
	probed, cacheRead := false, false
	uvCacheDirFn = func(context.Context, []string) (string, error) {
		probed = true
		return filepath.Join(t.TempDir(), "c"), nil
	}
	uvCachedFn = func(string, map[string]string) ([]catalog.Resolved, error) {
		cacheRead = true
		return []catalog.Resolved{{Name: "cowsay", Version: "6.1"}, {Name: "six", Version: "1.16.0"}}, nil
	}
	uvToolDirFn = func(context.Context, []string) (string, error) { return filepath.Join(t.TempDir(), "tools"), nil }
	uvInstalledFn = func(string, string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "6.0"}}, nil
	}
	t.Cleanup(func() {
		resolvePythonFn, resolveWithUVFn, uvConfigNeedsUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn = old, oldUV, oldNeeds, oldDir, oldCached, oldToolDir, oldInstalled
	})
	t.Setenv("UV_CACHE_DIR", "")
	t.Setenv("UV_TOOL_DIR", "")
	t.Setenv("UV_CONFIG_FILE", "")
	uvx, _ := Lookup("uvx")
	for _, tt := range []struct {
		noCache   string
		wantRead  bool
		wantNames int
	}{
		{"1", false, 2},
		{"true", false, 2},
		{"0", true, 3},
		{"", true, 3},
	} {
		t.Setenv("UV_NO_CACHE", tt.noCache)
		probed, cacheRead = false, false
		parsed := parseToolRun(uvx, []string{"cowsay"})
		parsed.ToolRun = true
		tree, err := expandInstall(context.Background(), uvx, []string{"cowsay"}, 0, parsed)
		if err != nil {
			t.Fatal(err)
		}
		if probed != tt.wantRead || cacheRead != tt.wantRead || len(tree) != tt.wantNames {
			t.Errorf("UV_NO_CACHE=%q: probed %v, read %v, %d packages; want read %v, %d packages", tt.noCache, probed, cacheRead, len(tree), tt.wantRead, tt.wantNames)
		}
	}
}

// A relative UV_CACHE_DIR, or a relative cache-dir in uv's configuration,
// is read against the directory uv runs in, and the resolver runs in
// scratch, where there is no cache: it is told the cache by its absolute
// path, as --cache-dir, which is uv's flag alone and so leaves the pip
// fallback in place. A --cache-dir on the line, an absolute path and a run
// that reads no cache need nothing.
func TestExpandInstall_ToolRunNamesARelativeEnvCacheDir(t *testing.T) {
	var gotUV []string
	old, oldUV, oldDir, oldCached, oldToolDir, oldInstalled := resolvePythonFn, resolveWithUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn
	resolvePythonFn = func(_ context.Context, _ string, _, uvFlags, _ []string) ([]catalog.Resolved, error) {
		gotUV = uvFlags
		return nil, nil
	}
	resolveWithUVFn = func(_ context.Context, _ string, _, uvFlags []string) ([]catalog.Resolved, error) {
		gotUV = uvFlags
		return nil, nil
	}
	uvCacheDirFn = func(context.Context, []string) (string, error) { return "", errors.New("none") }
	uvCachedFn = func(string, map[string]string) ([]catalog.Resolved, error) { return nil, nil }
	uvToolDirFn = func(context.Context, []string) (string, error) { return "", errors.New("none") }
	uvInstalledFn = func(string, string) ([]catalog.Resolved, error) { return nil, nil }
	t.Cleanup(func() {
		resolvePythonFn, resolveWithUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn = old, oldUV, oldDir, oldCached, oldToolDir, oldInstalled
	})
	t.Setenv("UV_CONFIG_FILE", "")
	uvx, _ := Lookup("uvx")
	// uv's own answer may be relative too, for a relative cache-dir in its
	// configuration, which it reads against the directory it runs in.
	uvAnswer := ""
	uvCacheDirFn = func(context.Context, []string) (string, error) {
		if uvAnswer == "" {
			return "", errors.New("none")
		}
		return uvAnswer, nil
	}
	for _, tt := range []struct {
		env, answer string
		args        []string
		wantUV      []string
	}{
		{"c", "", []string{"ruff@0.6.0"}, []string{"--cache-dir", absPath("c")}},
		{"c", "", []string{"--directory", "sub", "ruff@0.6.0"}, []string{"--cache-dir", absPath("sub/c")}},
		{"c", "", []string{"--cache-dir", "mine", "ruff@0.6.0"}, []string{"--cache-dir", absPath("mine")}},
		{"c", "", []string{"--cache-dir=mine", "ruff@0.6.0"}, []string{"--cache-dir=" + absPath("mine")}},
		{"c", "", []string{"--no-cache", "ruff@0.6.0"}, []string{"--no-cache"}},
		{absPath("c"), "", []string{"ruff@0.6.0"}, nil},
		{"", "", []string{"ruff@0.6.0"}, nil},
		{"", "rel", []string{"ruff@0.6.0"}, []string{"--cache-dir", absPath("rel")}},
		{"", "rel", []string{"--directory", "sub", "ruff@0.6.0"}, []string{"--cache-dir", absPath("sub/rel")}},
		{"", absPath("abs"), []string{"ruff@0.6.0"}, nil},
	} {
		t.Setenv("UV_CACHE_DIR", tt.env)
		uvAnswer = tt.answer
		gotUV = nil
		parsed := parseToolRun(uvx, tt.args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), uvx, tt.args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotUV, tt.wantUV) {
			t.Errorf("UV_CACHE_DIR=%q %v: uv flags = %v, want %v", tt.env, tt.args, gotUV, tt.wantUV)
		}
	}
}

// When expansion failed, the tree is only what an earlier run left on disk,
// which says nothing about what resolves today: the requested names are
// resolved as well, a release already in the set is not repeated, and each
// requested name counts once.
func TestResolveNamed_UnresolvedSetResolvesTheNamesToo(t *testing.T) {
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "tool", Version: "1.0.0"}, {Name: "dep", Version: "0.1.0"}}, errors.New("npm: registry unreachable")
	})
	m, _ := Lookup("npx")
	for _, tt := range []struct {
		latest    string
		wantSpecs []check.Spec
	}{
		{"2.0.0", []check.Spec{{Ecosystem: "npm", Name: "tool", Version: "1.0.0"}, {Ecosystem: "npm", Name: "dep", Version: "0.1.0"}, {Ecosystem: "npm", Name: "tool", Version: "2.0.0"}}},
		{"1.0.0", []check.Spec{{Ecosystem: "npm", Name: "tool", Version: "1.0.0"}, {Ecosystem: "npm", Name: "dep", Version: "0.1.0"}}},
	} {
		parsed := m.parseRun([]string{"tool@latest"})
		parsed.ToolRun = true
		asked := 0
		set := resolveNamed(context.Background(), m, Options{}, 0, parsed, func(context.Context, string, string, string) (string, error) {
			asked++
			return tt.latest, nil
		})
		if asked != 1 {
			t.Errorf("latest %s: registry asked %d times, want once", tt.latest, asked)
		}
		if !reflect.DeepEqual(set.specs, tt.wantSpecs) {
			t.Errorf("latest %s: specs = %+v, want %+v", tt.latest, set.specs, tt.wantSpecs)
		}
		if set.named != 1 || set.deps != 1 || set.expanded || set.unresolved == nil {
			t.Errorf("latest %s: set = %+v", tt.latest, set)
		}
	}
	// A cached copy fetched from a trusted registry covers that copy, not
	// today's request: the name is still resolved.
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "tool", Version: "1.0.0", Registry: "https://npm.acme.internal/tool/-/tool-1.0.0.tgz"}}, errors.New("npm: registry unreachable")
	})
	parsed := m.parseRun([]string{"tool@latest"})
	parsed.ToolRun = true
	asked := 0
	set := resolveNamed(warn.NewContext(context.Background(), false), m, Options{Trust: trust.Policy{Registries: []string{"https://npm.acme.internal/"}}}, 0, parsed,
		func(context.Context, string, string, string) (string, error) {
			asked++
			return "2.0.0", nil
		})
	if asked != 1 {
		t.Errorf("trusted cached copy: registry asked %d times, want once", asked)
	}
	if want := []check.Spec{{Ecosystem: "npm", Name: "tool", Version: "2.0.0"}}; !reflect.DeepEqual(set.specs, want) {
		t.Errorf("trusted cached copy: specs = %+v, want %+v", set.specs, want)
	}
}

// A relative npm_config_cache, or a relative cache= in an .npmrc, is
// resolved where npm runs, and the dry run runs in scratch: it is told the
// cache by its absolute path, as --cache, found once and shared with the
// npx-cache lookup. A --cache on the line and an absolute variable need
// nothing; a named install reads the variable the same way.
func TestExpandInstall_NamesARelativeNpmCache(t *testing.T) {
	var gotFlags []string
	var cacheRead string
	old, oldCached, oldGet, oldOmits := resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn
	resolveNpmFn = func(_ context.Context, _, _ string, _, flags []string) ([]catalog.Resolved, error) {
		gotFlags = flags
		return nil, nil
	}
	npxCachedFn = func(dir string, _ []string) ([]catalog.Resolved, error) {
		cacheRead = dir
		return nil, nil
	}
	npmConfigOmitsFn = func(context.Context, string, []string) ([]string, error) { return nil, nil }
	answer := ""
	npmConfigGetFn = func(context.Context, string, string, []string) (string, error) {
		if answer == "" {
			return "", errors.New("no npm")
		}
		return answer, nil
	}
	t.Cleanup(func() { resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn = old, oldCached, oldGet, oldOmits })
	npx, _ := Lookup("npx")
	npm, _ := Lookup("npm")
	fromNpm := filepath.Join(t.TempDir(), "from-npmrc")
	for _, tt := range []struct {
		m         *Manager
		env       string
		answer    string
		args      []string
		wantFlags []string
		wantCache string
	}{
		{npx, "./c", "", []string{"cowsay"}, []string{"--cache", absPath("c")}, absPath("c")},
		{npx, "./c", "", []string{"--cache", "mine", "cowsay"}, []string{"--cache=" + absPath("mine")}, absPath("mine")},
		{npx, absPath("c"), "", []string{"cowsay"}, nil, absPath("c")},
		{npx, "", fromNpm, []string{"cowsay"}, []string{"--cache", fromNpm}, fromNpm},
		{npx, "", "", []string{"cowsay"}, nil, ""},
		{npm, "./c", "", []string{"install", "cowsay"}, []string{"--cache", absPath("c")}, ""},
		{npm, absPath("c"), "", []string{"install", "cowsay"}, nil, ""},
	} {
		t.Setenv("npm_config_cache", tt.env)
		answer, gotFlags, cacheRead = tt.answer, nil, ""
		start := 0
		var parsed installArgs
		if tt.m == npx {
			parsed = npx.parseRun(tt.args)
			parsed.ToolRun = true
		} else {
			start = 1
			parsed = ParseSpecs(npm, tt.args[start:])
		}
		if _, err := expandInstall(context.Background(), tt.m, tt.args, start, parsed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotFlags, tt.wantFlags) {
			t.Errorf("%s npm_config_cache=%q %v: flags = %v, want %v", tt.m.Bin, tt.env, tt.args, gotFlags, tt.wantFlags)
		}
		if tt.wantCache != "" && cacheRead != tt.wantCache {
			t.Errorf("%s npm_config_cache=%q %v: npx cache read from %q, want %q", tt.m.Bin, tt.env, tt.args, cacheRead, tt.wantCache)
		}
	}
}

// A failed dry run does not skip what is on disk: npm may reuse the npx
// cache exactly when today's resolution fails, and uv runs an installed or
// cached environment regardless, so those trees are returned beside the
// error and checked. The omit policy, which shapes a fresh install, is not
// asked for.
func TestExpandInstall_ToolRunReadsTheCachesWhenTheDryRunFails(t *testing.T) {
	names := func(tree []catalog.Resolved) []string {
		var out []string
		for _, r := range tree {
			out = append(out, r.Name+"@"+r.Version)
		}
		return out
	}
	t.Run("npx", func(t *testing.T) {
		old, oldCached, oldGet, oldInc := resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn
		resolveNpmFn = func(context.Context, string, string, []string, []string) ([]catalog.Resolved, error) {
			return nil, errors.New("npm: registry unreachable")
		}
		npxCachedFn = func(string, []string) ([]catalog.Resolved, error) {
			return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"}, {Name: "get-stdin", Version: "8.0.0"}}, nil
		}
		npmConfigGetFn = func(context.Context, string, string, []string) (string, error) { return "", errors.New("no npm") }
		npmConfigOmitsFn = func(context.Context, string, []string) ([]string, error) {
			t.Error("the omit policy was asked for with no fresh tree to prune")
			return nil, nil
		}
		t.Cleanup(func() {
			resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn = old, oldCached, oldGet, oldInc
		})
		m, _ := Lookup("npx")
		parsed := m.parseRun([]string{"--omit=dev", "cowsay"})
		parsed.ToolRun = true
		tree, err := expandInstall(context.Background(), m, []string{"--omit=dev", "cowsay"}, 0, parsed)
		if err == nil || !strings.Contains(err.Error(), "unreachable") {
			t.Fatalf("err = %v, want the dry run's", err)
		}
		if want := []string{"cowsay@1.6.0", "get-stdin@8.0.0"}; !reflect.DeepEqual(names(tree), want) {
			t.Errorf("tree = %v, want the cached %v", names(tree), want)
		}
	})
	t.Run("uvx", func(t *testing.T) {
		old, oldUV, oldDir, oldCached, oldToolDir, oldInstalled := resolvePythonFn, resolveWithUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn
		resolvePythonFn = func(context.Context, string, []string, []string, []string) ([]catalog.Resolved, error) {
			return nil, errors.New("uv: index unreachable")
		}
		resolveWithUVFn = func(context.Context, string, []string, []string) ([]catalog.Resolved, error) {
			return nil, errors.New("uv: index unreachable")
		}
		uvCacheDirFn = func(context.Context, []string) (string, error) { return filepath.Join(t.TempDir(), "cache"), nil }
		uvCachedFn = func(string, map[string]string) ([]catalog.Resolved, error) {
			return []catalog.Resolved{{Name: "cowsay", Version: "6.1"}, {Name: "six", Version: "1.16.0"}}, nil
		}
		uvToolDirFn = func(context.Context, []string) (string, error) { return filepath.Join(t.TempDir(), "tools"), nil }
		uvInstalledFn = func(string, string) ([]catalog.Resolved, error) {
			return []catalog.Resolved{{Name: "cowsay", Version: "6.0"}, {Name: "six", Version: "1.15.0"}}, nil
		}
		t.Cleanup(func() {
			resolvePythonFn, resolveWithUVFn, uvCacheDirFn, uvCachedFn, uvToolDirFn, uvInstalledFn = old, oldUV, oldDir, oldCached, oldToolDir, oldInstalled
		})
		t.Setenv("UV_CACHE_DIR", "")
		t.Setenv("UV_TOOL_DIR", "")
		t.Setenv("UV_CONFIG_FILE", "")
		uvx, _ := Lookup("uvx")
		parsed := parseToolRun(uvx, []string{"cowsay"})
		parsed.ToolRun = true
		tree, err := expandInstall(context.Background(), uvx, []string{"cowsay"}, 0, parsed)
		if err == nil || !strings.Contains(err.Error(), "unreachable") {
			t.Fatalf("err = %v, want the resolver's", err)
		}
		if want := []string{"cowsay@6.1", "six@1.16.0", "cowsay@6.0", "six@1.15.0"}; !reflect.DeepEqual(names(tree), want) {
			t.Errorf("tree = %v, want the cached and installed %v", names(tree), want)
		}
	})
}

// What an earlier run's tree contributed to an unresolved set is counted
// and claimed: the fallback line names the dependencies it still checked,
// and the verbose coverage says where they came from.
func TestResolveNamed_UnresolvedSetKeepsAnEarlierRunsDependencies(t *testing.T) {
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"}, {Name: "get-stdin", Version: "8.0.0"}}, errors.New("npm: registry unreachable")
	})
	m, _ := Lookup("npx")
	parsed := m.parseRun([]string{"cowsay"})
	parsed.ToolRun = true
	// The name is resolved as well (what the cache holds says nothing about
	// what resolves today); the same release is not repeated.
	set := resolveNamed(context.Background(), m, Options{}, 0, parsed, func(context.Context, string, string, string) (string, error) {
		return "1.6.0", nil
	})
	if set.named != 1 || set.deps != 1 || set.expanded || set.unresolved == nil || len(set.specs) != 2 {
		t.Fatalf("set = %+v", set)
	}
	if got, want := set.coverage(), " (1 requested + 1 dependencies from an earlier run; dependencies not resolved)"; got != want {
		t.Errorf("coverage = %q, want %q", got, want)
	}
	var buf bytes.Buffer
	oldOut := errOut
	errOut = &buf
	t.Cleanup(func() { errOut = oldOut })
	reportUnexpanded(warn.NewContext(context.Background(), false), parsed.Specs, set.unresolved, set.deps)
	want := "ossprey: warning: could not resolve the dependencies of cowsay (npm: registry unreachable); checking the named packages and 1 dependencies from an earlier run\n"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

// A tool run's --with-requirements files are installed into the same
// environment as the packages, so they resolve together: the resolver gets
// each file as a "-r" spec, the path absolute against the run's directory.
func TestExpandInstall_ToolRunResolvesRequirementsFilesWithThePackages(t *testing.T) {
	var gotSpecs []string
	old, oldUV := resolvePythonFn, resolveWithUVFn
	resolvePythonFn = func(_ context.Context, _ string, specs, _, _ []string) ([]catalog.Resolved, error) {
		gotSpecs = specs
		return nil, nil
	}
	resolveWithUVFn = func(_ context.Context, _ string, specs, _ []string) ([]catalog.Resolved, error) {
		gotSpecs = specs
		return nil, nil
	}
	t.Cleanup(func() { resolvePythonFn, resolveWithUVFn = old, oldUV })
	uvx, _ := Lookup("uvx")
	for _, tt := range []struct {
		args []string
		want []string
	}{
		{[]string{"--with-requirements", "extra.txt", "ruff"}, []string{"ruff", "-r " + absPath("extra.txt")}},
		{[]string{"--directory", "sub", "--with-requirements", "extra.txt", "--with", "six", "ruff@0.6.0"},
			[]string{"six", "ruff==0.6.0", "-r " + absPath("sub/extra.txt")}},
	} {
		gotSpecs = nil
		parsed := parseToolRun(uvx, tt.args)
		parsed.ToolRun = true
		if _, err := expandInstall(context.Background(), uvx, tt.args, 0, parsed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotSpecs, tt.want) {
			t.Errorf("%v: specs = %v, want %v", tt.args, gotSpecs, tt.want)
		}
	}
}

// A release named twice with different extras is one spec, checked once,
// but both spellings reach the resolver: each extra brings dependencies of
// its own, and the last token alone would drop the first's.
func TestSpecTokens_KeepsEveryExtrasSpelling(t *testing.T) {
	uvx, _ := Lookup("uvx")
	parsed := parseToolRun(uvx, []string{"--from", "httpx[cli]==0.28.1", "--with", "httpx[http2]==0.28.1", "--with", "httpx[cli]==0.28.1", "httpx"})
	if want := []check.Spec{{Ecosystem: "pypi", Name: "httpx", Version: "0.28.1"}}; !reflect.DeepEqual(parsed.Specs, want) {
		t.Errorf("specs = %+v, want %+v", parsed.Specs, want)
	}
	if got, want := specTokens(uvx, parsed), []string{"httpx[cli]==0.28.1", "httpx[http2]==0.28.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tokens = %v, want %v", got, want)
	}
}

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
		// The `@version` shorthand keeps its extras and marker: each extra
		// brings dependencies of its own.
		{"uv", []string{"httpx[cli]@0.28.1", "rich[jupyter]@latest", "six@1.17.0; python_version > '3'"},
			[]string{"httpx[cli]==0.28.1", "rich[jupyter]", "six==1.17.0; python_version > '3'"}},
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
		// npm's options are rendered as nopt normalised them, from npm's own
		// parse of the whole line.
		{"npm keeps peer and omit flags, drops the rest",
			npmResolveFlags(npm, []string{"--save-dev", "--legacy-peer-deps", "--omit", "dev", "--registry=https://r.example", "-w", "web", "express"}),
			[]string{"--legacy-peer-deps", "--omit=dev", "--registry", "https://r.example/"}},
		{"npm reads nopt's negation parity",
			npmResolveFlags(npm, []string{"install", "--no-no-optional", "tool"}),
			[]string{"--optional"}},
		{"npm keeps --no-optional",
			npmResolveFlags(npm, []string{"install", "--no-optional", "tool"}),
			[]string{"--no-optional"}},
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
		{"npm makes --userconfig and --globalconfig absolute, the last --userconfig winning",
			npmResolveFlags(npm, []string{"--userconfig", "u.npmrc", "--userconfig=./v.npmrc", "--globalconfig", "g.npmrc", "express"}),
			[]string{"--globalconfig=" + absPath("g.npmrc"), "--userconfig", absPath("v.npmrc")}},
		{"npm keeps the cache policy and the cache, made absolute, the last --cache winning",
			npmResolveFlags(npm, []string{"--offline", "--prefer-offline", "--cache", "c", "--cache=~/d", "express"}),
			[]string{"--cache=" + absPath(expandHome("~/d")), "--offline", "--prefer-offline"}},
		{"npm reads its options before the verb too",
			npmResolveFlags(npm, []string{"--userconfig", "./corp.npmrc", "--offline", "install", "--omit=dev", "tool@1.0.0"}),
			[]string{"--offline", "--omit=dev", "--userconfig", absPath("corp.npmrc")}},
		{"npm renders a negated cache policy as its last-wins reading",
			npmResolveFlags(npm, []string{"install", "--prefer-offline", "--no-prefer-offline", "--no-offline", "tool@1.0.0"}),
			[]string{"--no-offline", "--no-prefer-offline"}},
		{"prefer-online",
			npmResolveFlags(npm, []string{"install", "--prefer-online", "--no-prefer-online", "tool@1.0.0"}),
			[]string{"--no-prefer-online"}},
		{"min-release-age",
			npmResolveFlags(npm, []string{"install", "--min-release-age", "7", "--min-release-age-exclude=left-pad", "tool@1.0.0"}),
			[]string{"--min-release-age=7", "--min-release-age-exclude=left-pad"}},
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
	ws := filepath.Join(root, "ws")
	member := filepath.Join(ws, "packages", "app")
	other := filepath.Join(ws, "other")
	nmOnly := filepath.Join(ws, "packages", "nm")
	for _, d := range []string{filepath.Join(member, "src"), other, filepath.Join(nmOnly, "node_modules")} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(ws, "package.json"), []byte(`{"workspaces":["packages/*"]}`), 0o644)
	os.WriteFile(filepath.Join(member, "package.json"), []byte(`{"name":"app"}`), 0o644)
	os.WriteFile(filepath.Join(other, "package.json"), []byte(`{"name":"other"}`), 0o644)
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
		// A declared workspace member's configuration is the root's: npm
		// walks on to the root and ignores the member's .npmrc. Not with
		// workspaces off, not for a non-member, and not for a prefix found
		// by node_modules alone, which no workspace glob names.
		{"workspace member", member, npm, []string{"install", "x"}, ws},
		{"workspace member subdirectory", filepath.Join(member, "src"), npm, []string{"install", "x"}, ws},
		{"workspace member, tool run", member, npm, []string{"exec", "x"}, ws},
		{"workspace member, --workspaces=false", member, npm, []string{"install", "--workspaces=false", "x"}, member},
		{"workspace member, --no-workspaces", member, npm, []string{"install", "--no-workspaces", "x"}, member},
		{"workspace member, --prefix", member, npm, []string{"install", "--prefix", ".", "x"}, member},
		{"not a member", other, npm, []string{"install", "x"}, other},
		{"node_modules only under a glob", nmOnly, npm, []string{"install", "x"}, nmOnly},
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
		// The cache a run reads, and whether it reads or refreshes it, decide
		// what uv resolves against offline or from stale metadata, so they
		// reach the resolver, the path against the run's directory, and only
		// uv can honour them.
		{"cache options before tool run", uv, []string{"--cache-dir", "c", "--refresh", "tool", "run", "ruff@0.6.0"},
			"", []string{"--cache-dir", absPath("c"), "--refresh"}, true},
		{"tool run cache options", uvx, []string{"--offline", "--cache-dir", "c", "-n", "ruff@0.6.0"},
			"", []string{"--offline", "--cache-dir", absPath("c"), "-n"}, true},
		{"tool run cache dir under --directory", uvx, []string{"--directory", "sub", "--cache-dir", "c", "ruff@0.6.0"},
			"", []string{"--cache-dir", absPath("sub/c")}, true},
		{"named install cache options", uv, []string{"pip", "install", "--no-cache", "--refresh-package", "ruff", "ruff"},
			".", []string{"--no-cache", "--refresh-package", "ruff"}, true},
		// --reinstall implies --refresh, which is what the resolver reads.
		{"tool run reinstall is refresh", uvx, []string{"--reinstall", "--reinstall-package", "six", "ruff@0.6.0"},
			"", []string{"--refresh", "--refresh-package", "six"}, true},
		{"named install reinstall is refresh", uv, []string{"pip", "install", "--reinstall", "ruff"},
			".", []string{"--refresh"}, true},
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
	old, oldOmits, oldCached, oldGet := resolveNpmFn, npmConfigOmitsFn, npxCachedFn, npmConfigGetFn
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) { return nil, nil }
	npmConfigGetFn = func(context.Context, string, string, []string) (string, error) { return "", errors.New("no npm") }
	resolveNpmFn = func(context.Context, string, string, []string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "needed", Version: "1.0.0"}, {Name: "extra", Version: "2.0.0", Optional: true},
			{Name: "devonly", Version: "3.0.0", Dev: true}, {Name: "both", Version: "4.0.0", DevOptional: true},
			{Name: "peer", Version: "5.0.0", Peer: true},
			// Two copies of one release, a dev-only and an optional-only one
			// (aliases): left out only when both kinds are omitted.
			{Name: "aliased", Version: "6.0.0", Copies: []catalog.DependencyKinds{{Dev: true}, {Optional: true}}}}, nil
	}
	// npm answers the omit policy for the dry run's own flags; asked is
	// how often it was consulted and askedFlags what with.
	var answer []string
	var answerErr error
	asked := 0
	var askedFlags []string
	askedDir := ""
	npmConfigOmitsFn = func(_ context.Context, dir string, flags []string) ([]string, error) {
		asked++
		askedFlags, askedDir = flags, dir
		return answer, answerErr
	}
	t.Cleanup(func() {
		resolveNpmFn, npmConfigOmitsFn, npxCachedFn, npmConfigGetFn = old, oldOmits, oldCached, oldGet
	})
	m, _ := Lookup("npm")

	names := func(tree []catalog.Resolved) []string {
		var out []string
		for _, r := range tree {
			out = append(out, r.Name)
		}
		return out
	}
	all := []string{"needed", "extra", "devonly", "both", "peer", "aliased"}
	for _, tt := range []struct {
		args      []string
		toolRun   bool
		answer    []string
		answerErr error
		want      []string
		wantFlags []string
	}{
		// npm's answer prunes the fresh tree, whatever configured it: the
		// line (which reaches npm as the dry run's flags), the environment
		// or an .npmrc. A devOptional package is reached both ways and
		// goes only when both are omitted; peers go with peer.
		{[]string{"exec", "cowsay@1.6.0"}, true, nil, nil, all, nil},
		{[]string{"exec", "--omit=optional", "cowsay@1.6.0"}, true, []string{"optional"}, nil, []string{"needed", "devonly", "both", "peer", "aliased"}, []string{"--omit=optional"}},
		{[]string{"exec", "--no-optional", "cowsay@1.6.0"}, true, []string{"optional"}, nil, []string{"needed", "devonly", "both", "peer", "aliased"}, []string{"--no-optional"}},
		{[]string{"exec", "--omit=optional", "--include=optional", "cowsay@1.6.0"}, true, nil, nil, all, []string{"--include=optional", "--omit=optional"}},
		{[]string{"exec", "cowsay@1.6.0"}, true, []string{"optional"}, nil, []string{"needed", "devonly", "both", "peer", "aliased"}, nil},
		{[]string{"exec", "cowsay@1.6.0"}, true, []string{"dev"}, nil, []string{"needed", "extra", "both", "peer", "aliased"}, nil},
		{[]string{"exec", "cowsay@1.6.0"}, true, []string{"dev", "optional"}, nil, []string{"needed", "peer"}, nil},
		{[]string{"exec", "cowsay@1.6.0"}, true, []string{"peer"}, nil, []string{"needed", "extra", "devonly", "both", "aliased"}, nil},
		// A named install asks with the same flags, location included.
		{[]string{"install", "--omit", "optional", "cowsay"}, false, []string{"optional"}, nil, []string{"needed", "devonly", "both", "peer", "aliased"}, []string{"--omit=optional"}},
		{[]string{"install", "cowsay"}, false, []string{"optional"}, nil, []string{"needed", "devonly", "both", "peer", "aliased"}, nil},
		{[]string{"install", "-g", "cowsay"}, false, nil, nil, all, nil},
		// The probe runs in the cwd with the command's own selectors:
		// --prefix names the configuration (the command's, else the one it
		// would discover), --workspaces=false keeps npm at it.
		{[]string{"install", "--prefix", "../x", "cowsay"}, false, nil, nil, all, nil},
		{[]string{"exec", "--workspaces=false", "cowsay@1.6.0"}, true, nil, nil, all, nil},
		{[]string{"install", "--no-workspaces", "cowsay"}, false, nil, nil, all, nil},
		// When npm cannot answer, nothing is dropped.
		{[]string{"install", "--omit=optional", "cowsay"}, false, nil, errors.New("no npm"), all, []string{"--omit=optional"}},
	} {
		answer, answerErr, asked, askedFlags, askedDir = tt.answer, tt.answerErr, 0, nil, ""
		start := 0
		var parsed installArgs
		if tt.toolRun {
			parsed = m.parseRun(tt.args)
			parsed.ToolRun = true
		} else {
			start = 1
			parsed = ParseSpecs(m, tt.args[start:])
		}
		tree, err := expandInstall(context.Background(), m, tt.args, start, parsed)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(names(tree), tt.want) {
			t.Errorf("%v: tree = %v, want %v", tt.args, names(tree), tt.want)
		}
		if asked != 1 {
			t.Errorf("%v: npm asked %d times, want once", tt.args, asked)
		}
		location := []string{"--prefix", npmLocalPrefix()}
		switch {
		case slices.Contains(tt.args, "-g"):
			location = []string{"-g"}
		case slices.Contains(tt.args, "--prefix"):
			location = []string{"--prefix", absPath("../x")}
		}
		if slices.Contains(tt.args, "--workspaces=false") || slices.Contains(tt.args, "--no-workspaces") {
			location = append(location, "--workspaces=false")
		}
		if want := slices.Concat(tt.wantFlags, location); !reflect.DeepEqual(askedFlags, want) {
			t.Errorf("%v: npm asked with %v, want %v", tt.args, askedFlags, want)
		}
		if askedDir != "." {
			t.Errorf("%v: npm asked in %q, want the cwd", tt.args, askedDir)
		}
	}
}

// A relative npm_config_userconfig or _globalconfig is resolved where npm
// runs; the dry run and the probes run elsewhere, so they are told the file
// absolutely, as the flag, for a tool run and a named install alike. A flag
// on the line and an absolute variable need nothing.
func TestExpandInstall_NamesARelativeNpmConfigFile(t *testing.T) {
	var gotFlags []string
	old, oldCached, oldGet, oldOmits := resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn
	resolveNpmFn = func(_ context.Context, _, _ string, _, flags []string) ([]catalog.Resolved, error) {
		gotFlags = flags
		return nil, nil
	}
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) { return nil, nil }
	npmConfigOmitsFn = func(context.Context, string, []string) ([]string, error) { return nil, nil }
	npmConfigGetFn = func(context.Context, string, string, []string) (string, error) { return "", errors.New("no npm") }
	t.Cleanup(func() { resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn = old, oldCached, oldGet, oldOmits })
	t.Setenv("npm_config_cache", "")
	npx, _ := Lookup("npx")
	npm, _ := Lookup("npm")
	for _, tt := range []struct {
		m         *Manager
		env, val  string
		args      []string
		wantFlags []string
	}{
		{npx, "NPM_CONFIG_USERCONFIG", "corp.npmrc", []string{"cowsay"}, []string{"--userconfig", absPath("corp.npmrc")}},
		{npx, "NPM_CONFIG_USERCONFIG", "corp.npmrc", []string{"--userconfig", "mine.npmrc", "cowsay"}, []string{"--userconfig", absPath("mine.npmrc")}},
		{npx, "NPM_CONFIG_USERCONFIG", absPath("corp.npmrc"), []string{"cowsay"}, nil},
		{npx, "npm_config_globalconfig", "g.npmrc", []string{"cowsay"}, []string{"--globalconfig", absPath("g.npmrc")}},
		{npm, "NPM_CONFIG_USERCONFIG", "corp.npmrc", []string{"install", "cowsay"}, []string{"--userconfig", absPath("corp.npmrc")}},
		{npm, "NPM_CONFIG_USERCONFIG", "corp.npmrc", []string{"install", "--userconfig=mine.npmrc", "cowsay"}, []string{"--userconfig", absPath("mine.npmrc")}},
	} {
		t.Setenv("NPM_CONFIG_USERCONFIG", "")
		t.Setenv("npm_config_globalconfig", "")
		t.Setenv(tt.env, tt.val)
		gotFlags = nil
		start := 0
		var parsed installArgs
		if tt.m == npx {
			parsed = npx.parseRun(tt.args)
			parsed.ToolRun = true
		} else {
			start = 1
			parsed = ParseSpecs(npm, tt.args[start:])
		}
		if _, err := expandInstall(context.Background(), tt.m, tt.args, start, parsed); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotFlags, tt.wantFlags) {
			t.Errorf("%s %s=%q %v: flags = %v, want %v", tt.m.Bin, tt.env, tt.val, tt.args, gotFlags, tt.wantFlags)
		}
	}
}

// npm reuses what an earlier run of the same packages left in its npx cache,
// with the dependencies resolved back then: the check covers that tree as
// well as today's resolution, deduplicated.
// A uv tool run may reuse a tool environment cached by an earlier run, with
// the dependencies resolved back then, so the cached environment's packages
// are checked beside the fresh resolution. The cache is --cache-dir, else
// what uv reports; a run that reads no cache or resolves afresh adds nothing.
func TestExpandInstall_ToolRunCoversTheUVCache(t *testing.T) {
	old, oldUV, oldCached, oldDir := resolvePythonFn, resolveWithUVFn, uvCachedFn, uvCacheDirFn
	fresh := func(context.Context, string, []string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "6.1"}, {Name: "six", Version: "1.17.0"}}, nil
	}
	resolvePythonFn = func(ctx context.Context, dir string, specs, uvFlags, _ []string) ([]catalog.Resolved, error) {
		return fresh(ctx, dir, specs, uvFlags)
	}
	resolveWithUVFn = fresh
	var cacheDir string
	var cacheWant map[string]string
	asked := 0
	uvCachedFn = func(dir string, want map[string]string) ([]catalog.Resolved, error) {
		cacheDir, cacheWant = dir, want
		asked++
		return []catalog.Resolved{{Name: "cowsay", Version: "6.1"}, {Name: "six", Version: "1.16.0"}}, nil
	}
	// uv answers with a relative path, as it does for a relative cache-dir
	// in a config file; selectorsAsked records the flags it was asked with.
	// The absolute answers are real ones, since a rooted path is not
	// absolute on Windows.
	fromUV := filepath.Join(t.TempDir(), "from-uv")
	cfgDir := filepath.Join(t.TempDir(), "cfg")
	var selectorsAsked []string
	dirAsked := false
	uvAnswer := fromUV
	uvCacheDirFn = func(_ context.Context, flags []string) (string, error) {
		dirAsked, selectorsAsked = true, flags
		return uvAnswer, nil
	}
	// The tool `uv tool install` keeps, asked for by name when the request
	// is bare.
	oldToolDir, oldInstalled := uvToolDirFn, uvInstalledFn
	toolsDir := filepath.Join(t.TempDir(), "tools")
	installedAsked := ""
	uvToolDirFn = func(context.Context, []string) (string, error) { return toolsDir, nil }
	uvInstalledFn = func(dir, name string) ([]catalog.Resolved, error) {
		installedAsked = name
		if dir != toolsDir {
			t.Errorf("installed tool read from %q, want %q", dir, toolsDir)
		}
		return []catalog.Resolved{{Name: "cowsay", Version: "6.0"}, {Name: "six", Version: "1.15.0"}}, nil
	}
	t.Setenv("UV_CACHE_DIR", "")
	t.Setenv("UV_TOOL_DIR", "")
	t.Cleanup(func() {
		resolvePythonFn, resolveWithUVFn, uvCachedFn, uvCacheDirFn = old, oldUV, oldCached, oldDir
		uvToolDirFn, uvInstalledFn = oldToolDir, oldInstalled
	})

	names := func(tree []catalog.Resolved) []string {
		var out []string
		for _, r := range tree {
			out = append(out, r.Name+"@"+r.Version)
		}
		return out
	}
	uvx, _ := Lookup("uvx")
	uv, _ := Lookup("uv")
	// What a run may execute: the fresh resolution, the cached environment
	// (cached), and for a bare request the installed tool too (all); with
	// no cache read, the fresh resolution and the installed tool (noCache).
	cached := []string{"cowsay@6.1", "six@1.17.0", "six@1.16.0"}
	all := []string{"cowsay@6.1", "six@1.17.0", "six@1.16.0", "cowsay@6.0", "six@1.15.0"}
	noCache := []string{"cowsay@6.1", "six@1.17.0", "cowsay@6.0", "six@1.15.0"}
	for _, tt := range []struct {
		m             *Manager
		args          []string
		uvAnswer      string
		wantCache     string
		wantSelectors []string
		wantWant      map[string]string
		wantTree      []string
		wantInstalled string
	}{
		{uvx, []string{"cowsay@6.1", "-t", "hi"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": "6.1"}, cached, ""},
		// A bare request runs the installed tool as installed, so its
		// environment is read too: the command, or --from, with no version,
		// `@latest`, --with or --isolated.
		{uvx, []string{"cowsay", "-t", "hi"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": ""}, all, "cowsay"},
		{uvx, []string{"--from", "cowsay", "cowsay", "-t", "hi"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": ""}, all, "cowsay"},
		{uv, []string{"tool", "run", "cowsay"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": ""}, all, "cowsay"},
		{uvx, []string{"cowsay@latest"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": ""}, cached, ""},
		{uvx, []string{"--isolated", "cowsay"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": ""}, cached, ""},
		{uvx, []string{"--cache-dir", "c", "--with", "Rich", "cowsay", "-t", "hi"}, "", absPath("c"), nil, map[string]string{"cowsay": "", "rich": ""}, cached, ""},
		// A --with requirement with a marker may not be installed at all,
		// so a cached environment is not asked to hold it.
		{uvx, []string{"--with", "rich; sys_platform == \"win32\"", "cowsay"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": ""}, cached, ""},
		// Unless it is also requested unconditionally.
		{uvx, []string{"--with", "rich; sys_platform == \"win32\"", "--with", "rich", "cowsay"}, fromUV, fromUV, []string{}, map[string]string{"cowsay": "", "rich": ""}, cached, ""},
		{uv, []string{"--cache-dir=d", "tool", "run", "--index", "https://i.example", "cowsay"}, "", absPath("d"), nil, map[string]string{"cowsay": ""}, all, "cowsay"},
		// A relative --cache-dir is relative to the directory the run
		// changes to, as is a relative answer from uv.
		{uvx, []string{"--directory", "sub", "--cache-dir", "c", "cowsay"}, "", absPath("sub/c"), nil, map[string]string{"cowsay": ""}, all, "cowsay"},
		{uv, []string{"--directory", "sub", "tool", "run", "cowsay"}, "rel", absPath("sub/rel"), []string{}, map[string]string{"cowsay": ""}, all, "cowsay"},
		// The configuration selectors reach uv, the file made absolute.
		{uvx, []string{"--config-file", "custom.toml", "cowsay"}, cfgDir, cfgDir, []string{"--config-file", absPath("custom.toml")}, map[string]string{"cowsay": ""}, all, "cowsay"},
		{uv, []string{"--no-config", "--directory", "sub", "tool", "run", "--config-file", "c.toml", "cowsay"}, cfgDir, cfgDir,
			[]string{"--no-config", "--config-file", absPath("sub/c.toml")}, map[string]string{"cowsay": ""}, all, "cowsay"},
		// The cache flags govern the cache; the installed tool runs anyway.
		{uvx, []string{"--no-cache", "cowsay"}, "", "", nil, nil, noCache, "cowsay"},
		{uvx, []string{"--refresh", "cowsay"}, "", "", nil, nil, noCache, "cowsay"},
		{uv, []string{"-n", "tool", "run", "cowsay"}, "", "", nil, nil, noCache, "cowsay"},
		{uvx, []string{"--no-cache", "cowsay@6.1"}, "", "", nil, nil, []string{"cowsay@6.1", "six@1.17.0"}, ""},
	} {
		cacheDir, cacheWant, asked, dirAsked, selectorsAsked, uvAnswer, installedAsked = "", nil, 0, false, nil, tt.uvAnswer, ""
		start := 0
		if tt.m == uv {
			var ok bool
			if start, ok = uv.toolRunAt(tt.args); !ok {
				t.Fatalf("%v: not a tool run", tt.args)
			}
		}
		parsed := parseToolRun(tt.m, tt.args[start:])
		parsed.ToolRun = true
		tree, err := expandInstall(context.Background(), tt.m, tt.args, start, parsed)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(names(tree), tt.wantTree) {
			t.Errorf("%s %v: tree = %v, want %v", tt.m.Bin, tt.args, names(tree), tt.wantTree)
		}
		if (asked == 0) != (tt.wantWant == nil) || cacheDir != tt.wantCache || !reflect.DeepEqual(cacheWant, tt.wantWant) {
			t.Errorf("%s %v: cache read %d times from %q for %v, want %q for %v", tt.m.Bin, tt.args, asked, cacheDir, cacheWant, tt.wantCache, tt.wantWant)
		}
		if dirAsked != (tt.wantSelectors != nil) || len(selectorsAsked) != len(tt.wantSelectors) || (len(tt.wantSelectors) > 0 && !reflect.DeepEqual(selectorsAsked, tt.wantSelectors)) {
			t.Errorf("%s %v: uv cache dir asked = %v with %v, want %v with %v", tt.m.Bin, tt.args, dirAsked, selectorsAsked, tt.wantSelectors != nil, tt.wantSelectors)
		}
		if installedAsked != tt.wantInstalled {
			t.Errorf("%s %v: installed tool read for %q, want %q", tt.m.Bin, tt.args, installedAsked, tt.wantInstalled)
		}
	}

	// An unreadable cache adds nothing and fails nothing.
	uvCachedFn = func(string, map[string]string) ([]catalog.Resolved, error) { return nil, errors.New("unreadable") }
	args := []string{"cowsay@6.1"}
	parsed := parseToolRun(uvx, args)
	parsed.ToolRun = true
	if tree, err := expandInstall(context.Background(), uvx, args, 0, parsed); err != nil || len(tree) != 2 {
		t.Errorf("unreadable cache: tree = %v, err = %v", tree, err)
	}
}

func TestExpandInstall_ToolRunCoversTheNpxCache(t *testing.T) {
	old, oldCached, oldGet, oldInc := resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn
	// npm's configuration includes nothing here, whatever the host's does.
	// npm answers the omit policy as its own parse of the flags would.
	npmConfigOmitsFn = func(_ context.Context, _ string, flags []string) ([]string, error) {
		var kinds []string
		for _, f := range flags {
			if k, ok := strings.CutPrefix(f, "--omit="); ok {
				kinds = append(kinds, k)
			}
		}
		return kinds, nil
	}
	// Today's resolution fetches get-stdin from the internal registry, as a
	// dev dependency; the cache holds the same release fetched publicly,
	// and an older one.
	resolveNpmFn = func(context.Context, string, string, []string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"},
			{Name: "get-stdin", Version: "8.0.0", Registry: "https://npm.acme.internal/get-stdin/-/get-stdin-8.0.0.tgz", Dev: true}}, nil
	}
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"},
			{Name: "get-stdin", Version: "8.0.0", Registry: "https://registry.npmjs.org/get-stdin/-/get-stdin-8.0.0.tgz"},
			{Name: "get-stdin", Version: "7.0.0", Registry: "https://registry.npmjs.org/get-stdin/-/get-stdin-7.0.0.tgz"}}, nil
	}
	npmConfigGetFn = func(context.Context, string, string, []string) (string, error) { return "", errors.New("no npm") }
	t.Cleanup(func() {
		resolveNpmFn, npxCachedFn, npmConfigGetFn, npmConfigOmitsFn = old, oldCached, oldGet, oldInc
	})

	names := func(tree []catalog.Resolved) []string {
		var out []string
		for _, r := range tree {
			out = append(out, r.Name+"@"+r.Version)
		}
		return out
	}
	// Both ways of running a tool through npm read the cache.
	for _, tt := range []struct {
		manager string
		args    []string
	}{
		{"npm", []string{"exec", "cowsay@1.6.0"}},
		{"npx", []string{"cowsay@1.6.0"}},
	} {
		m, _ := Lookup(tt.manager)
		parsed := m.parseRun(tt.args)
		parsed.ToolRun = true
		tree, err := expandInstall(context.Background(), m, tt.args, 0, parsed)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"cowsay@1.6.0", "get-stdin@8.0.0", "get-stdin@7.0.0"}; !reflect.DeepEqual(names(tree), want) {
			t.Errorf("%s %v: tree = %v, want %v", tt.manager, tt.args, names(tree), want)
		}
		// A release both report keeps neither sighting's excuse: the
		// registries disagree so none is recorded, and only the fresh copy
		// was a dev dependency.
		if got := tree[1]; got.Registry != "" || got.Dev {
			t.Errorf("%s %v: merged sighting = %+v, want no registry and not dev", tt.manager, tt.args, got)
		}
	}

	// So a registry the fresh fetch trusts does not cover the cached copy
	// fetched publicly: the release is checked.
	npx, _ := Lookup("npx")
	args := []string{"cowsay@1.6.0"}
	parsed := npx.parseRun(args)
	parsed.ToolRun = true
	ctx := warn.NewContext(context.Background(), true)
	set := resolveNamed(ctx, npx, Options{Args: args, Trust: trust.Policy{Registries: []string{"https://npm.acme.internal/"}}}, 0, parsed, nil)
	want := []check.Spec{
		{Ecosystem: "npm", Name: "cowsay", Version: "1.6.0"},
		{Ecosystem: "npm", Name: "get-stdin", Version: "8.0.0"},
		{Ecosystem: "npm", Name: "get-stdin", Version: "7.0.0"},
	}
	if !reflect.DeepEqual(set.specs, want) {
		t.Errorf("specs = %+v, want %+v", set.specs, want)
	}
	if drained := warn.Drain(ctx); strings.Contains(drained, "trusted") {
		t.Errorf("a publicly cached release was trusted:\n%s", drained)
	}

	// The omit policy prunes the fresh prediction only: npm reuses a cached
	// installation as it is, so an optional dependency it holds runs under
	// --omit=optional too, and stays checked.
	resolveNpmFn = func(context.Context, string, string, []string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"}, {Name: "extra", Version: "2.0.0", Optional: true}}, nil
	}
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) {
		return []catalog.Resolved{{Name: "cowsay", Version: "1.6.0"}, {Name: "extra", Version: "2.0.0", Optional: true},
			{Name: "extra", Version: "1.0.0", Optional: true}}, nil
	}
	omitArgs := []string{"--omit=optional", "cowsay@1.6.0"}
	omitParsed := npx.parseRun(omitArgs)
	omitParsed.ToolRun = true
	tree, err := expandInstall(context.Background(), npx, omitArgs, 0, omitParsed)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cowsay@1.6.0", "extra@2.0.0", "extra@1.0.0"}; !reflect.DeepEqual(names(tree), want) {
		t.Errorf("--omit=optional with a cache: tree = %v, want %v", names(tree), want)
	}
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) { return nil, nil }
	if tree, err := expandInstall(context.Background(), npx, omitArgs, 0, omitParsed); err != nil || !reflect.DeepEqual(names(tree), []string{"cowsay@1.6.0"}) {
		t.Errorf("--omit=optional without a cache: tree = %v, err = %v", names(tree), err)
	}

	// A cache that cannot be read adds nothing and fails nothing.
	npxCachedFn = func(string, []string) ([]catalog.Resolved, error) { return nil, errors.New("unreadable") }
	if tree, err := expandInstall(context.Background(), npx, args, 0, parsed); err != nil || len(tree) != 2 {
		t.Errorf("unreadable cache: tree = %v, err = %v", tree, err)
	}
}
