package forward

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
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
	}, 1, parsed, nil, true)

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
	}, true)
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
	}, true)
	if set.named != 1 || set.deps != 0 || len(set.specs) != 1 {
		t.Errorf("set = %+v", set)
	}
}

// A tool run fetches one package and runs it; it is not expanded.
func TestRun_ToolRun_DoesNotExpand(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	swapExpand(t, func(context.Context, *Manager, []string, int, installArgs) ([]catalog.Resolved, error) {
		t.Error("a tool run was expanded")
		return nil, nil
	})
	if err := Run(context.Background(), Options{Bin: "uvx", Args: []string{"ruff@0.6.0", "check", "."}}); err != nil {
		t.Fatalf("Run: %v", err)
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
		{"uv to pip renames the index flags",
			pipResolveFlags(uv, []string{"--index", "https://i.example", "--default-index=https://d.example", "--resolution", "lowest", "httpx"}),
			[]string{"--extra-index-url", "https://i.example", "--index-url=https://d.example"}},
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
