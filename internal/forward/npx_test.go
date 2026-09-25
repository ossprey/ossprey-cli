package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// noLocalBins makes every name look absent from node_modules, so a parse test
// does not depend on the directory it runs in.
func noLocalBins(t *testing.T) {
	t.Helper()
	old := localBinFn
	localBinFn = func(string, bool) bool { return false }
	t.Cleanup(func() { localBinFn = old })
}

func TestNpxParse(t *testing.T) {
	noLocalBins(t)
	npm := func(name, version string) check.Spec {
		return check.Spec{Ecosystem: "npm", Name: name, Version: version}
	}
	cases := []struct {
		name  string
		args  []string
		specs []check.Spec
		non   []string
	}{
		{"bare command", []string{"cowsay"}, []check.Spec{npm("cowsay", "")}, nil},
		// Only the first positional is a package: moo is cowsay's argv, and a
		// real npm package too.
		{"program args are not packages", []string{"cowsay", "moo"}, []check.Spec{npm("cowsay", "")}, nil},
		{"program flags are not ours", []string{"cowsay", "-p", "evil"}, []check.Spec{npm("cowsay", "")}, nil},
		{"pinned", []string{"cowsay@1.5.0", "moo"}, []check.Spec{npm("cowsay", "1.5.0")}, nil},
		{"scoped pinned", []string{"@angular/cli@17.0.0", "new", "app"}, []check.Spec{npm("@angular/cli", "17.0.0")}, nil},
		// Tags and ranges keep the specifier for resolveNpxSpecifiers.
		{"dist-tag kept", []string{"create-vite@next", "app"}, []check.Spec{npm("create-vite", "next")}, nil},
		{"range kept", []string{"cowsay@^1"}, []check.Spec{npm("cowsay", "^1")}, nil},
		{"exact normalised", []string{"cowsay@v1.5.0"}, []check.Spec{npm("cowsay", "1.5.0")}, nil},
		// Shorthands and option values, per npm's own definitions.
		{"loglevel value", []string{"--loglevel", "silent", "cowsay"}, []check.Spec{npm("cowsay", "")}, nil},
		{"silent shorthand carries its value", []string{"-s", "cowsay", "moo"}, []check.Spec{npm("cowsay", "")}, nil},
		{"removed -n takes a value", []string{"-n", "--inspect", "cowsay"}, []check.Spec{npm("cowsay", "")}, nil},
		{"negated boolean", []string{"--no-yes", "cowsay", "moo"}, []check.Spec{npm("cowsay", "")}, nil},
		{"boolean with explicit value", []string{"--yes", "true", "cowsay"}, []check.Spec{npm("cowsay", "")}, nil},
		// A string option in npm 12 and unknown (so boolean) in npm 10: either
		// token may be what runs, so both are checked.
		{"version-dependent option checks both readings", []string{"--allow-scripts", "helper-pkg", "evil-pkg", "arg"},
			[]check.Spec{npm("helper-pkg", ""), npm("evil-pkg", "")}, nil},
		{"unknown flag checks both readings", []string{"--brand-new-flag", "a", "b"},
			[]check.Spec{npm("a", ""), npm("b", "")}, nil},
		{"inline version-dependent value is not a candidate", []string{"--allow-scripts=helper-pkg", "evil-pkg"},
			[]check.Spec{npm("evil-pkg", "")}, nil},
		{"leading options", []string{"-y", "--quiet", "create-react-app", "my-app"}, []check.Spec{npm("create-react-app", "")}, nil},
		{"value flag before command", []string{"--registry", "https://r.example", "cowsay"}, []check.Spec{npm("cowsay", "")}, nil},
		{"double dash", []string{"--yes", "--", "cowsay", "moo"}, []check.Spec{npm("cowsay", "")}, nil},
		// With -p, the positional is a command the packages provide.
		{"package flag", []string{"-p", "typescript@5.4.0", "tsc", "--version"}, []check.Spec{npm("typescript", "5.4.0")}, nil},
		{"package flag inline and repeated", []string{"--package=yo", "--package", "generator-code", "--", "yo", "code"},
			[]check.Spec{npm("yo", ""), npm("generator-code", "")}, nil},
		{"call with package", []string{"-p", "cowsay", "-c", "cowsay hi"}, []check.Spec{npm("cowsay", "")}, nil},
		{"call alone fetches nothing", []string{"-c", "eslint ."}, nil, nil},
		{"alias", []string{"npm:cowsay@1.5.0"}, []check.Spec{npm("cowsay", "1.5.0")}, nil},
		{"git target", []string{"github:user/repo"}, nil, []string{"github:user/repo"}},
		{"local path", []string{"./tool"}, nil, []string{"./tool"}},
		{"nothing", []string{"--version"}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := npxParse(tc.args)
			if !reflect.DeepEqual(got.Specs, tc.specs) {
				t.Errorf("specs = %+v, want %+v", got.Specs, tc.specs)
			}
			if !reflect.DeepEqual(got.NonPackages, tc.non) {
				t.Errorf("non-packages = %v, want %v", got.NonPackages, tc.non)
			}
		})
	}
}

func TestNpxLocalBinIsNotChecked(t *testing.T) {
	old := localBinFn
	localBinFn = func(name string, _ bool) bool { return name == "eslint" }
	t.Cleanup(func() { localBinFn = old })

	if got := npxParse([]string{"eslint", "."}).Specs; len(got) != 0 {
		t.Errorf("a project-local bin runs from node_modules and fetches nothing; got specs %+v", got)
	}
	// A pinned version is fetched unless the local copy matches, so it is checked.
	if got := npxParse([]string{"eslint@9.0.0", "."}).Specs; len(got) != 1 {
		t.Errorf("a pinned command must still be checked; got %+v", got)
	}
}

// --prefix moves the project npx runs from, so a bin found from the current
// directory says nothing about what npx will fetch.
func TestNpxPrefixDisablesTheLocalBinSkip(t *testing.T) {
	old := localBinFn
	localBinFn = func(string, bool) bool { return true }
	t.Cleanup(func() { localBinFn = old })

	for _, args := range [][]string{
		{"--prefix", "/tmp/empty", "eslint"},
		{"--prefix=/tmp/empty", "eslint"},
		{"-C", "/tmp/empty", "eslint"},
	} {
		if got := npxParse(args).Specs; len(got) != 1 || got[0].Name != "eslint" {
			t.Errorf("%v: specs = %+v, want eslint checked", args, got)
		}
	}
	if got := npxParse([]string{"eslint"}).Specs; len(got) != 0 {
		t.Errorf("without --prefix the local bin is used; got %+v", got)
	}
}

func TestLocalBin(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "node_modules", ".bin"), 0o755))
	must(os.WriteFile(filepath.Join(root, "node_modules", ".bin", "tsc"), nil, 0o755))
	must(os.MkdirAll(filepath.Join(root, "node_modules", "@scope", "tool"), 0o755))
	must(os.WriteFile(filepath.Join(root, "node_modules", "@scope", "tool", "package.json"), []byte("{}"), 0o644))
	sub := filepath.Join(root, "src", "deep")
	must(os.MkdirAll(sub, 0o755))
	t.Chdir(sub)

	if !localBin("tsc", true) {
		t.Error("tsc is a bin in the nearest project's node_modules/.bin")
	}
	if localBin("tsc", false) {
		t.Error("a -p package is looked up as a package, not as a bin")
	}
	if !localBin("@scope/tool", false) {
		t.Error("@scope/tool is installed in the project")
	}
	if localBin("cowsay", true) {
		t.Error("cowsay is not installed")
	}

	// A nearer project root stops the walk: npm does not look past it.
	must(os.WriteFile(filepath.Join(sub, "package.json"), []byte("{}"), 0o644))
	if localBin("tsc", true) {
		t.Error("the walk must stop at the nearest package.json")
	}
}

func TestRun_Npx_ChecksThePackageBeforeRunningIt(t *testing.T) {
	noLocalBins(t)
	var order []string
	var gotSpecs []check.Spec
	swap(t, func(_ context.Context, bin string, _ []string) error {
		order = append(order, "exec:"+bin)
		return nil
	}, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		order, gotSpecs = append(order, "check"), o.Specs
		return ossbom.New(ossbom.Environment{}), nil
	})

	args := []string{"-y", "cowsay@1.5.0", "moo"}
	if err := Run(context.Background(), Options{Bin: "npx", Args: args}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := []string{"check", "exec:npx"}; !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	if want := []check.Spec{{Ecosystem: "npm", Name: "cowsay", Version: "1.5.0"}}; !reflect.DeepEqual(gotSpecs, want) {
		t.Errorf("checked %+v, want %+v", gotSpecs, want)
	}
}

func TestRun_Npx_MalwareBlocks(t *testing.T) {
	noLocalBins(t)
	ex := &stubExec{}
	swap(t, ex.fn, malwareSBOM)

	err := Run(context.Background(), Options{Bin: "npx", Args: []string{"evil@1.0.0"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("npx must not run a package flagged as malware")
	}
}

// Naming nothing to fetch is not a manifest install: npx runs something already
// on disk, so it must forward without scanning the project.
func TestRun_Npx_NothingToFetchForwardsWithoutScan(t *testing.T) {
	old := localBinFn
	localBinFn = func(string, bool) bool { return true }
	t.Cleanup(func() { localBinFn = old })

	for _, args := range [][]string{{"eslint", "."}, {"-c", "echo hi"}, {"--version"}, {"github:user/repo"}} {
		ex := &stubExec{}
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			t.Errorf("%v: nothing is fetched, so nothing should be checked", args)
			return nil, nil
		})
		if err := Run(context.Background(), Options{Bin: "npx", Args: args}); err != nil {
			t.Fatalf("%v: Run: %v", args, err)
		}
		if !ex.called || !reflect.DeepEqual(ex.args, args) {
			t.Errorf("%v: forwarded %v (called=%v)", args, ex.args, ex.called)
		}
	}
}

// runNpxResolving runs npx with a stub resolver and returns what was checked
// and what the resolver was asked.
func runNpxResolving(t *testing.T, args []string, resolve func(name, spec string, pick registry.NpmPick) string) ([]check.Spec, []string) {
	t.Helper()
	noLocalBins(t)
	ex := &stubExec{}
	var got []check.Spec
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o.Specs
		return ossbom.New(ossbom.Environment{}), nil
	})
	var asked []string
	err := Run(warn.NewContext(context.Background(), false), Options{
		Bin:  "npx",
		Args: args,
		ResolveSpec: func(_ context.Context, name, spec string, pick registry.NpmPick) (string, error) {
			asked = append(asked, fmt.Sprintf("%s@%s tag=%q before=%s", name, spec, pick.DefaultTag, pick.Before.Format(time.RFC3339)))
			return resolve(name, spec, pick), nil
		},
		ResolveLatest: func(context.Context, string, string) (string, error) {
			t.Error("npx must resolve through the npm-aware resolver, never plain latest")
			return "", errors.New("unused")
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return got, asked
}

// Every non-exact spec — an unpinned name included — is checked at the release
// npm would run for it: a malicious release can sit behind @next, on an older
// major line, or behind a deprecated latest.
func TestRun_Npx_ResolvesSpecifiersToWhatNpxRuns(t *testing.T) {
	got, asked := runNpxResolving(t,
		[]string{"-p", "create-vite@next", "-p", "cowsay@^1", "-p", "left-pad", "-p", "exact@1.0.0", "create-vite", "app"},
		func(_, spec string, _ registry.NpmPick) string {
			return map[string]string{"next": "6.0.0-beta.2", "^1": "1.5.0", "": "1.3.0"}[spec]
		})
	want := []check.Spec{
		{Ecosystem: "npm", Name: "create-vite", Version: "6.0.0-beta.2"},
		{Ecosystem: "npm", Name: "cowsay", Version: "1.5.0"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
		{Ecosystem: "npm", Name: "exact", Version: "1.0.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("checked %+v, want %+v", got, want)
	}
	if len(asked) != 3 {
		t.Errorf("an exact version needs no resolving; asked %v", asked)
	}
}

// --tag and --before change what npx runs, so they reach the resolver, from a
// flag or from npm_config_* (the flag wins).
func TestRun_Npx_TagAndBeforeReachTheResolver(t *testing.T) {
	stub := func(string, string, registry.NpmPick) string { return "1.0.0" }
	cases := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"flags", nil, []string{"--tag", "beta", "--before", "2024-06-01", "cowsay"},
			`cowsay@ tag="beta" before=2024-06-01T00:00:00Z`},
		{"inline and alias", nil, []string{"--tag=beta", "--enjoy-by=2024-06-01T12:00:00Z", "cowsay@^1"},
			`cowsay@^1 tag="beta" before=2024-06-01T12:00:00Z`},
		{"environment", map[string]string{"NPM_CONFIG_TAG": "canary", "npm_config_before": "2024-06-01"}, []string{"cowsay"},
			`cowsay@ tag="canary" before=2024-06-01T00:00:00Z`},
		{"flag beats environment", map[string]string{"npm_config_tag": "canary"}, []string{"--tag", "beta", "cowsay"},
			`cowsay@ tag="beta" before=0001-01-01T00:00:00Z`},
		// A tag value is not the package.
		{"value is consumed", nil, []string{"--tag", "latest", "cowsay"},
			`cowsay@ tag="latest" before=0001-01-01T00:00:00Z`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("npm_config_tag", "")
			os.Unsetenv("npm_config_tag")
			t.Setenv("npm_config_before", "")
			os.Unsetenv("npm_config_before")
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			_, asked := runNpxResolving(t, c.args, stub)
			if len(asked) != 1 || asked[0] != c.want {
				t.Errorf("resolver asked %v, want [%s]", asked, c.want)
			}
		})
	}
}

// A --before npm might read but ossprey cannot must not be guessed at: the
// affected check is skipped with a warning, never reported clean. An exact
// version does not depend on the date and is still checked.
func TestRun_Npx_UnreadableBeforeSkipsTheCheck(t *testing.T) {
	var buf bytes.Buffer
	old := errOut
	errOut = &buf
	t.Cleanup(func() { errOut = old })

	got, asked := runNpxResolving(t,
		[]string{"--before", "next tuesday", "-p", "cowsay", "-p", "exact@1.0.0", "cowsay"},
		func(string, string, registry.NpmPick) string { return "9.9.9" })
	if len(asked) != 0 {
		t.Errorf("nothing should be resolved against a date we cannot read; asked %v", asked)
	}
	if want := []check.Spec{{Ecosystem: "npm", Name: "exact", Version: "1.0.0"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("checked %+v, want %+v", got, want)
	}
	if !strings.Contains(buf.String(), "--before date ossprey cannot read; skipping its check") {
		t.Errorf("expected the skipped check to be named, got:\n%s", buf.String())
	}
}

func TestParseNpmDate(t *testing.T) {
	for in, want := range map[string]string{
		"2024-06-01":                "2024-06-01T00:00:00Z",
		"2024-06-01T12:30:00Z":      "2024-06-01T12:30:00Z",
		"2024-06-01T12:30:00.000Z":  "2024-06-01T12:30:00Z",
		"2024-06-01T12:30:00+02:00": "2024-06-01T10:30:00Z",
	} {
		got, ok := parseNpmDate(in)
		if !ok || got.UTC().Format(time.RFC3339) != want {
			t.Errorf("parseNpmDate(%q) = %v, %v; want %s", in, got, ok, want)
		}
	}
	if _, ok := parseNpmDate("next tuesday"); ok {
		t.Error("an unreadable date must be reported, not guessed")
	}
}

// An unresolvable specifier is never reported as checked.
func TestRun_Npx_UnresolvableSpecifierIsNotReportedClean(t *testing.T) {
	noLocalBins(t)
	ex := &stubExec{}
	swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
		t.Error("nothing resolved, so nothing should be checked")
		return nil, nil
	})
	var buf bytes.Buffer
	old := errOut
	errOut = &buf
	t.Cleanup(func() { errOut = old })

	ctx := warn.NewContext(context.Background(), false)
	err := Run(ctx, Options{
		Bin:  "npx",
		Args: []string{"cowsay@^9"},
		ResolveSpec: func(context.Context, string, string, registry.NpmPick) (string, error) {
			return "", fmt.Errorf("%w cowsay@^9", registry.ErrNoMatch)
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "matched no published release; skipping its check") {
		t.Errorf("expected the skipped check to be named, got:\n%s", out)
	}
	if strings.Contains(out, "no malware found") {
		t.Errorf("an unchecked package must not read as clean:\n%s", out)
	}
}

// npx writes no lockfile, so passive mode submits the named package alongside
// the run rather than cataloguing the directory afterwards.
func TestRun_Npx_PassiveSubmitsTheNamedPackage(t *testing.T) {
	noLocalBins(t)
	ex := &stubExec{}
	var got check.Options
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o
		return malwareSBOM(context.Background(), o)
	})
	err := Run(context.Background(), Options{Bin: "npx", Args: []string{"evil@1.0.0"}, Passive: true})
	if err != nil {
		t.Fatalf("passive never blocks: %v", err)
	}
	if !ex.called {
		t.Error("passive must run npx")
	}
	if !got.SubmitOnly || len(got.Specs) != 1 || got.Specs[0].Name != "evil" {
		t.Errorf("submitted %+v, want evil submit-only", got)
	}
}

// TestNpxTablesAgreeWithInstalledNpm re-derives npx_flags.go from the npm on
// PATH. A flag missing from both tables is fine — npxParse checks both
// readings of it — but one in the wrong table moves the check onto the wrong
// token: a boolean read as an option swallows the package, an option read as a
// boolean checks its value instead of what runs.
func TestNpxTablesAgreeWithInstalledNpm(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	defs := installedNpmDefinitions(t, node)
	if defs == "" {
		t.Skip("could not locate npm's config definitions")
	}
	script := `const {definitions, shorthands} = require(process.argv[1]);
const out = {switches: [], options: [], shorthands};
for (const [k, {type}] of Object.entries(definitions))
  (type === Boolean || (Array.isArray(type) && type.includes(Boolean)) ? out.switches : out.options).push(k);
console.log(JSON.stringify(out));`
	raw, err := exec.Command(node, "-e", script, defs).Output()
	if err != nil {
		t.Skipf("reading %s: %v", defs, err)
	}
	var got struct {
		Switches   []string            `json:"switches"`
		Options    []string            `json:"options"`
		Shorthands map[string][]string `json:"shorthands"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range got.Switches {
		if npxOptions[k] {
			t.Errorf("--%s is a boolean in the installed npm but npxOptions says it takes a value", k)
		}
	}
	for _, k := range got.Options {
		if npxSwitches[k] {
			t.Errorf("--%s takes a value in the installed npm but npxSwitches says it is a boolean", k)
		}
	}
	for k, exp := range got.Shorthands {
		ours, ok := npxShorthands[k]
		if !ok || k == "p" || k == "n" {
			continue // unknown to us is ambiguous (safe); npx overrides p and n
		}
		want := ""
		if len(exp) == 1 {
			want = strings.TrimPrefix(exp[0], "--")
		}
		if ours != want {
			t.Errorf("shorthand -%s: installed npm expands to %v, npxShorthands says %q", k, exp, ours)
		}
	}
}

// installedNpmDefinitions finds @npmcli/config's definitions inside the npm
// that ships with node, wherever this platform keeps it.
func installedNpmDefinitions(t *testing.T, node string) string {
	t.Helper()
	var roots []string
	if npm, err := exec.LookPath("npm"); err == nil {
		if out, err := exec.Command(npm, "root", "-g").Output(); err == nil {
			roots = append(roots, filepath.Join(strings.TrimSpace(string(out)), "npm"))
		}
	}
	if real, err := filepath.EvalSymlinks(node); err == nil {
		dir := filepath.Dir(real)
		roots = append(roots,
			filepath.Join(dir, "node_modules", "npm"),              // Windows
			filepath.Join(dir, "..", "lib", "node_modules", "npm")) // Unix
	}
	for _, r := range roots {
		p := filepath.Join(r, "node_modules", "@npmcli", "config", "lib", "definitions", "index.js")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
