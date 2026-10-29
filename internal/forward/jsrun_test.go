package forward

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/shim"
)

func npmSpec(name, version string) check.Spec {
	return check.Spec{Ecosystem: "npm", Name: name, Version: version}
}

func TestNpxRun(t *testing.T) {
	tests := []struct {
		args      []string
		wantSpecs []check.Spec
		wantLocal string
	}{
		// Only the command is a package; the rest is the program's argv.
		{[]string{"cowsay", "moo"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		{[]string{"cowsay", "--package", "evil"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		{[]string{"-y", "cowsay", "moo"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		{[]string{"cowsay@1.5.0", "--help"}, []check.Spec{npmSpec("cowsay", "1.5.0")}, ""},
		// An explicit tag is kept as typed: npm fetches it whatever --tag
		// says, and never takes a tag spec from the local tree.
		{[]string{"cowsay@latest"}, []check.Spec{npmSpec("cowsay", "")}, ""},
		{[]string{"@scope/tool@2.0.0", "x"}, []check.Spec{npmSpec("@scope/tool", "2.0.0")}, ""},
		{[]string{"--", "cowsay", "--yes"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		// --package names what is fetched; the positional is only its binary.
		{[]string{"-p", "cowsay@1.5.0", "cowsay", "hi"}, []check.Spec{npmSpec("cowsay", "1.5.0")}, ""},
		{[]string{"--package=a@1.0.0", "-p", "b@2.0.0", "run-it"}, []check.Spec{npmSpec("a", "1.0.0"), npmSpec("b", "2.0.0")}, ""},
		{[]string{"--package", "cowsay@latest", "cowsay"}, []check.Spec{npmSpec("cowsay", "")}, ""},
		// Value options must not leave their value standing in for the command.
		{[]string{"--registry", "https://registry.npmjs.org", "cowsay"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		{[]string{"--cache", "/tmp/c", "--loglevel", "silent", "cowsay"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		// A negated switch npx itself misreads as taking a value: npm still
		// runs cowsay, so cowsay is what must be checked.
		{[]string{"--no-update-notifier", "cowsay", "moo"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		// --call runs a shell command; with no --package nothing is fetched.
		{[]string{"-c", "eslint ."}, nil, ""},
		{[]string{"-p", "eslint@9.0.0", "-c", "eslint ."}, []check.Spec{npmSpec("eslint", "9.0.0")}, ""},
		{[]string{"--version"}, nil, ""},
		{[]string{"./local-script.js"}, nil, ""},
	}
	for _, tc := range tests {
		got := npxRun(tc.args)
		if !reflect.DeepEqual(got.Specs, tc.wantSpecs) || got.LocalCommand != tc.wantLocal {
			t.Errorf("npxRun(%q) = specs %+v local %q; want %+v local %q",
				tc.args, got.Specs, got.LocalCommand, tc.wantSpecs, tc.wantLocal)
		}
	}
}

func TestNpmExecRun(t *testing.T) {
	tests := []struct {
		args      []string
		wantSpecs []check.Spec
	}{
		{[]string{"exec", "cowsay", "moo"}, []check.Spec{npmSpec("cowsay", "")}},
		{[]string{"x", "--", "cowsay", "--package=evil"}, []check.Spec{npmSpec("cowsay", "")}},
		{[]string{"--yes", "exec", "cowsay"}, []check.Spec{npmSpec("cowsay", "")}},
		// npm reads options after the command too, unless "--" ends them.
		{[]string{"exec", "cowsay", "--package", "left-pad@1.3.0"}, []check.Spec{npmSpec("left-pad", "1.3.0")}},
		{[]string{"exec", "--package=left-pad@1.3.0", "--", "left-pad"}, []check.Spec{npmSpec("left-pad", "1.3.0")}},
		// For npm itself -p is --parseable, not --package.
		{[]string{"exec", "-p", "cowsay", "moo"}, []check.Spec{npmSpec("cowsay", "")}},
		{[]string{"exec", "--workspace", "web", "cowsay"}, []check.Spec{npmSpec("cowsay", "")}},
	}
	for _, tc := range tests {
		if got := npmExecRun(tc.args); !reflect.DeepEqual(got.Specs, tc.wantSpecs) {
			t.Errorf("npmExecRun(%q) = %+v, want %+v", tc.args, got.Specs, tc.wantSpecs)
		}
	}
}

// A command bunx fetches under another package's name keeps its tag on the
// token the resolver reads: `tsc@latest` is `typescript@latest`, not the
// configured tag's TypeScript.
func TestBunxRun_AliasKeepsTheTag(t *testing.T) {
	bunx, _ := Lookup("bunx")
	for _, tt := range []struct {
		args []string
		want []string
	}{
		{[]string{"tsc@latest", "--noEmit"}, []string{"typescript@latest"}},
		{[]string{"claude@2.0.0"}, []string{"@anthropic-ai/claude-code@2.0.0"}},
		{[]string{"tsc"}, []string{"typescript"}},
		// An explicit --package is kept as typed too.
		{[]string{"--package", "cowsay@latest", "cowsay"}, []string{"cowsay@latest"}},
	} {
		parsed := bunx.parseRun(tt.args)
		if got := specTokens(bunx, parsed); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%v: tokens = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestBunxRun(t *testing.T) {
	tests := []struct {
		args      []string
		wantSpecs []check.Spec
		wantLocal string
	}{
		{[]string{"cowsay", "moo"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		{[]string{"--bun", "--silent", "cowsay", "--package", "evil"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		// bunx gives "--" no meaning: the next positional is still the package.
		{[]string{"--", "cowsay"}, []check.Spec{npmSpec("cowsay", "")}, "cowsay"},
		{[]string{"cowsay@1.5.0"}, []check.Spec{npmSpec("cowsay", "1.5.0")}, ""},
		{[]string{"-p", "@angular/cli@17.0.0", "ng", "new"}, []check.Spec{npmSpec("@angular/cli", "17.0.0")}, ""},
		{[]string{"--package=cowsay", "cowsay"}, []check.Spec{npmSpec("cowsay", "")}, ""},
		// bunx fetches these under another package's name.
		{[]string{"tsc", "--noEmit"}, []check.Spec{npmSpec("typescript", "")}, "tsc"},
		{[]string{"claude@2.0.0"}, []check.Spec{npmSpec("@anthropic-ai/claude-code", "2.0.0")}, ""},
		// --package with no binary runs nothing.
		{[]string{"-p", "cowsay"}, nil, ""},
		{nil, nil, ""},
	}
	for _, tc := range tests {
		got := bunxRun(tc.args)
		if !reflect.DeepEqual(got.Specs, tc.wantSpecs) || got.LocalCommand != tc.wantLocal {
			t.Errorf("bunxRun(%q) = specs %+v local %q; want %+v local %q",
				tc.args, got.Specs, got.LocalCommand, tc.wantSpecs, tc.wantLocal)
		}
	}
}

func TestBunInstallDetection(t *testing.T) {
	bun, _ := Lookup("bun")
	for _, tc := range []struct {
		args      []string
		wantStart int
		wantOK    bool
	}{
		{[]string{"add", "react"}, 1, true},
		{[]string{"a", "react"}, 1, true},
		{[]string{"install"}, 1, true},
		{[]string{"i", "react"}, 1, true},
		{[]string{"ci"}, 1, true},
		{[]string{"update", "react"}, 1, true},
		{[]string{"up"}, 1, true},
		{[]string{"--silent", "install"}, 2, true},
		{[]string{"run", "dev"}, 0, false},
		{[]string{"x", "cowsay"}, 0, false}, // fetch-and-execute: toolRunAt
		{[]string{"index.ts"}, 0, false},
		// bun does not read option values when finding its command.
		{[]string{"--cwd", "web", "add", "react"}, 0, false},
	} {
		start, ok := bun.installAt(tc.args)
		if start != tc.wantStart || ok != tc.wantOK {
			t.Errorf("bun installAt(%q) = %d, %v; want %d, %v", tc.args, start, ok, tc.wantStart, tc.wantOK)
		}
	}
}

func TestBunAddValueFlags(t *testing.T) {
	bun, _ := Lookup("bun")
	got := ParseSpecs(bun, []string{"--registry", "https://r.example", "-d", "--cwd", "web", "react@18.2.0", "-E", "zod"})
	want := []check.Spec{npmSpec("react", "18.2.0"), npmSpec("zod", "")}
	if !reflect.DeepEqual(got.Specs, want) {
		t.Errorf("specs = %+v, want %+v", got.Specs, want)
	}
}

// swapLocalBin fixes whether the command is a project-local binary.
func swapLocalBin(t *testing.T, local bool) {
	t.Helper()
	old := localBinFn
	localBinFn = func(string) bool { return local }
	t.Cleanup(func() { localBinFn = old })
}

func TestRun_NpmSideToolRun_ChecksOnlyTheTool(t *testing.T) {
	swapLocalBin(t, false)
	for _, tc := range []struct {
		bin  string
		args []string
	}{
		{"npx", []string{"cowsay", "moo"}},
		{"npm", []string{"exec", "cowsay", "moo"}},
		{"npm", []string{"x", "--", "cowsay", "moo"}},
		{"bunx", []string{"cowsay", "moo"}},
		{"bun", []string{"x", "cowsay", "moo"}},
	} {
		t.Run(tc.bin+" "+strings.Join(tc.args, " "), func(t *testing.T) {
			ex := &stubExec{}
			var gotSpecs []check.Spec
			swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
				gotSpecs = o.Specs
				return ossbom.New(ossbom.Environment{}), nil
			})
			pin := func(context.Context, string, string) (string, error) { return "1.0.0", nil }
			if err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args, ResolveLatest: pin}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if want := []check.Spec{npmSpec("cowsay", "1.0.0")}; !reflect.DeepEqual(gotSpecs, want) {
				t.Errorf("checked specs = %+v, want %+v", gotSpecs, want)
			}
			if !ex.called || ex.bin != tc.bin || !reflect.DeepEqual(ex.args, tc.args) {
				t.Errorf("exec = %s %v (called=%v), want %s %v", ex.bin, ex.args, ex.called, tc.bin, tc.args)
			}
		})
	}
}

func TestRun_NpmSideToolRun_MalwareBlocks(t *testing.T) {
	swapLocalBin(t, false)
	for _, bin := range []string{"npx", "bunx"} {
		ex := &stubExec{}
		swap(t, ex.fn, malwareSBOM)
		err := Run(context.Background(), Options{Bin: bin, Args: []string{"evil@1.0.0"}})
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("%s: Run = %v, want ErrBlocked", bin, err)
		}
		if ex.called {
			t.Errorf("a blocked %s run must not exec", bin)
		}
	}
}

// A project's own binary is run, not fetched: checking the registry package of
// the same name would check something else.
func TestRun_ProjectBinaryForwardsUnchecked(t *testing.T) {
	swapLocalBin(t, true)
	for _, bin := range []string{"npx", "bunx"} {
		ex := &stubExec{}
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			t.Errorf("%s eslint: a project binary was checked", bin)
			return ossbom.New(ossbom.Environment{}), nil
		})
		if err := Run(context.Background(), Options{Bin: bin, Args: []string{"eslint", "."}}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !ex.called {
			t.Errorf("%s eslint must forward", bin)
		}
	}
}

// --package and a pinned version are always fetched, local binary or not.
func TestRun_FetchedPackageIsCheckedDespiteProjectBinary(t *testing.T) {
	swapLocalBin(t, true)
	for _, args := range [][]string{{"-p", "eslint@9.0.0", "eslint"}, {"eslint@9.0.0"}} {
		ex := &stubExec{}
		checked := false
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			checked = true
			return ossbom.New(ossbom.Environment{}), nil
		})
		if err := Run(context.Background(), Options{Bin: "npx", Args: args}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if !checked {
			t.Errorf("npx %v: fetched package not checked", args)
		}
	}
}

func TestRun_NpmRunIsNotAToolRun(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
		t.Error("npm run was checked")
		return ossbom.New(ossbom.Environment{}), nil
	})
	if err := Run(context.Background(), Options{Bin: "npm", Args: []string{"run", "build"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// npm can write a lockfile, but `npm exec` installs into npm's cache: a passive
// run submits the package it names, never a scan of the project.
func TestRun_PassiveNpmExec_SubmitsTheTool(t *testing.T) {
	swapLocalBin(t, false)
	ex := &stubExec{}
	var got check.Options
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o
		return ossbom.New(ossbom.Environment{}), nil
	})
	err := Run(context.Background(), Options{Bin: "npm", Args: []string{"exec", "cowsay@1.5.0"}, Passive: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := []check.Spec{npmSpec("cowsay", "1.5.0")}; !got.SubmitOnly || !reflect.DeepEqual(got.Specs, want) {
		t.Errorf("submitted %+v (SubmitOnly=%v), want %+v", got.Specs, got.SubmitOnly, want)
	}
}

func TestRun_BunInstall_ScansTheProject(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	scanned := false
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
		scanned = true
		return ossbom.New(ossbom.Environment{}), nil
	})
	if err := Run(context.Background(), Options{Bin: "bun", Args: []string{"install", "--frozen-lockfile"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !scanned || !ex.called {
		t.Errorf("bun install: scanned=%v forwarded=%v, want both", scanned, ex.called)
	}
}

func TestProjectHasBin(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("app/package.json")
	write("app/node_modules/.bin/eslint")
	write("app/src/deep/.keep")
	write("app/pkgs/inner/package.json")

	for _, tc := range []struct {
		dir, name string
		want      bool
	}{
		{"app", "eslint", true},
		{"app/src/deep", "eslint", true}, // npm walks up to the project
		{"app", "prettier", false},
		// The nearest package.json is the project; npm does not look past it.
		{"app/pkgs/inner", "eslint", false},
		{"app", "../app/node_modules/.bin/eslint", false},
		{"app", ".bin", false},
	} {
		t.Chdir(filepath.Join(root, tc.dir))
		if got := projectHasBin(tc.name); got != tc.want {
			t.Errorf("projectHasBin(%q) in %s = %v, want %v", tc.name, tc.dir, got, tc.want)
		}
	}
}

// installedNpm finds the real npm's package root and node, or skips. The
// shim-skipping lookup matters: on a machine with ossprey shims, PATH npm is a
// script with no package beside it.
func installedNpm(t *testing.T) (node, root string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	npm, err := shim.LookPathReal("npm")
	if err != nil {
		t.Skip("npm not installed")
	}
	cli, err := filepath.EvalSymlinks(npm)
	if err != nil {
		t.Skipf("resolve npm: %v", err)
	}
	root = filepath.Dir(filepath.Dir(cli))
	if _, err := os.Stat(filepath.Join(root, "bin", "npx-cli.js")); err != nil {
		t.Skipf("no npm package found beside %s", cli)
	}
	return node, root
}

// npm's option table is generated; this diffs it against the installed npm. An
// option missing here is one whose value could be read as the command.
func TestNpmConfigTableMatchesNpm(t *testing.T) {
	node, root := installedNpm(t)
	const script = `
const { definitions, shorthands } = require(process.argv[1] + '/node_modules/@npmcli/config/lib/definitions')
const kinds = {}
for (const [k, d] of Object.entries(definitions)) {
  let t = d.type
  if (Array.isArray(t) && t.length === 1) t = t[0]
  if (t === Boolean) kinds[k] = 'bool'
  else if (Array.isArray(t) && t.includes(Boolean)) kinds[k] = t.includes(String) ? 'bool-or-string'
    : t.includes('always') ? 'bool-or-always' : t.every((x) => x === null || x === Boolean) ? 'bool' : 'unknown'
  else kinds[k] = t === String ? 'string' : 'value'
}
const sh = {}
for (const [k, v] of Object.entries(shorthands)) sh[k] = Array.isArray(v) ? v : String(v).split(/\s+/)
console.log(JSON.stringify({ kinds, shorthands: sh }))
`
	out, err := exec.Command(node, "-e", script, root).Output()
	if err != nil {
		t.Fatalf("read npm definitions: %v", err)
	}
	var npm struct {
		Kinds      map[string]string
		Shorthands map[string][]string
	}
	if err := json.Unmarshal(out, &npm); err != nil {
		t.Fatal(err)
	}
	names := map[npmFlagKind]string{npmValue: "value", npmString: "string", npmBool: "bool",
		npmBoolOrString: "bool-or-string", npmBoolOrAlways: "bool-or-always"}
	for key, want := range npm.Kinds {
		got, ok := npmConfig[key]
		if !ok || names[got] != want {
			t.Errorf("npm option --%s is %s, npmConfig has %q (regenerate npm_config.go)", key, want, names[got])
		}
	}
	for key, want := range npm.Shorthands {
		if got := npmShorthands[key]; !reflect.DeepEqual(got, want) {
			t.Errorf("npm shorthand %s = %q, npmShorthands has %q", key, want, got)
		}
	}
}

// oraclePreload stands in for npm's lib/cli.js: it parses the argv it is handed
// with npm's own nopt and option definitions and prints the result. Run in
// front of bin/npx-cli.js, that is npx's rewrite and npm's parse, unported.
const oraclePreload = `
const Module = require('module')
const load = Module._load
Module._load = function (request, parent, isMain) {
  if (request !== '../lib/cli.js') return load.apply(this, arguments)
  return (proc) => {
    const req = Module.createRequire(parent.filename)
    const nopt = req('nopt')
    const { definitions, shorthands } = req('@npmcli/config/lib/definitions')
    const types = {}
    for (const [k, d] of Object.entries(definitions)) types[k] = d.type
    const conf = nopt(types, shorthands, proc.argv, 2)
    const pkg = conf.package === undefined ? [] : [].concat(conf.package)
    process.stdout.write(JSON.stringify({
      positionals: conf.argv.remain.slice(1),
      packages: pkg.map(String),
      call: conf.call !== undefined,
      registry: conf.registry === undefined ? '' : String(conf.registry),
      // nopt's path type resolves against the cwd; relative to it again so
      // the port, which keeps the path as given, compares equal.
      userconfig: conf.userconfig === undefined ? '' : require('path').relative(process.cwd(), String(conf.userconfig)),
      // The options a tool run's dry run is given, as npm attributed them:
      // a Date (before) as the word, a path (prefix) relative to the cwd,
      // everything else as its string.
      config: Object.fromEntries(['legacy-peer-deps', 'strict-peer-deps', 'optional', 'omit', 'include',
        'before', 'tag', 'globalconfig', 'global', 'prefix', 'location', 'cache', 'offline', 'prefer-offline', 'prefer-online', 'workspaces', 'min-release-age', 'min-release-age-exclude', 'production', 'only', 'dev', 'also'].filter(k => conf[k] !== undefined).map(k =>
          [k, [].concat(conf[k]).map(v => v instanceof Date ? 'date'
            : k === 'prefix' || k === 'globalconfig' || k === 'cache' ? require('path').relative(process.cwd(), String(v)) : String(v))])),
    }))
  }
}
`

// Whatever npm decides is the command, the forwarder must decide too: the
// token checked has to be the token run. Each case runs the real npx-cli.js /
// npm-cli.js with only the final dispatch replaced.
func TestNpmParsersMatchNpm(t *testing.T) {
	node, root := installedNpm(t)
	preload := filepath.Join(t.TempDir(), "oracle.js")
	if err := os.WriteFile(preload, []byte(oraclePreload), 0o644); err != nil {
		t.Fatal(err)
	}
	oracleDir := t.TempDir()
	oracle := func(cli string, args []string) npmArgv {
		t.Helper()
		cmd := exec.Command(node, append([]string{"-r", preload, filepath.Join(root, "bin", cli)}, args...)...)
		cmd.Dir = oracleDir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s %q: %v", cli, args, err)
		}
		var got struct {
			Positionals []string
			Packages    []string
			Call        bool
			Registry    string
			Userconfig  string
			Config      map[string][]string
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("%s %q: %v (%s)", cli, args, err, out)
		}
		return npmArgv{Packages: got.Packages, Call: got.Call, Positionals: got.Positionals,
			Registry: got.Registry, Userconfig: filepath.ToSlash(got.Userconfig), Config: got.Config}
	}
	norm := func(a npmArgv) npmArgv {
		if len(a.Packages) == 0 {
			a.Packages = nil
		}
		if len(a.Positionals) == 0 {
			a.Positionals = nil
		}
		// A home path is absolute on both sides after nopt's expansion; the
		// oracle reports it relative to its cwd, so the port's is too.
		rel := func(v string) string {
			if filepath.IsAbs(v) {
				if r, err := filepath.Rel(oracleDir, v); err == nil {
					v = r
				}
			}
			return filepath.ToSlash(v)
		}
		a.Userconfig = rel(a.Userconfig)
		if len(a.Config) == 0 {
			a.Config = nil
		}
		// The port keeps a date as typed and a prefix as given; the oracle
		// reports the word and the cwd-relative path. nopt keeps one value
		// for a scalar, every value for an array (omit, include).
		cfg := map[string][]string{}
		for k, vs := range a.Config {
			out := []string{}
			for _, v := range vs {
				switch k {
				case "before":
					v = "date"
				case "prefix", "globalconfig", "cache":
					v = rel(filepath.Clean(v))
				}
				out = append(out, v)
			}
			if k != "omit" && k != "include" {
				out = out[len(out)-1:]
			}
			cfg[k] = out
		}
		if len(cfg) > 0 {
			a.Config = cfg
		}
		return a
	}

	npx := [][]string{
		{"cowsay", "moo"}, {"-y", "cowsay", "moo"}, {"--yes", "cowsay"}, {"--package=cowsay", "cowsay"},
		{"-p", "cowsay", "-p", "left-pad", "cowsay", "hello"}, {"-p=cowsay", "cowsay"},
		{"-c", "echo hi"}, {"-p", "cowsay", "-c", "cowsay hi"}, {"--call=echo", "x"},
		{"--registry", "https://registry.npmjs.org", "cowsay", "moo"}, {"--registry=https://r.example", "cowsay"},
		{"--no-install", "cowsay"}, {"--no", "cowsay", "moo"}, {"-n", "cowsay", "moo"},
		{"--no-update-notifier", "cowsay", "moo"}, {"--no-audit", "--no-fund", "cowsay"},
		{"--ignore-existing", "cowsay"}, {"-q", "cowsay"}, {"--quiet", "cowsay", "moo"},
		{"--loglevel", "silent", "cowsay", "moo"}, {"--", "cowsay", "--yes"}, {"cowsay@1.5.0", "--help"},
		{"@scope/pkg@1.0.0", "arg"}, {"-gy", "cowsay"}, {"--prefer-offline", "cowsay"}, {"--offline", "--cache", "c", "cowsay"}, {"--no-offline", "cowsay"},
		// nopt toggles the negation per prefix.
		{"--no-no-optional", "cowsay"}, {"--no-no-no-optional", "cowsay"}, {"--no-no-optional=false", "cowsay"},
		{"--workspaces=false", "cowsay"}, {"--no-workspaces", "cowsay"},
		{"--prefer-online", "cowsay"}, {"--no-prefer-online", "cowsay"},
		{"--min-release-age=7", "cowsay"}, {"--min-release-age", "3", "--min-release-age-exclude", "cowsay", "--min-release-age-exclude=left-pad", "cowsay"},
		// npm's older spellings of the omit policy.
		{"--production", "cowsay"}, {"--production=false", "cowsay"}, {"--no-production", "cowsay"}, {"--only=prod", "cowsay"}, {"--also=dev", "cowsay"}, {"--dev", "cowsay"},
		{"--cache", "/tmp/c", "cowsay"}, {"--userconfig", "./x.npmrc", "cowsay", "moo"},
		{"--shell", "bash", "cowsay"}, {"--color", "always", "cowsay"}, {"--browser", "firefox", "cowsay"},
		{"--workspace", "a", "cowsay"}, {"-w", "a", "cowsay"}, {"--package", "cowsay", "--", "cowsay", "moo"},
		{"--pack=cowsay", "cowsay"}, {"--reg", "https://r.example", "cowsay"}, {"--unknown-thing", "cowsay", "moo"},
		// nopt types registry as a url: an invalid value drops the option, and
		// the last value is the one validated.
		{"--registry", "nope", "cowsay"}, {"--registry", "https://a.example", "--registry", "nope", "cowsay"},
		{"--registry", "https://a.example", "--registry", "https://b.example/", "cowsay"},
		{"cowsay", "--registry", "https://after.example"},
		{"--userconfig=./y.npmrc", "cowsay"}, {"--userconfig", "sub/../z.npmrc", "cowsay", "moo"},
		{"--unknown=1", "cowsay"}, {"-d", "cowsay"}, {"--yes=true", "cowsay"}, {"--version"}, {},
		// The resolution options and the .npmrc selectors npm reads for the
		// run, with the program's own `--before` left to the program.
		{"--before=2024-01-01", "cowsay", "--before=2020-01-01"}, {"-g", "cowsay"}, {"--global", "cowsay", "moo"},
		{"--prefix", "../other", "cowsay"}, {"--prefix=sub/../o", "cowsay"}, {"--location=global", "cowsay"},
		{"--location", "project", "cowsay"}, {"--omit", "dev", "--omit=optional", "--tag", "beta", "--legacy-peer-deps", "cowsay", "--tag", "x"},
		{"--no-optional", "cowsay"}, {"--legacy-peer-deps=false", "cowsay"}, {"--strict-peer-deps", "--include=dev", "cowsay"},
		{"--no-optional", "--optional", "cowsay"}, {"--optional", "--no-optional", "cowsay", "moo"},
		{"--optional=false", "cowsay"}, {"--no-optional=false", "cowsay"}, {"--no-global=false", "cowsay"},
		{"--tag", "next", "--tag=latest", "cowsay"},
		{"--globalconfig", "./corp.npmrc", "cowsay"}, {"--globalconfig=sub/../g.npmrc", "cowsay", "moo"},
		// nopt expands a leading ~/ in a path-typed option.
		{"--userconfig", "~/u.npmrc", "cowsay"}, {"--globalconfig=~/g.npmrc", "cowsay"}, {"--prefix", "~/p", "cowsay"},
		{"--cache", "~/c", "cowsay"}, {"--cache=./c", "cowsay", "moo"},
		// A negated path option is invalid to npm, which keeps its default.
		{"--no-cache", "cowsay"}, {"--no-prefix", "cowsay"}, {"--no-globalconfig", "cowsay", "moo"}, {"--cache=false", "cowsay"},
		// A later negation drops an earlier value with it, as nopt's last
		// value wins and the invalid boolean is then dropped.
		{"--cache", "custom", "--no-cache", "cowsay"}, {"--no-cache", "--cache", "custom", "cowsay"},
		{"--prefix", "p", "--no-prefix", "cowsay"}, {"--globalconfig", "g.npmrc", "--no-globalconfig", "cowsay"},
		{"--userconfig", "./x.npmrc", "--no-userconfig", "cowsay"}, {"--registry", "https://a.example", "--no-registry", "cowsay"},
		{"--tag", "beta", "--no-tag", "cowsay"}, {"--omit", "dev", "--no-omit", "cowsay"},
	}
	for _, args := range npx {
		want, got := norm(oracle("npx-cli.js", args)), norm(parseNpmArgv(npxArgv(args)))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("npx %q: ported %+v, npm %+v", args, got, want)
		}
	}

	npmExec := [][]string{
		{"exec", "cowsay", "moo"}, {"exec", "--", "cowsay", "--yes"}, {"x", "cowsay"},
		{"exec", "--package=cowsay", "--", "cowsay"}, {"exec", "-p", "cowsay", "moo"},
		{"exec", "cowsay", "--package", "left-pad"}, {"--yes", "exec", "cowsay"},
		{"exec", "--pack=cowsay", "--", "cowsay"}, {"exec", "-c", "echo hi"},
		{"exec", "--workspace", "web", "cowsay"}, {"exec", "-gy", "cowsay"}, {"exec", "--no-yes", "cowsay"},
		{"exec", "--prefix", "../o", "cowsay"}, {"exec", "cowsay", "--before=2024-01-01"}, {"--omit=dev", "exec", "cowsay"},
	}
	for _, args := range npmExec {
		want := norm(oracle("npm-cli.js", args))
		got := parseNpmArgv(args)
		got.Positionals = got.Positionals[1:] // the verb, as the oracle drops it
		if got = norm(got); !reflect.DeepEqual(got, want) {
			t.Errorf("npm %q: ported %+v, npm %+v", args, got, want)
		}
	}
}
