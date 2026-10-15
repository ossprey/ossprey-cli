package forward

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// specNames runs the forwarder's own install detection and parse, returning
// the names it would check, or ok=false when the command is not an install.
func specNames(t *testing.T, bin string, args []string) (names []string, ok bool) {
	t.Helper()
	m, found := Lookup(bin)
	if !found {
		t.Fatalf("unknown manager %q", bin)
	}
	start, isInstall := m.installAt(args)
	if !isInstall {
		return nil, false
	}
	p := parseInstallArgs(m, args[start:], m.reqFileArgs != nil && m.reqFileArgs(args))
	for _, s := range p.Specs {
		names = append(names, s.Name)
	}
	return names, true
}

// Global options before the verb, per manager. A boolean must not swallow the
// verb; a value flag must not leave its value standing in for it.
func TestGlobalFlagsBeforeVerbPerManager(t *testing.T) {
	cases := []struct {
		bin  string
		args []string
		want []string
	}{
		{"npm", []string{"-g", "install", "lodash"}, []string{"lodash"}},
		{"npm", []string{"--global", "i", "lodash"}, []string{"lodash"}},
		{"npm", []string{"--registry", "https://r.example", "install", "lodash"}, []string{"lodash"}},
		{"npm", []string{"--userconfig", "/tmp/npmrc", "add", "lodash"}, []string{"lodash"}},
		{"npm", []string{"--prefix=/tmp/app", "install", "lodash"}, []string{"lodash"}},
		{"npm", []string{"--workspace", "web", "install", "lodash"}, []string{"lodash"}},
		{"pnpm", []string{"--recursive", "add", "lodash"}, []string{"lodash"}},
		{"pnpm", []string{"--reporter", "silent", "add", "lodash"}, []string{"lodash"}},
		{"pnpm", []string{"--store-dir", "/tmp/s", "add", "lodash"}, []string{"lodash"}},
		{"yarn", []string{"--cwd", "web", "add", "lodash"}, []string{"lodash"}},
		{"yarn", []string{"--registry", "https://r.example", "add", "lodash"}, []string{"lodash"}},
		{"yarn", []string{"--silent", "add", "lodash"}, []string{"lodash"}},
		{"pip", []string{"--isolated", "install", "flask"}, []string{"flask"}},
		{"pip", []string{"-v", "install", "flask"}, []string{"flask"}},
		{"pip", []string{"--log", "/tmp/pip.log", "install", "flask"}, []string{"flask"}},
		{"pip", []string{"--proxy", "http://p:3128", "install", "flask"}, []string{"flask"}},
		{"pip3", []string{"--python", "/usr/bin/python3", "install", "flask"}, []string{"flask"}},
		{"poetry", []string{"--project", "svc", "add", "flask"}, []string{"flask"}},
		{"poetry", []string{"-P", "svc", "add", "flask"}, []string{"flask"}},
		{"poetry", []string{"--directory=svc", "add", "flask"}, []string{"flask"}},
		{"poetry", []string{"-n", "add", "flask"}, []string{"flask"}},
		{"uv", []string{"--offline", "add", "flask"}, []string{"flask"}},
		{"uv", []string{"-p", "3.12", "add", "flask"}, []string{"flask"}},
		{"uv", []string{"--cache-dir", "/tmp/c", "pip", "install", "flask"}, []string{"flask"}},
		{"uv", []string{"--color", "never", "add", "flask"}, []string{"flask"}},
		{"uv", []string{"--project", "svc", "tool", "install", "ruff"}, []string{"ruff"}},
	}
	for _, tc := range cases {
		got, ok := specNames(t, tc.bin, tc.args)
		if !ok {
			t.Errorf("%s %v: not detected as an install", tc.bin, tc.args)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %v: checked %v, want %v", tc.bin, tc.args, got, tc.want)
		}
	}
}

// The OSS-1577 class per manager: boolean flags commonly written between the
// verb and the package must not be in either value table, or they swallow the
// package (or verb) and the install goes through unchecked.
func TestBooleanFlagsAreNotValueFlagsPerManager(t *testing.T) {
	booleans := map[string][]string{
		"npm": {"-D", "--save-dev", "-E", "--save-exact", "-O", "--save-optional",
			"-P", "--save-prod", "-B", "--save-bundle", "-g", "--global", "--no-save",
			"--ignore-scripts", "--legacy-peer-deps", "--force", "-f", "--dry-run",
			"--foreground-scripts", "--prefer-offline", "--offline", "--no-audit",
			"--no-fund", "-y", "--yes", "--package-lock-only", "--install-links",
			"--strict-peer-deps", "-s", "--silent", "-q", "-ws", "--workspaces"},
		"yarn": {"-D", "--dev", "-P", "--peer", "-O", "--optional", "-E", "--exact",
			"-T", "--tilde", "-W", "--ignore-workspace-root-check", "--frozen-lockfile",
			"--pure-lockfile", "--ignore-scripts", "--offline", "--prefer-offline",
			"--production", "--silent", "--flat", "--force", "--no-lockfile",
			"--immutable", "--interactive", "-i", "--cached"},
		"bun": {"-d", "--dev", "-D", "-E", "--exact", "-g", "--global", "-p",
			"--production", "-y", "--yarn", "-f", "--force", "--optional", "--peer",
			"--trust", "--dry-run", "--no-save", "--save", "--frozen-lockfile",
			"--silent", "--verbose", "--no-cache", "--ignore-scripts", "-a", "--analyze",
			"--only-missing", "--lockfile-only", "--save-text-lockfile", "--no-verify",
			"--offline", "--prefer-offline",
			// Optional-value: the next token may be the package.
			"-c", "--config", "--catalog"},
		"pip": {"-U", "--upgrade", "--user", "--pre", "--no-deps", "--force-reinstall",
			"-I", "--ignore-installed", "--no-cache-dir", "--no-build-isolation",
			"--require-hashes", "--dry-run", "--break-system-packages", "-q", "--quiet",
			"-v", "--verbose", "--isolated", "--no-index", "--prefer-binary",
			"--compile", "--no-compile", "--no-input", "--disable-pip-version-check"},
		"poetry": {"-D", "--dev", "-e", "--editable", "--allow-prereleases",
			"--dry-run", "--lock", "--no-root", "--sync", "--all-extras", "--all-groups",
			"-n", "--no-interaction", "-q", "--quiet", "-v", "--verbose", "--compile",
			"--only-root", "--no-directory", "--no-cache", "--regenerate"},
		// -e/--editable are absent on purpose: a value in `uv pip install`, a
		// boolean in `uv add` / `uv tool install`.
		"uv": {"--dev", "--raw", "--frozen", "--locked", "--no-sync", "--active",
			"--workspace", "--no-workspace", "-U", "--upgrade", "--system", "--user",
			"--break-system-packages", "--no-deps", "--dry-run", "--exact", "--strict",
			"--force", "--offline", "-q", "--quiet", "-v", "--verbose", "-n", "--no-cache",
			"--lfs", "--all-extras", "--all-groups", "--no-dev", "--only-dev",
			"--inexact", "--check", "--reinstall", "--refresh", "--no-build",
			"--no-binary", "--no-sources", "--compile-bytecode", "--no-config"},
	}
	booleans["pip3"] = booleans["pip"]
	for bin, flags := range booleans {
		for _, f := range flags {
			if valueFlags[bin][f] {
				t.Errorf("valueFlags[%s] lists boolean %q; it would swallow the package name", bin, f)
			}
			if globalValueFlags[bin][f] {
				t.Errorf("globalValueFlags[%s] lists boolean %q; it would swallow the verb", bin, f)
			}
		}
	}
}

// npm's own option table types every flag, so the npm value tables can be
// checked against it without an npm on the machine.
func TestNpmValueFlagsAreValueTypedInNpmConfig(t *testing.T) {
	kindOf := func(flag string) (npmFlagKind, bool) {
		name := strings.TrimLeft(flag, "-")
		if strings.HasPrefix(flag, "--") {
			k, ok := npmConfig[name]
			return k, ok
		}
		exp, ok := npmShorthands[name]
		if !ok || len(exp) != 1 {
			return 0, false
		}
		k, ok := npmConfig[strings.TrimLeft(exp[0], "-")]
		return k, ok
	}
	for table, flags := range map[string]map[string]bool{
		"valueFlags":       valueFlags["npm"],
		"globalValueFlags": globalValueFlags["npm"],
	} {
		for f := range flags {
			k, ok := kindOf(f)
			if !ok {
				t.Errorf("%s[npm] lists %q, which npm does not define", table, f)
				continue
			}
			if k.isBool() {
				t.Errorf("%s[npm] lists %q, which npm parses as a boolean", table, f)
			}
		}
	}
}

// helpOptions reads an installed tool's --help and splits its options into
// value-taking and boolean. Skips the test when the tool is missing.
func helpOptions(t *testing.T, cmd ...string) (values, booleans map[string]bool) {
	t.Helper()
	path, err := exec.LookPath(cmd[0])
	if err != nil {
		t.Skipf("%s not installed", cmd[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, append(cmd[1:], "--help")...).Output()
	if err != nil {
		t.Skipf("%v --help: %v", cmd, err)
	}
	values, booleans = map[string]bool{}, map[string]bool{}
	re := regexp.MustCompile(`(?m)^\s{1,8}(?:(-[A-Za-z])(?:\|v+)?,\s*)?(--[A-Za-z][A-Za-z0-9-]*)(=\S*|\s<[^>]*>|\.\.\.)?`)
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		isValue := strings.HasPrefix(m[3], "=") || strings.HasPrefix(m[3], " <")
		for _, f := range m[1:3] {
			if f == "" {
				continue
			}
			if isValue {
				values[f] = true
			} else {
				booleans[f] = true
			}
		}
	}
	return values, booleans
}

// The same invariant, diffed against the installed managers' own help. A flag
// that is a value in one install subcommand and a boolean in another is
// ambiguous and left out.
func TestValueFlagTablesListNoBooleanOfTheInstalledManager(t *testing.T) {
	for bin, cmds := range map[string][][]string{
		"uv": {{"uv"}, {"uv", "add"}, {"uv", "sync"}, {"uv", "lock"},
			{"uv", "pip", "install"}, {"uv", "pip", "sync"}, {"uv", "tool", "install"}},
		"pip":    {{"pip"}, {"pip", "install"}},
		"poetry": {{"poetry", "add"}, {"poetry", "install"}, {"poetry", "sync"}, {"poetry", "update"}, {"poetry", "lock"}},
		"bun":    {{"bun", "add"}, {"bun", "install"}, {"bun", "update"}},
	} {
		t.Run(bin, func(t *testing.T) {
			values, booleans := map[string]bool{}, map[string]bool{}
			for _, c := range cmds {
				v, b := helpOptions(t, c...)
				for f := range v {
					values[f] = true
				}
				for f := range b {
					booleans[f] = true
				}
			}
			if len(booleans) == 0 {
				t.Skipf("%s --help listed no options", bin)
			}
			for f := range booleans {
				if values[f] {
					continue
				}
				if valueFlags[bin][f] {
					t.Errorf("valueFlags[%s] lists %q, a boolean in %s; it swallows the package", bin, f, bin)
				}
				if globalValueFlags[bin][f] {
					t.Errorf("globalValueFlags[%s] lists %q, a boolean in %s; it swallows the verb", bin, f, bin)
				}
			}
		})
	}
}

// poetry add's group/extra selectors take a value; the package after them is
// the one installed.
func TestPoetryAddGroupsCheckThePackage(t *testing.T) {
	for _, args := range [][]string{
		{"add", "--group", "dev", "pytest"},
		{"add", "--group=dev", "pytest"},
		{"add", "-G", "dev", "pytest"},
		{"add", "--dev", "pytest"},
		{"add", "-D", "pytest"},
		{"add", "-E", "socks", "pytest"},
		{"add", "--extras", "socks", "pytest"},
		{"add", "--source", "internal", "pytest"},
		{"add", "--python", "3.12", "pytest"},
		{"add", "--allow-prereleases", "pytest"},
		{"add", "--lock", "pytest"},
		{"add", "-e", "pytest"},
		{"add", "--", "pytest"},
	} {
		got, ok := specNames(t, "poetry", args)
		if !ok || !reflect.DeepEqual(got, []string{"pytest"}) {
			t.Errorf("poetry %v: checked %v (install=%v), want [pytest]", args, got, ok)
		}
	}
}

// uv add / uv pip install name their packages beside flags of both dialects.
func TestUVAddAndPipInstallCheckThePackage(t *testing.T) {
	for _, args := range [][]string{
		{"add", "--dev", "httpx"},
		{"add", "--group", "lint", "httpx"},
		{"add", "--optional", "web", "httpx"},
		{"add", "--extra", "http2", "httpx"},
		{"add", "--package", "api", "httpx"},
		{"add", "-m", "sys_platform == 'linux'", "httpx"},
		{"add", "--frozen", "httpx"},
		{"add", "--raw", "httpx"},
		{"add", "--tag", "v1", "httpx"},
		{"pip", "install", "--system", "httpx"},
		{"pip", "install", "-U", "httpx"},
		{"pip", "install", "-e", "./local", "httpx"},
		{"pip", "install", "-c", "constraints.txt", "httpx"},
		{"pip", "install", "--python", "3.12", "httpx"},
		{"pip", "install", "--prefix", "/opt/x", "httpx"},
	} {
		got, ok := specNames(t, "uv", args)
		if !ok || !reflect.DeepEqual(got, []string{"httpx"}) {
			t.Errorf("uv %v: checked %v (install=%v), want [httpx]", args, got, ok)
		}
	}
}

// yarn: classic and berry share add/install; `up` is berry, `upgrade` classic.
func TestYarnVerbsAndFlags(t *testing.T) {
	for _, args := range [][]string{
		{"add", "-D", "react"},
		{"add", "--dev", "react"},
		{"add", "-W", "react"},
		{"add", "-E", "react"},
		{"add", "--exact", "react"},
		{"add", "-P", "react"},
		{"add", "--cwd", "web", "react"},
		{"upgrade", "react"},
		{"up", "react"},
	} {
		got, ok := specNames(t, "yarn", args)
		if !ok || !reflect.DeepEqual(got, []string{"react"}) {
			t.Errorf("yarn %v: checked %v (install=%v), want [react]", args, got, ok)
		}
	}
	for _, args := range [][]string{{"install"}, {"install", "--frozen-lockfile"}, {"install", "--immutable"}} {
		got, ok := specNames(t, "yarn", args)
		if !ok || got != nil {
			t.Errorf("yarn %v: want a manifest install, got specs %v (install=%v)", args, got, ok)
		}
	}
}

// `--` ends options; whatever follows is still a package to check.
func TestDoubleDashAfterVerbStillChecksPackages(t *testing.T) {
	for _, tc := range []struct {
		bin  string
		args []string
		want []string
	}{
		{"npm", []string{"install", "--", "lodash"}, []string{"lodash"}},
		{"pip", []string{"install", "--", "flask"}, []string{"flask"}},
		{"poetry", []string{"add", "--", "flask"}, []string{"flask"}},
		{"uv", []string{"add", "--", "flask"}, []string{"flask"}},
	} {
		got, ok := specNames(t, tc.bin, tc.args)
		if !ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %v: checked %v (install=%v), want %v", tc.bin, tc.args, got, ok, tc.want)
		}
	}
}

// Spec shapes users type: version specifiers, scoped names, and every target
// that is not a registry package.
func TestParseSpecsSpecShapes(t *testing.T) {
	npm, _ := Lookup("npm")
	pip, _ := Lookup("pip")
	for _, tc := range []struct {
		m       *Manager
		token   string
		want    *check.Spec // nil: not a registry package
		comment string
	}{
		{npm, "@scope/pkg@1.2.3", &check.Spec{Ecosystem: "npm", Name: "@scope/pkg", Version: "1.2.3"}, "scoped, pinned"},
		{npm, "@scope/pkg", &check.Spec{Ecosystem: "npm", Name: "@scope/pkg"}, "scoped, unpinned"},
		{pip, "flask>=2.0", &check.Spec{Ecosystem: "pypi", Name: "flask"}, "range resolves latest"},
		{pip, "flask~=2.0", &check.Spec{Ecosystem: "pypi", Name: "flask"}, "compatible release"},
		{pip, "flask!=2.0", &check.Spec{Ecosystem: "pypi", Name: "flask"}, "exclusion"},
		{pip, "flask<3", &check.Spec{Ecosystem: "pypi", Name: "flask"}, "upper bound"},
		{pip, "flask==3.0.0", &check.Spec{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"}, "pinned"},
		{npm, "git+ssh://git@github.com/x/y.git", nil, "vcs"},
		{npm, "git://github.com/x/y.git", nil, "git protocol"},
		{npm, "https://example.com/x-1.0.0.tgz", nil, "tarball url"},
		{npm, "file:../lib", nil, "file:"},
		{npm, "../lib", nil, "relative path"},
		{npm, "~/lib", nil, "home path"},
		{npm, "/abs/lib", nil, "absolute path"},
		{npm, `..\lib`, nil, "windows relative path"},
		{npm, "pkg-1.0.0.tgz", nil, "local tarball"},
		{pip, "pkg-1.0-py3-none-any.whl", nil, "wheel"},
		{pip, "pkg-1.0.tar.gz", nil, "sdist"},
		{pip, "pkg-1.0.zip", nil, "zip"},
		{pip, "pkg@git+https://github.com/x/y", nil, "PEP 508 direct reference"},
		{pip, ".", nil, "the project itself"},
	} {
		got := ParseSpecs(tc.m, []string{tc.token})
		if tc.want == nil {
			if len(got.Specs) != 0 || !reflect.DeepEqual(got.NonPackages, []string{tc.token}) {
				t.Errorf("%s (%s): got specs %+v non-packages %v, want it skipped as a non-package",
					tc.token, tc.comment, got.Specs, got.NonPackages)
			}
			continue
		}
		if len(got.Specs) != 1 || got.Specs[0] != *tc.want {
			t.Errorf("%s (%s): got %+v, want %+v", tc.token, tc.comment, got.Specs, *tc.want)
		}
	}
}

// pip constraints are not requirements: `-c` installs nothing, so the named
// package is still the install, and two -r files are a manifest install.
func TestPipConstraintsAndRequirementFiles(t *testing.T) {
	pip, _ := Lookup("pip")
	p := ParseSpecs(pip, []string{"-c", "constraints.txt", "flask"})
	if len(p.Specs) != 1 || p.Specs[0].Name != "flask" || len(p.ReqFiles) != 0 || len(p.NonPackages) != 0 {
		t.Errorf("-c constraints.txt flask: got %+v", p)
	}
	p = ParseSpecs(pip, []string{"--constraint=constraints.txt", "flask"})
	if len(p.Specs) != 1 || p.Specs[0].Name != "flask" {
		t.Errorf("--constraint= flask: got %+v", p)
	}
	p = ParseSpecs(pip, []string{"-r", "a.txt", "--requirement", "b.txt"})
	if !reflect.DeepEqual(p.ReqFiles, []string{"a.txt", "b.txt"}) || !manifestInstall(p) {
		t.Errorf("two -r files: got %+v, want both tracked and a manifest install", p)
	}
}

// Fail closed: an unpinned name is pinned to its latest release and that
// release is what is checked — and what can block.
func TestRun_UnpinnedResolvedToLatestCanBlock(t *testing.T) {
	for _, tc := range []struct {
		bin, eco string
		args     []string
	}{
		{"npm", "npm", []string{"install", "evil"}},
		{"pnpm", "npm", []string{"add", "evil"}},
		{"yarn", "npm", []string{"add", "evil"}},
		{"bun", "npm", []string{"add", "evil"}},
		{"pip", "pypi", []string{"install", "evil>=1.0"}},
		{"pip3", "pypi", []string{"install", "evil"}},
		{"poetry", "pypi", []string{"add", "evil"}},
		{"uv", "pypi", []string{"add", "evil"}},
		{"uv", "pypi", []string{"pip", "install", "evil"}},
	} {
		t.Run(tc.bin+" "+strings.Join(tc.args, " "), func(t *testing.T) {
			ex := &stubExec{}
			var got []check.Spec
			swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
				got = o.Specs
				s := ossbom.New(ossbom.Environment{})
				s.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:"+tc.eco+"/evil@6.6.6", "bad"))
				return s, nil
			})
			var asked []string
			err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args,
				ResolveLatest: func(_ context.Context, eco, name string) (string, error) {
					asked = append(asked, eco+"/"+name)
					return "6.6.6", nil
				}})
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("Run = %v, want ErrBlocked", err)
			}
			if ex.called {
				t.Error("a blocked install ran the manager")
			}
			if want := []string{tc.eco + "/evil"}; !reflect.DeepEqual(asked, want) {
				t.Errorf("resolved %v, want %v", asked, want)
			}
			if want := []check.Spec{{Ecosystem: tc.eco, Name: "evil", Version: "6.6.6"}}; !reflect.DeepEqual(got, want) {
				t.Errorf("checked %+v, want %+v", got, want)
			}
		})
	}
}

// Fail open is per package: one unreachable lookup drops only that package,
// and the rest are still checked and can still block.
func TestRun_PartialRegistryOutageStillChecksTheRest(t *testing.T) {
	ex := &stubExec{}
	var got []check.Spec
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o.Specs
		return malwareSBOM(ctx, o)
	})
	err := Run(context.Background(), Options{
		Bin:  "npm",
		Args: []string{"install", "flaky", "evil", "pinned@1.0.0"},
		ResolveLatest: func(_ context.Context, _, name string) (string, error) {
			if name == "flaky" {
				return "", errors.New("connection reset")
			}
			return "1.0.0", nil
		},
	})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Run = %v, want ErrBlocked", err)
	}
	want := []check.Spec{
		{Ecosystem: "npm", Name: "evil", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "pinned", Version: "1.0.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("checked %+v, want %+v", got, want)
	}
}

// A registry outage is not a 404: it is graded as its own warning, so the user
// can tell "private package" from "registry down".
func TestRun_RegistryOutageWarningIsNotThePrivatePackageOne(t *testing.T) {
	out := captureErrOut(t)
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	ctx := warn.NewContext(context.Background(), false)
	err := Run(ctx, Options{Bin: "npm", Args: []string{"install", "lodash"},
		ResolveLatest: func(context.Context, string, string) (string, error) {
			return "", errors.New("dial tcp: connection refused")
		}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ex.called {
		t.Fatal("an outage must not block the install")
	}
	if strings.Contains(out.String(), "not on the public registry") {
		t.Errorf("an outage was reported as a private package:\n%s", out)
	}
	if !strings.Contains(out.String(), "lodash") || !strings.Contains(out.String(), "skipping its check") {
		t.Errorf("verbose output must name the skipped package and the consequence:\n%s", out)
	}
}

// The real manager's exit status is the forwarder's, unchanged, on every path
// that runs it.
func TestRun_ManagerExitErrorPassesThrough(t *testing.T) {
	exitErr := exitError(t, 7)
	failing := func(context.Context, string, []string) error { return exitErr }
	componentSBOM := func(context.Context, scanRequest) (*ossbom.SBOM, error) {
		s := ossbom.New(ossbom.Environment{})
		s.AddComponent(ossbom.Component{Name: "a", Version: "1.0.0", Type: "npm"})
		return s, nil
	}
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"non-install", Options{Bin: "npm", Args: []string{"run", "test"}}},
		{"named clean", Options{Bin: "npm", Args: []string{"install", "lodash@1.0.0"}}},
		{"manifest clean", Options{Bin: "pip", Args: []string{"install", "-r", "req.txt"}}},
		{"local target", Options{Bin: "npm", Args: []string{"install", "./x.tgz"}}},
		{"skip-ci", Options{Bin: "npm", Args: []string{"install", "lodash@1.0.0"}, SkipCI: true}},
		{"passive after install", Options{Bin: "npm", Args: []string{"install"}, Passive: true}},
		{"passive alongside", Options{Bin: "pip", Args: []string{"install", "flask==1.0"}, Passive: true}},
		{"tool run", Options{Bin: "uvx", Args: []string{"ruff==0.6.0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swap(t, failing, cleanSBOM)
			swapScan(t, componentSBOM)
			err := Run(context.Background(), tc.opts)
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 7 {
				t.Errorf("Run = %v, want the manager's exit status 7 unchanged", err)
			}
		})
	}
}

// exitError produces a real *exec.ExitError with the given code by re-running
// this test binary as a helper process.
func exitError(t *testing.T, code int) *exec.ExitError {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcessExit$")
	cmd.Env = append(os.Environ(), fmt.Sprintf("OSSPREY_FORWARD_HELPER_EXIT=%d", code))
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != code {
		t.Fatalf("could not produce exit code %d: %v", code, err)
	}
	return ee
}

func TestHelperProcessExit(t *testing.T) {
	code := os.Getenv("OSSPREY_FORWARD_HELPER_EXIT")
	if code == "" {
		return
	}
	n, _ := strconv.Atoi(code)
	os.Exit(n)
}

// A passive install that fails is still catalogued (it may have installed most
// of the tree), and its failure is still the result.
func TestRun_PassiveFailedInstallIsStillScanned(t *testing.T) {
	installErr := errors.New("install failed")
	swap(t, func(context.Context, string, []string) error { return installErr }, cleanSBOM)
	scanned := false
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
		scanned = true
		return ossbom.New(ossbom.Environment{}), nil
	})
	err := Run(context.Background(), Options{Bin: "pnpm", Args: []string{"add", "left-pad"}, Passive: true})
	if !errors.Is(err, installErr) {
		t.Errorf("Run = %v, want the install's own error", err)
	}
	if !scanned {
		t.Error("a failed passive install must still be catalogued")
	}
}

// Passive routing per manager: an invocation that leaves no lockfile here
// submits the named packages instead of cataloguing ".".
func TestRun_PassiveRoutingPerManager(t *testing.T) {
	for _, tc := range []struct {
		bin        string
		args       []string
		afterScan  bool
		wantNamed  string
		wantPassed bool
	}{
		{"pnpm", []string{"add", "left-pad@1.3.0"}, true, "", true},
		{"yarn", []string{"add", "left-pad@1.3.0"}, true, "", true},
		{"poetry", []string{"add", "flask==3.0.0"}, true, "", true},
		{"uv", []string{"add", "flask==3.0.0"}, true, "", true},
		{"pnpm", []string{"add", "-g", "left-pad@1.3.0"}, false, "left-pad", true},
		{"yarn", []string{"add", "--no-lockfile", "left-pad@1.3.0"}, false, "left-pad", true},
		{"poetry", []string{"--directory", "../svc", "add", "flask==3.0.0"}, false, "flask", true},
		{"uv", []string{"pip", "install", "flask==3.0.0"}, false, "flask", true},
		{"uv", []string{"tool", "install", "ruff==0.6.0"}, false, "ruff", true},
		{"bun", []string{"add", "left-pad@1.3.0"}, false, "left-pad", true},
		{"npx", []string{"cowsay@1.5.0"}, false, "cowsay", true},
		{"uvx", []string{"ruff==0.6.0"}, false, "ruff", true},
	} {
		t.Run(tc.bin+" "+strings.Join(tc.args, " "), func(t *testing.T) {
			swapLocalBin(t, false)
			ex := &stubExec{}
			var got check.Options
			swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
				got = o
				return cleanSBOM(ctx, o)
			})
			var scan *scanRequest
			swapScan(t, func(_ context.Context, req scanRequest) (*ossbom.SBOM, error) {
				scan = &req
				return ossbom.New(ossbom.Environment{}), nil
			})
			if err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args, Passive: true}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !ex.called {
				t.Fatal("passive must always run the manager")
			}
			if tc.afterScan {
				if scan == nil || !scan.Installed || !scan.SubmitOnly {
					t.Errorf("want the post-install catalogue, got scan=%+v", scan)
				}
				return
			}
			if scan != nil {
				t.Errorf("no local lockfile here, yet %q was catalogued", scan.Dir)
			}
			if !got.SubmitOnly || len(got.Specs) != 1 || got.Specs[0].Name != tc.wantNamed {
				t.Errorf("submitted %+v (SubmitOnly=%v), want %s", got.Specs, got.SubmitOnly, tc.wantNamed)
			}
		})
	}
}

// The monitor id rides every passive submission, both kinds.
func TestRun_PassiveMonitorIDReachesTheSubmission(t *testing.T) {
	id := "ospi_" + strings.Repeat("ab", 32)

	var chk check.Options
	swap(t, func(context.Context, string, []string) error { return nil },
		func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
			chk = o
			return cleanSBOM(ctx, o)
		})
	if err := Run(context.Background(), Options{Bin: "pip", Args: []string{"install", "flask==3.0.0"},
		Passive: true, MonitorID: id}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if chk.MonitorID != id || !chk.SubmitOnly {
		t.Errorf("named submission: MonitorID=%q SubmitOnly=%v", chk.MonitorID, chk.SubmitOnly)
	}

	for _, tc := range []struct {
		bin  string
		args []string
	}{{"npm", []string{"install"}}, {"pip", []string{"install", "-r", "req.txt"}}} {
		bin, args := tc.bin, tc.args
		var req scanRequest
		swapScan(t, func(_ context.Context, r scanRequest) (*ossbom.SBOM, error) {
			req = r
			return ossbom.New(ossbom.Environment{}), nil
		})
		if err := Run(context.Background(), Options{Bin: bin, Args: args, Passive: true, MonitorID: id}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if req.MonitorID != id || !req.SubmitOnly {
			t.Errorf("%s %v: scan MonitorID=%q SubmitOnly=%v", bin, args, req.MonitorID, req.SubmitOnly)
		}
	}
}

// A failed passive post names the monitor, but never prints the whole id: it is
// a write credential and this line lands in CI logs.
func TestRun_PassiveFailureRedactsTheMonitorID(t *testing.T) {
	id := "ospi_" + strings.Repeat("cd", 32)
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
		return nil, errors.New("api unreachable")
	})
	out, err := quietOutput(t, context.Background(), Options{Bin: "npm", Args: []string{"install"},
		Passive: true, MonitorID: id})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "could not post scan") || !strings.Contains(out, "monitor ospi_") {
		t.Errorf("want a one-line warning naming the monitor, got %q", out)
	}
	if strings.Contains(out, id) {
		t.Errorf("the full monitor id was printed: %q", out)
	}
}

// Every named package failing resolution under passive posts nothing, and that
// is not a platform error: quiet stays silent, no "could not post" warning.
func TestRun_PassiveNothingResolvedIsNotAPostFailure(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
		t.Error("nothing resolved, yet a submission was made")
		return nil, nil
	})
	out, err := quietOutput(t, warn.NewContext(context.Background(), false), Options{
		Bin: "pip", Args: []string{"install", "flask"}, Passive: true,
		ResolveLatest: func(context.Context, string, string) (string, error) {
			return "", fmt.Errorf("%w (registry returned status 404)", registry.ErrNotFound)
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ex.called {
		t.Error("the install must run")
	}
	if out != "" {
		t.Errorf("want silence, got %q", out)
	}
}

// What docs/forwarder.md lists as not checked must still reach the manager,
// untouched, with no check and no project scan.
func TestRun_DocumentedUncheckedCommandsForward(t *testing.T) {
	for _, tc := range []struct {
		bin  string
		args []string
	}{
		{"pnpm", []string{"dlx", "cowsay", "moo"}},
		{"yarn", []string{"dlx", "cowsay"}},
		{"npm", []string{"init", "vite"}},
		{"npm", []string{"create", "vite@latest", "my-app"}},
		{"bun", []string{"create", "vite"}},
		{"yarn", []string{"create", "vite"}},
		{"npm", []string{"run", "build"}},
		{"pnpm", []string{"run", "build"}},
		{"pnpm", []string{"exec", "eslint"}},
		{"bun", []string{"run", "build"}},
		{"yarn", []string{"run", "build"}},
		{"poetry", []string{"run", "pytest"}},
		{"uv", []string{"run", "--with", "rich", "script.py"}},
		{"pip", []string{"list"}},
		{"pip", []string{"download", "flask"}},
		{"uv", []string{"pip", "compile", "requirements.in"}},
	} {
		t.Run(tc.bin+" "+strings.Join(tc.args, " "), func(t *testing.T) {
			ex := &stubExec{}
			swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
				t.Error("a pass-through command was checked")
				return nil, nil
			})
			if err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !ex.called || ex.bin != tc.bin || !reflect.DeepEqual(ex.args, tc.args) {
				t.Errorf("exec = %s %v (called=%v), want %s %v", ex.bin, ex.args, ex.called, tc.bin, tc.args)
			}
		})
	}
}

// Every forwarding path drains collected warnings before the manager runs:
// the manager's output owns the terminal from then on.
func TestRun_WarningsDrainBeforeEveryExec(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"clean named", Options{Bin: "npm", Args: []string{"install", "lodash", "@acme/one"}}},
		{"all unresolved", Options{Bin: "npm", Args: []string{"install", "@acme/one"}}},
		{"local only", Options{Bin: "npm", Args: []string{"install", "./x.tgz"}}},
		{"non-install", Options{Bin: "npm", Args: []string{"run", "x"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := warn.NewContext(context.Background(), false)
			// Something recorded before Run must be gone by the time we exec.
			warn.Add(ctx, warn.Entry{Class: "probe", One: "probe warning", Many: "%d probes", Item: "probe"})
			var leftAtExec string
			swap(t, func(context.Context, string, []string) error {
				leftAtExec = warn.Drain(ctx)
				return nil
			}, cleanSBOM)
			tc.opts.ResolveLatest = warnedResolve
			if _, err := quietOutput(t, ctx, tc.opts); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if leftAtExec != "" {
				t.Errorf("warnings were still pending when the manager ran:\n%s", leftAtExec)
			}
		})
	}
}

// A named install never takes the manifest-scan path, even when only some of
// its targets are registry packages.
func TestRun_MixedLocalAndRegistryTargetsChecksOnlyTheRegistryOnes(t *testing.T) {
	ex := &stubExec{}
	var got []string
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		for _, s := range o.Specs {
			got = append(got, s.Name)
		}
		return cleanSBOM(ctx, o)
	})
	args := []string{"add", "git+https://github.com/x/y.git", "../lib", "lodash@4.17.21", "https://e.com/a.tgz"}
	if err := Run(context.Background(), Options{Bin: "yarn", Args: args}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Equal(got, []string{"lodash"}) {
		t.Errorf("checked %v, want [lodash]", got)
	}
	if !ex.called || !reflect.DeepEqual(ex.args, args) {
		t.Errorf("exec args = %v, want %v unchanged", ex.args, args)
	}
}

// helpFlags reads a command's --help into the options that take a value and
// those that do not. Both clap (uv) and optparse (pip) print a value as
// "<NAME>" after the option.
func helpFlags(t *testing.T, bin string, args ...string) (value, boolean map[string]bool) {
	t.Helper()
	out, err := exec.Command(bin, append(args, "--help")...).Output()
	if err != nil {
		t.Skipf("%s %v --help: %v", bin, args, err)
	}
	value, boolean = map[string]bool{}, map[string]bool{}
	re := regexp.MustCompile(`(?m)^\s+(?:(-[a-zA-Z]), )?(--[a-z][a-z0-9-]*)(\.\.\.)?( <|  |$)`)
	for _, m := range re.FindAllStringSubmatch(string(out), -1) {
		into := boolean
		if m[4] == " <" {
			into = value
		}
		for _, f := range m[1:3] {
			if f != "" {
				into[f] = true
			}
		}
	}
	return value, boolean
}

// uv's install commands share one table, so a flag belongs in it only when it
// takes a value in every command that has it: `-e/--editable` takes a path in
// `uv pip install` but is a switch in `uv add` and `uv tool install`, where
// listing it swallowed the package after it. And every flag that takes a value
// everywhere must be listed, or its value is read as a package — or, for the
// requirements and package flags, the file or package goes unchecked.
func TestUVInstallFlagTablesMatchUV(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not installed")
	}
	valueIn, boolIn := map[string]bool{}, map[string]bool{}
	for _, sub := range [][]string{{"add"}, {"sync"}, {"lock"}, {"pip", "install"}, {"pip", "sync"}, {"tool", "install"}} {
		v, b := helpFlags(t, "uv", sub...)
		maps.Copy(valueIn, v)
		maps.Copy(boolIn, b)
	}
	listed := func(f string) bool {
		return valueFlags["uv"][f] || requirementFileFlags["uv"][f] ||
			packageValueFlags["uv"][f] || sourceFlags["uv"][f]
	}
	for _, table := range []map[string]bool{valueFlags["uv"], requirementFileFlags["uv"], packageValueFlags["uv"], sourceFlags["uv"]} {
		for f := range table {
			if boolIn[f] {
				t.Errorf("%s is a switch in some uv install command but is listed as taking a value", f)
			}
		}
	}
	for f := range valueIn {
		if !boolIn[f] && !listed(f) {
			t.Errorf("uv %s takes a value but is in no flag table", f)
		}
	}
}

// pip's install options, held to the installed pip the same way.
func TestPipInstallFlagTablesMatchPip(t *testing.T) {
	if _, err := exec.LookPath("pip"); err != nil {
		t.Skip("pip not installed")
	}
	value, boolean := helpFlags(t, "pip", "install")
	for f := range valueFlags["pip"] {
		if boolean[f] {
			t.Errorf("pip %s is a switch but is listed as taking a value", f)
		}
	}
	for f := range value {
		if !valueFlags["pip"][f] && !requirementFileFlags["pip"][f] {
			t.Errorf("pip %s takes a value but is in no flag table", f)
		}
	}
}

// A clause after a comma opens with an operator; a digit starts a new name.
func TestSplitRequirementsDigitStartsANewName(t *testing.T) {
	got := splitRequirements("ok,3to2,b>=1,<2")
	want := []string{"ok", "3to2", "b>=1,<2"}
	if !slices.Equal(got, want) {
		t.Fatalf("splitRequirements = %q, want %q", got, want)
	}
}
