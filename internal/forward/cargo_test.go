package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/trust"
)

// cargoMode is the path a cargo command takes: resolved into scratch and checked before its lock lands, checked before it runs, or passed straight through.
func cargoMode(args []string) string {
	m, _ := Lookup("cargo")
	if _, ok := m.resolveAt(args); ok {
		return "resolve"
	}
	if _, ok := m.installAt(args); ok {
		return "before"
	}
	return "through"
}

func TestCargoDetection(t *testing.T) {
	for _, tc := range []struct{ args, want string }{
		{"add serde", "resolve"},
		{"add serde@=1.0.100", "resolve"},
		{"add serde@1.0 --features derive tokio", "resolve"},
		{"add --git https://github.com/serde-rs/serde foo", "resolve"},
		{"add --path ../x", "resolve"},
		{"+nightly add serde", "resolve"},
		{"--config k=v add serde", "resolve"},
		{"--config=k=v add serde", "resolve"},
		{"-Z unstable-options -C sub add serde", "resolve"},
		{"--color always -v update", "resolve"},
		{"update", "resolve"},
		{"update -p serde --precise 1.0.100", "resolve"},
		{"generate-lockfile", "resolve"},
		{"fetch", "resolve"},
		{"install ripgrep", "before"},
		{"install --vers 14.1.0 ripgrep", "before"},
		{"install --path .", "before"},
		{"+stable install ripgrep", "before"},
		// clap reads a group of shorts as cargo 1.99.1 does: a value short takes the rest, else the next token.
		{"-qZ unstable-options install ripgrep", "before"},
		{"-Z unstable-options -qC sub add serde", "resolve"},
		{"-qCsub add serde", "resolve"},
		{"add --help", "through"},
		{"update -h", "through"},
		{"add -qh serde", "through"},
		{"update -vh", "through"},
		{"add -Fh serde", "resolve"},
		{"install --list", "through"},
		// Help or the version prints and runs nothing, before or after the verb (cargo 1.99.1).
		{"install ripgrep --help", "through"},
		{"install -h ripgrep", "through"},
		{"install -qh ripgrep", "through"},
		{"install ripgrep -hq", "through"},
		{"-h install ripgrep", "through"},
		{"--help install ripgrep", "through"},
		{"-qh install ripgrep", "through"},
		{"-V install ripgrep", "through"},
		{"--version install ripgrep", "through"},
		{"-h add serde", "through"},
		{"-V add serde", "through"},
		{"install --vers 14.1.0 -F h ripgrep", "before"},
		// An attached value is the option's, so -C-h names a directory called -h (cargo 1.99.1, nightly -C).
		{"-Zunstable-options -C-h install ripgrep", "before"},
		{"-qZunstable-options -C-h install ripgrep", "before"},
		{"install -F-h ripgrep", "before"},
		{"-Zunstable-options -C-h add serde", "resolve"},
		{"add -p-h serde", "resolve"},
		{"update -p-h", "resolve"},
		{"update -qp-h", "resolve"},
		{"update -p=-h", "resolve"},
		// An optional value never takes an option token, so the help after it is help (cargo 1.99.1).
		{"install --bin --help ripgrep", "through"},
		{"install --example -h ripgrep", "through"},
		{"install --target -qh ripgrep", "through"},
		{"install --bin rg ripgrep", "before"},
		{"add -p -h", "through"},
		{"update -p --help", "through"},
		{"update -qp -h", "through"},
		{"update -p serde -p -h", "through"},
		{"build", "through"},
		{"+nightly build", "through"},
		{"check", "through"},
		{"run", "through"},
		{"test", "through"},
		{"bench", "through"},
		{"b", "through"},
		{"remove serde", "through"},
		// rustup reads +toolchain only as the first argument; anywhere else cargo takes it as the command.
		{"-q +nightly add serde", "through"},
		{"--explain E0001", "through"},
		{"", "through"},
	} {
		if got := cargoMode(strings.Fields(tc.args)); got != tc.want {
			t.Errorf("cargo %s: %s, want %s", tc.args, got, tc.want)
		}
	}
}

func TestParseCargoInstall(t *testing.T) {
	crate := func(name, version string) []check.Spec {
		return []check.Spec{{Ecosystem: "cargo", Name: name, Version: version}}
	}
	ripgrep := crate("ripgrep", "")
	for _, tc := range []struct {
		args, defaultRegistry string
		specs                 []check.Spec
		nonPkgs               []string
	}{
		{"ripgrep", "", ripgrep, nil},
		{"--vers 14.1.0 ripgrep", "", crate("ripgrep", "14.1.0"), nil},
		{"--version=14.1.0 ripgrep fd-find", "", append(crate("ripgrep", "14.1.0"), crate("fd-find", "14.1.0")...), nil},
		{"ripgrep@14.1.0", "", crate("ripgrep", "14.1.0"), nil},
		{"ripgrep@=14.1.0", "", crate("ripgrep", "14.1.0"), nil},
		{"ripgrep@^14", "", []check.Spec{{Ecosystem: "cargo", Name: "ripgrep", Constraint: "^14"}}, nil},
		{"--version ^14 ripgrep", "", []check.Spec{{Ecosystem: "cargo", Name: "ripgrep", Constraint: "^14"}}, nil},
		{"--path .", "", nil, []string{"--path ."}},
		{"--git https://github.com/BurntSushi/ripgrep ripgrep", "", nil, []string{"ripgrep", "--git https://github.com/BurntSushi/ripgrep"}},
		{"--registry corp ripgrep", "", nil, []string{"ripgrep", "--registry corp"}},
		{"--index sparse+https://crates.corp.example/ ripgrep", "", nil, []string{"ripgrep", "--index sparse+https://crates.corp.example/"}},
		{"--registry crates-io ripgrep", "", ripgrep, nil},
		{"--index=sparse+https://index.crates.io/ ripgrep", "", ripgrep, nil},
		{"--index https://github.com/rust-lang/crates.io-index ripgrep", "", ripgrep, nil},
		{"--index https://index.crates.io/ ripgrep", "", nil, []string{"ripgrep", "--index https://index.crates.io/"}},
		// Only IDNA could say whether a non-ASCII host is github.com, so crates.io is never assumed.
		{"--index https://例子.test/rust-lang/crates.io-index ripgrep", "", nil, []string{"ripgrep", "--index https://例子.test/rust-lang/crates.io-index"}},
		{"ripgrep", "corp", nil, []string{"ripgrep", "registry.default corp"}},
		{"--registry crates-io ripgrep", "corp", ripgrep, nil},
		{"--registry other ripgrep", "corp", nil, []string{"ripgrep", "--registry other"}},
		{"--bin rg ripgrep", "", ripgrep, nil},
		{"--target x86_64-unknown-linux-gnu --root /opt -F a,b -j 4 --profile release ripgrep", "", ripgrep, nil},
		{"--features=derive --locked --force -f ripgrep", "", ripgrep, nil},
		{"--config k=v -Z unstable-options ripgrep", "", ripgrep, nil},
		// Grouped, attached and separate shorts, read as cargo 1.99.1 reads them.
		{"-qF pcre2 ripgrep@14.1.1", "", crate("ripgrep", "14.1.1"), nil},
		{"-q -F pcre2 ripgrep@14.1.1", "", crate("ripgrep", "14.1.1"), nil},
		{"-qFpcre2 ripgrep", "", ripgrep, nil},
		{"-qF=pcre2 ripgrep", "", ripgrep, nil},
		{"-fqF pcre2 ripgrep", "", ripgrep, nil},
		{"-vvF pcre2 ripgrep", "", ripgrep, nil},
		{"-Fq ripgrep", "", ripgrep, nil},
		{"-qj 4 ripgrep", "", ripgrep, nil},
		{"-qZ unstable-options ripgrep", "", ripgrep, nil},
		{"-j -2 ripgrep", "", ripgrep, nil},
		// An optional value is never an option, so pcre2 is -F's.
		{"--bin -F pcre2 ripgrep", "", ripgrep, nil},
		{"--bin -qF pcre2 ripgrep", "", ripgrep, nil},
		{"-qF pcre2 --registry corp ripgrep", "", nil, []string{"ripgrep", "--registry corp"}},
		{"./local", "", nil, []string{"./local"}},
	} {
		got := parseCargoInstall(strings.Fields(tc.args), tc.defaultRegistry)
		if !reflect.DeepEqual(got.Specs, tc.specs) || !reflect.DeepEqual(got.NonPackages, tc.nonPkgs) {
			t.Errorf("cargo install %s (default %q): specs %+v, non-packages %q; want %+v, %q", tc.args, tc.defaultRegistry, got.Specs, got.NonPackages, tc.specs, tc.nonPkgs)
		}
	}
}

// cargo install reads the last --config, then CARGO_REGISTRY_DEFAULT, then the configs from CARGO_HOME up, and never the project's.
func TestCargoDefaultRegistry(t *testing.T) {
	corp := "[registry]\ndefault = \"corp\"\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		env   string
		args  []string
		want  string
	}{
		{"nothing set", nil, "", []string{"install", "x"}, ""},
		{"CARGO_HOME", map[string]string{"home/.cargo/config.toml": corp}, "", []string{"install", "x"}, "corp"},
		{"CARGO_HOME's config without extension", map[string]string{"home/.cargo/config": corp}, "", []string{"install", "x"}, "corp"},
		{"above CARGO_HOME", map[string]string{".cargo/config.toml": corp}, "", []string{"install", "x"}, "corp"},
		{"crates-io named", map[string]string{"home/.cargo/config.toml": "[registry]\ndefault = \"crates-io\"\n"}, "", []string{"install", "x"}, ""},
		{"the project's config is not read", map[string]string{"cwd/.cargo/config.toml": corp}, "", []string{"install", "x"}, ""},
		{"an include may set it", map[string]string{"home/.cargo/config.toml": "include = [\"corp.toml\"]\n"}, "", []string{"install", "x"}, "an included config"},
		{"the environment", nil, "corp", []string{"install", "x"}, "corp"},
		{"the environment over CARGO_HOME", map[string]string{"home/.cargo/config.toml": corp}, "crates-io", []string{"install", "x"}, ""},
		{"--config before the verb", nil, "", []string{"--config", `registry.default="corp"`, "install", "x"}, "corp"},
		{"--config after the verb", nil, "", []string{"install", "--config=registry.default='corp'", "x"}, "corp"},
		{"the last --config wins", nil, "", []string{"--config", `registry.default="corp"`, "install", "--config", `registry.default="crates-io"`, "x"}, ""},
		{"--config over the environment", nil, "corp", []string{"--config", `registry.default="crates-io"`, "install", "x"}, ""},
		{"a --config file", map[string]string{"corp.toml": corp}, "", []string{"install", "--config", "@corp.toml", "x"}, "corp"},
		{"config.toml beside config is ignored", map[string]string{"home/.cargo/config": "[build]\njobs = 2\n", "home/.cargo/config.toml": corp}, "", []string{"install", "x"}, ""},
		{"config is read beside config.toml", map[string]string{"home/.cargo/config": corp, "home/.cargo/config.toml": "[build]\njobs = 2\n"}, "", []string{"install", "x"}, "corp"},
		{"config.toml beside config is ignored above CARGO_HOME", map[string]string{".cargo/config": "[build]\njobs = 2\n", ".cargo/config.toml": corp}, "", []string{"install", "x"}, ""},
		{"a config too deep to read may set it", map[string]string{"home/.cargo/config.toml": "x = " + strings.Repeat("[", 17) + strings.Repeat("]", 17) + "\n"}, "", []string{"install", "x"}, "a config it cannot read"},
		{"a config too large to read may set it", map[string]string{"home/.cargo/config.toml": "# " + strings.Repeat("x", catalog.CargoManifestLimit) + "\n"}, "", []string{"install", "x"}, "a config it cannot read"},
		{"a --config file too deep to read may set it", map[string]string{"deep.toml": "x = " + strings.Repeat("[", 17) + strings.Repeat("]", 17) + "\n"}, "", []string{"install", "--config", "@deep.toml", "x"}, "a config it cannot read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			for _, d := range []string{"home/.cargo", "cwd/.cargo"} {
				if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for name, data := range tc.files {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(base, name)), 0o755); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(base, name), data)
			}
			t.Setenv("CARGO_HOME", filepath.Join(base, "home", ".cargo"))
			t.Setenv("CARGO_REGISTRY_DEFAULT", tc.env)
			if tc.env == "" {
				unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
			}
			t.Chdir(filepath.Join(base, "cwd"))
			args := slices.Clone(tc.args)
			for i, a := range args {
				if strings.HasPrefix(a, "@") {
					args[i] = filepath.Join(base, a[1:])
				}
			}
			if got := cargoDefaultRegistry(args); got != tc.want {
				t.Errorf("cargo %v: %q, want %q", args, got, tc.want)
			}
		})
	}
}

// cargo 1.99.1 joins a relative CARGO_HOME to its physical working directory, after -C, cleans `..` without following links, and reads the configs from there up.
func TestCargoDefaultRegistryRelativeHome(t *testing.T) {
	corp := "[registry]\ndefault = \"corp\"\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		links map[string]string
		cwd   string
		home  string
		args  []string
		want  string
	}{
		{"the configs above it", map[string]string{".cargo/config.toml": corp}, nil, "cwd", ".cargo", []string{"install", "x"}, "corp"},
		{"its own config", map[string]string{"cwd/.cargo/config.toml": corp}, nil, "cwd", ".cargo", []string{"install", "x"}, "corp"},
		{"joined after -C", map[string]string{"cwd/sub/h/config.toml": corp}, nil, "cwd", "h", []string{"-Z", "unstable-options", "-qC", "sub", "install", "x"}, "corp"},
		{"not joined to the -C-less cwd", map[string]string{"cwd/sub/h/config.toml": corp}, nil, "cwd", "h", []string{"install", "x"}, ""},
		{"from the physical working directory", map[string]string{"real/.cargo/config.toml": corp}, map[string]string{"link": "real/proj"}, "link", ".cargo", []string{"install", "x"}, "corp"},
		{"with .. cleaned before links", map[string]string{".cargo/config.toml": corp, "other/.cargo/config.toml": "[registry]\ndefault = \"crates-io\"\n"}, map[string]string{"cwd/lnk": "other/deep"}, "cwd", "lnk/../h", []string{"install", "x"}, "corp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			for _, d := range []string{"cwd/sub", "real/proj", "other/deep"} {
				if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for name, data := range tc.files {
				if err := os.MkdirAll(filepath.Dir(filepath.Join(base, name)), 0o755); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(base, name), data)
			}
			for link, target := range tc.links {
				if err := os.Symlink(filepath.Join(base, target), filepath.Join(base, link)); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			t.Setenv("CARGO_HOME", tc.home)
			unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
			t.Chdir(filepath.Join(base, tc.cwd))
			if got := cargoDefaultRegistry(tc.args); got != tc.want {
				t.Errorf("CARGO_HOME=%s cargo %v: %q, want %q", tc.home, tc.args, got, tc.want)
			}
		})
	}
}

// cargo 1.99.1 resolves -C as chdir(2) does: from the physical working directory, each link followed before the `..` after it.
func TestCargoDefaultRegistryUnderCThroughALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows takes `..` off -C's path as written")
	}
	for _, tc := range []struct {
		name, config, link, target, cwd, home, dirC, wantDir, want string
	}{
		{"-C .. from a linked working directory", "real/.cargo/config.toml", "link", "real/proj", "link", ".cargo", "..", "real", "corp"},
		{"-C through a link and then ..", "cwd/.cargo/config.toml", "cwd/lnk", "other/deep", "cwd", "h", "lnk/../sub", "other/sub", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			if real, err := filepath.EvalSymlinks(base); err == nil {
				base = real
			}
			for _, d := range []string{"cwd/sub", "real/proj", "other/deep", "other/sub", filepath.Dir(tc.config)} {
				if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			writeFile(t, filepath.Join(base, tc.config), "[registry]\ndefault = \"corp\"\n")
			if err := os.Symlink(filepath.Join(base, tc.target), filepath.Join(base, tc.link)); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			t.Setenv("CARGO_HOME", tc.home)
			unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
			// The logical path, so the working directory starts out spelled through the link.
			t.Chdir(filepath.Join(base, tc.cwd))
			globals := []string{"-Zunstable-options", "-C", tc.dirC}
			if got, want := cargoConfigDir(globals), filepath.Join(base, tc.wantDir); got != want {
				t.Errorf("cargo %v runs in %s, want %s", globals, got, want)
			}
			if got := cargoDefaultRegistry(append(globals, "install", "x")); got != tc.want {
				t.Errorf("CARGO_HOME=%s cargo %v install: %q, want %q", tc.home, globals, got, tc.want)
			}
		})
	}
}

// clapHelpFlags reads clap's help, short-only options included: the options taking a value, those whose value is optional, and those taking none.
func clapHelpFlags(help string) (takes, optional, switches map[string]bool) {
	takes, optional, switches = map[string]bool{}, map[string]bool{}, map[string]bool{}
	flag := regexp.MustCompile(`^--?[A-Za-z][A-Za-z-]*$`)
	for _, line := range strings.Split(help, "\n") {
		fields := strings.Fields(line)
		var names []string
		i := 0
		for ; i < len(fields); i++ {
			f := strings.TrimSuffix(strings.TrimSuffix(fields[i], ","), "...")
			if !flag.MatchString(f) {
				break
			}
			names = append(names, f)
		}
		value := i < len(fields) && (strings.HasPrefix(fields[i], "<") || strings.HasPrefix(fields[i], "[<"))
		for _, n := range names {
			if value {
				takes[n] = true
				optional[n] = strings.HasPrefix(fields[i], "[<")
			} else {
				switches[n] = true
			}
		}
	}
	return takes, optional, switches
}

func TestCargoFlagTablesMatchCargo(t *testing.T) {
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Skip("cargo not installed")
	}
	install := [][]string{{"install", "--help"}}
	resolve := [][]string{{"add", "--help"}, {"update", "--help"}, {"fetch", "--help"}, {"generate-lockfile", "--help"}}
	for _, tc := range []struct {
		helps  [][]string
		table  map[string]bool
		hidden []string
		// only narrows the help's value options to the ones the table holds.
		only func(name string, optional bool) bool
	}{
		{[][]string{{"--help"}}, globalValueFlags["cargo"], nil, nil},
		{install, valueFlags["cargo"], []string{"--vers"}, nil},
		{install, cargoOptionalValues, nil, func(_ string, optional bool) bool { return optional }},
		// One table serves the four verbs, so no short may be a switch in one and take a value in another.
		{resolve, cargoResolveShorts, nil, func(name string, _ bool) bool { return !strings.HasPrefix(name, "--") }},
		{resolve, cargoResolveOptional, nil, func(name string, optional bool) bool { return optional && !strings.HasPrefix(name, "--") }},
	} {
		var help strings.Builder
		for _, args := range tc.helps {
			out, err := exec.Command(cargo, args...).Output()
			if err != nil {
				t.Skipf("cargo %v: %v", args, err)
			}
			help.Write(out)
		}
		takes, optional, switches := clapHelpFlags(help.String())
		if len(takes) == 0 {
			t.Fatalf("cargo %v: read no options from %q", tc.helps, help.String())
		}
		if tc.only != nil {
			for f := range takes {
				if !tc.only(f, optional[f]) {
					delete(takes, f)
				}
			}
		}
		for f := range takes {
			if !tc.table[f] {
				t.Errorf("cargo %v: %s takes a value but is missing from the table", tc.helps, f)
			}
		}
		for f := range tc.table {
			switch {
			case switches[f]:
				t.Errorf("cargo %v: %s is a switch, and listing it swallows the token after it", tc.helps, f)
			case !takes[f] && !slices.Contains(tc.hidden, f):
				t.Errorf("cargo %v: %s is not one of the options this table holds", tc.helps, f)
			}
		}
	}
	// cargoFetchUnknown lets through exactly what these two tables hold, so they must match what cargo fetch lists.
	out, err := exec.Command(cargo, "fetch", "--help").Output()
	if err != nil {
		t.Skipf("cargo fetch --help: %v", err)
	}
	takes, _, switches := clapHelpFlags(string(out))
	if !maps.Equal(takes, cargoFetchValues) || !maps.Equal(switches, cargoFetchSwitches) {
		t.Errorf("cargo fetch lists values %v and switches %v, want %v and %v", takes, switches, cargoFetchValues, cargoFetchSwitches)
	}
}

const memberManifest = "[package]\nname = \"a\"\nversion = \"0.1.0\"\n"

const cargo199 = "cargo 1.99.1 (5f94df478 2026-08-27)"

// cargoProject is a workspace with one member and no lock yet, the working directory, and what the forwarder finds for it; cargo is 1.99.1 and must not run unless the test says how.
func cargoProject(t *testing.T) (string, cargoWorkspace) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "Cargo.toml"), "[workspace]\nmembers = [\"a\"]\n")
	writeFile(t, filepath.Join(root, "a", "Cargo.toml"), memberManifest)
	t.Chdir(root)
	// A gating check resolves its credential before cargo runs: an API key here, with no stored login to refresh.
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	t.Setenv("OSSPREY_API_KEY", "test-key")
	unsetEnv(t, "API_KEY")
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	// The cargo add mirror goes in the user cache.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("LocalAppData", os.Getenv("XDG_CACHE_HOME"))
	ws := cargoWorkspace{
		Lock:      filepath.Join(root, "Cargo.lock"),
		Manifests: []string{filepath.Join(root, "Cargo.toml"), filepath.Join(root, "a", "Cargo.toml")},
		ConfigDir: root,
	}
	oldWS, oldVersion, oldMeta, oldRun, oldCommit, oldErr := cargoWorkspaceFn, cargoVersionFn, cargoMetadataFn, cargoRunFn, commitFn, cargoErrOut
	cargoErrOut = &bytes.Buffer{}
	cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return ws, nil }
	cargoVersionFn = func(context.Context, string, []string) (string, error) { return cargo199, nil }
	// The mirror holds the workspace the project has.
	cargoMetadataFn = func(ctx context.Context, dir string, args []string, _ string) (cargoWorkspace, error) {
		ws, err := cargoWorkspaceFn(ctx, args)
		return mirroredWorkspace(dir, ws), err
	}
	cargoRunFn = func(_ context.Context, _ string, _, args []string, _ io.Writer) error {
		t.Errorf("cargo %v ran", args)
		return nil
	}
	t.Cleanup(func() {
		cargoWorkspaceFn, cargoVersionFn, cargoMetadataFn, cargoRunFn, commitFn, cargoErrOut = oldWS, oldVersion, oldMeta, oldRun, oldCommit, oldErr
	})
	return root, ws
}

// mirroredWorkspace is ws as cargo spells it in the mirror where it runs in dir, the working directory's place there.
func mirroredWorkspace(dir string, ws cargoWorkspace) cargoWorkspace {
	s := strings.TrimSuffix(dir, mirrorPath("", cargoCwd(nil)))
	out := cargoWorkspace{Lock: mirrorPath(s, ws.Lock), ConfigDir: ws.ConfigDir}
	for _, m := range ws.Manifests {
		out.Manifests = append(out.Manifests, mirrorPath(s, m))
	}
	return out
}

// unsetEnv removes a variable for the test, since cargo reads an empty one as set.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const evilLock = "version = 4\n\n[[package]]\nname = \"evil\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"

const addedEvil = "\n[dependencies]\nevil = \"1\"\n"

// fakeCargo is a cargo 1.97 that locks lock where the last --config resolver.lockfile-path, else CARGO_RESOLVER_LOCKFILE_PATH, else its root says, and for add appends addedEvil to the member manifest under its working directory.
type fakeCargo struct {
	t    *testing.T
	root string
	lock string
	// ignore writes the lock at root whatever points it elsewhere, as cargo before 1.97 does.
	ignore bool
	err    error
	runs   []fakeRun
}

type fakeRun struct {
	dir       string
	env, args []string
	// seen is what the lock cargo was pointed at held when it started.
	seen string
}

func (f *fakeCargo) run(_ context.Context, dir string, env, args []string, stderr io.Writer) error {
	at := redirectedLock(env, args)
	seen, _ := os.ReadFile(at)
	f.runs = append(f.runs, fakeRun{dir, env, args, string(seen)})
	if args[verbIndex("cargo", args)] == "add" {
		p := filepath.Join(dir, "a", "Cargo.toml")
		writeFile(f.t, p, readFile(f.t, p)+addedEvil)
	}
	if at == "" || f.ignore {
		at = filepath.Join(f.root, "Cargo.lock")
	}
	if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
		f.t.Fatal(err)
	}
	writeFile(f.t, at, f.lock)
	fmt.Fprintf(stderr, "     Locking 1 package to %s\n", at)
	return f.err
}

// swapCargo makes f the cargo the forwarder runs.
func swapCargo(t *testing.T, f *fakeCargo) {
	old := cargoRunFn
	cargoRunFn = f.run
	t.Cleanup(func() { cargoRunFn = old })
}

// redirectedLock is where cargo 1.97 writes the lock for env and args: the last --config's resolver.lockfile-path, else the variable, else "".
func redirectedLock(env, args []string) string {
	at := ""
	for _, c := range cargoConfigArgs(args) {
		doc, err := catalog.ParseCargoConfig([]byte(c))
		if r, ok := doc["resolver"].(map[string]any); err == nil && ok {
			if p, ok := r["lockfile-path"].(string); ok {
				at = p
			}
		}
	}
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "CARGO_RESOLVER_LOCKFILE_PATH="); ok && at == "" {
			at = v
		}
	}
	return at
}

// landings records each project file renamed into place, in order, and renames it.
func landings(t *testing.T) *[]string {
	var got []string
	old := commitFn
	commitFn = func(s staged) error {
		got = append(got, s.path)
		return old(s)
	}
	t.Cleanup(func() { commitFn = old })
	return &got
}

// noLanding fails the test when anything is renamed into the project.
func noLanding(t *testing.T) {
	old := commitFn
	commitFn = func(s staged) error {
		t.Errorf("wrote %s", s.path)
		return errors.New("no landing")
	}
	t.Cleanup(func() { commitFn = old })
}

// needSymlinks skips a test that makes links where links cannot be made.
func needSymlinks(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(dir, filepath.Join(dir, "link")); err != nil {
		t.Skipf("cannot make links: %v", err)
	}
}

// lockScan records the scan of the lock and answers with sbom.
func lockScan(t *testing.T, got *scanRequest, lock *string, sbom func() *ossbom.SBOM) func(context.Context, scanRequest) (*ossbom.SBOM, error) {
	return func(_ context.Context, req scanRequest) (*ossbom.SBOM, error) {
		*got = req
		entries, err := os.ReadDir(req.Dir)
		if err != nil || len(entries) != 1 || entries[0].Name() != "Cargo.lock" {
			t.Errorf("scanned %s holding %v (%v), want the lock alone", req.Dir, entries, err)
		}
		*lock = readFile(t, filepath.Join(req.Dir, "Cargo.lock"))
		return sbom(), nil
	}
}

func evilSBOM() *ossbom.SBOM {
	s := ossbom.New(ossbom.Environment{})
	s.AddComponent(ossbom.Component{Name: "evil", Version: "1.0.0", Type: "cargo"})
	s.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:cargo/evil@1.0.0", "bad"))
	return s
}

func cleanCrates() *ossbom.SBOM {
	s := ossbom.New(ossbom.Environment{})
	s.AddComponent(ossbom.Component{Name: "serde", Version: "1.0.228", Type: "cargo"})
	s.AddComponent(ossbom.Component{Name: "itoa", Version: "1.0.15", Type: "cargo"})
	return s
}

// projectState is every file under root with its bytes, for a byte-for-byte comparison.
func projectState(t *testing.T, root string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			got[p] = readFile(t, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// cargo before 1.97, and 1.97.0's pre-releases, ignore resolver.lockfile-path and write the project's lock (verified with 1.96.0, 1.80.0 and 1.97.0-nightly), so semver order decides, a pre-release below its release.
func TestCargoRedirects(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{cargo199, true},
		{"cargo 1.97.0 (c980f4866 2026-06-30)", true},
		{"cargo 1.97.1", true},
		{"cargo 1.98.0-nightly (eb94155a9 2026-06-09)", true},
		{"cargo 1.100.0-beta.13 (3acc79c0c 2026-11-05)", true},
		{"cargo 2.0.0", true},
		{"cargo 1.97.0-beta.3 (31bcf52c8 2026-05-28)", false},
		{"cargo 1.97.0-nightly (eb94155a9 2026-04-09)", false},
		{"cargo 1.96.0 (30a34c682 2026-05-25)", false},
		{"cargo 1.80.0 (376290515 2024-07-16)", false},
		{"cargo 1.97", false},
		{"cargo 1.970.0x", false},
		{"rustc 1.99.1", false},
		{"cargo-1.99.1", false},
		{"", false},
		{"cargo 1.99999999999999999999.0", false},
	} {
		if got := cargoRedirects(tc.line); got != tc.want {
			t.Errorf("%q: %v, want %v", tc.line, got, tc.want)
		}
	}
}

// Every refusal comes before cargo runs and leaves the project byte for byte as it was (OSS-2553).
func TestRunCargo_RefusesBeforeCargoRuns(t *testing.T) {
	big := func(t *testing.T, p string) {
		writeFile(t, p, "")
		if err := os.Truncate(p, catalog.CargoProofLimit+1); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name    string
		args    string
		prepare func(t *testing.T, root string, ws cargoWorkspace)
		want    string
	}{
		{"cargo 1.96.0", "update", func(*testing.T, string, cargoWorkspace) {
			cargoVersionFn = func(context.Context, string, []string) (string, error) {
				return "cargo 1.96.0 (30a34c682 2026-05-25)", nil
			}
		}, "ossprey needs cargo 1.97 or later to check it before it changes the project, and found `cargo 1.96.0 (30a34c682 2026-05-25)`"},
		{"cargo 1.80.0 on add --dry-run", "add --dry-run evil", func(*testing.T, string, cargoWorkspace) {
			cargoVersionFn = func(context.Context, string, []string) (string, error) {
				return "cargo 1.80.0 (376290515 2024-07-16)", nil
			}
		}, "ossprey needs cargo 1.97 or later"},
		{"no version", "add evil", func(*testing.T, string, cargoWorkspace) {
			cargoVersionFn = func(context.Context, string, []string) (string, error) { return "", errors.New("exit status 1") }
		}, "could not read cargo's version (exit status 1)"},
		{"a moved lock", "add evil", func(t *testing.T, _ string, _ cargoWorkspace) {
			cargoWorkspaceFn = readCargoWorkspace
			t.Setenv("CARGO_RESOLVER_LOCKFILE_PATH", "elsewhere/Cargo.lock")
		}, "its Cargo.lock cannot be checked (a resolver.lockfile-path may move it)"},
		{"a moved lock on update", "update", func(t *testing.T, _ string, _ cargoWorkspace) {
			cargoWorkspaceFn = readCargoWorkspace
			t.Setenv("CARGO_RESOLVER_LOCKFILE_PATH", "elsewhere/Cargo.lock")
		}, "its Cargo.lock cannot be checked (a resolver.lockfile-path may move it)"},
		{"a config that cannot be read", "update", func(t *testing.T, root string, _ cargoWorkspace) {
			cargoWorkspaceFn = readCargoWorkspace
			t.Setenv("CARGO_HOME", t.TempDir())
			if err := os.MkdirAll(filepath.Join(root, ".cargo", "config.toml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "its Cargo.lock cannot be checked (a resolver.lockfile-path may move it)"},
		{"a cargo script", "-Zscript generate-lockfile --manifest-path s.rs", func(*testing.T, string, cargoWorkspace) {
			cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return cargoWorkspace{}, errScriptLock }
		}, "its Cargo.lock cannot be checked (a cargo script keeps it in the build directory)"},
		{"no workspace", "add evil", func(*testing.T, string, cargoWorkspace) {
			cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) {
				return cargoWorkspace{}, errors.New("cargo metadata: error: could not find `Cargo.toml` in `/empty` or any parent directory")
			}
		}, "its Cargo.lock cannot be checked (cargo metadata: error: could not find `Cargo.toml`"},
		{"no workspace on update", "update", func(*testing.T, string, cargoWorkspace) {
			cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) {
				return cargoWorkspace{}, errors.New("cargo metadata: error: could not find `Cargo.toml` in `/empty` or any parent directory")
			}
		}, "its Cargo.lock cannot be checked (cargo metadata: error: could not find `Cargo.toml`"},
		{"a lock that is not a regular file", "update", func(t *testing.T, _ string, ws cargoWorkspace) {
			if err := os.Remove(ws.Lock); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(ws.Lock, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		{"a lock over the bound", "fetch", func(t *testing.T, _ string, ws cargoWorkspace) { big(t, ws.Lock) }, "over the"},
		{"a manifest over the bound", "add -p a evil", func(t *testing.T, root string, _ cargoWorkspace) {
			big(t, filepath.Join(root, "a", "Cargo.toml"))
		}, "over the"},
		// --breaking rewrites Cargo.toml as well as the lock, and only the lock is redirected (verified with cargo 1.99.1).
		{"update --breaking", "update -Zunstable-options --breaking evil", nil, "--breaking edits Cargo.toml"},
		{"update -b in a group", "update -Zunstable-options -qb evil", nil, "--breaking edits Cargo.toml"},
		{"update --breaking --dry-run", "update -Zunstable-options --breaking -n", nil, "--breaking edits Cargo.toml"},
		// An empty -p takes no option token, so the flag after it is cargo's (verified with cargo 1.99.1).
		{"update --breaking after an empty -p", "update -Zunstable-options -p evil -p --breaking", nil, "--breaking edits Cargo.toml"},
		{"update -b after an empty -p", "update -Zunstable-options -p evil -p -b", nil, "--breaking edits Cargo.toml"},
		{"update -b where a value may be", "update -Zunstable-options -m -b", nil, "--breaking edits Cargo.toml"},
		// The resolve step passes on only what update takes, so the lock landed before cargo fetch rejected the line.
		{"fetch with an option it lacks", "fetch --tagret x86_64-unknown-linux-gnu", nil, "cargo fetch would reject `--tagret`"},
		{"fetch with a positional", "fetch serde", nil, "cargo fetch would reject `serde`"},
		{"fetch with a value missing", "fetch --color --locked", nil, "cargo fetch would reject `--color`"},
		{"fetch with an argument after --", "fetch -- serde", nil, "cargo fetch would reject `serde`"},
		// rustup keys a directory override by the project's path, so the mirror may run an older cargo (verified with rustup).
		{"another toolchain in the mirror", "add -p a evil", func(t *testing.T, _ string, _ cargoWorkspace) {
			needSymlinks(t)
			cargoVersionFn = func(_ context.Context, dir string, _ []string) (string, error) {
				if dir == "" {
					return cargo199, nil
				}
				return "cargo 1.96.0 (30a34c682 2026-05-25)", nil
			}
		}, "the mirror of the workspace runs `cargo 1.96.0 (30a34c682 2026-05-25)`, not the project's `" + cargo199 + "`"},
		// An absolute path in a Cargo.toml leads cargo out of the mirror, where add -p wrote a member's manifest through a link (verified with cargo 1.99.1).
		{"a member only the mirror has", "add -p b evil", func(t *testing.T, _ string, _ cargoWorkspace) {
			needSymlinks(t)
			inner := cargoMetadataFn
			cargoMetadataFn = func(ctx context.Context, dir string, args []string, configDir string) (cargoWorkspace, error) {
				ws, err := inner(ctx, dir, args, configDir)
				ws.Manifests = append(ws.Manifests, filepath.Join(filepath.Dir(ws.Lock), "b", "Cargo.toml"))
				return ws, err
			}
		}, "cargo would see another workspace in ossprey's copy of it, since it would take "},
		// cargo's own error, not the absolute-path explanation, since a [workspace] above the cache fails the same way.
		{"no workspace in the mirror", "add evil", func(t *testing.T, _ string, _ cargoWorkspace) {
			needSymlinks(t)
			cargoMetadataFn = func(context.Context, string, []string, string) (cargoWorkspace, error) {
				return cargoWorkspace{}, errors.New("cargo metadata: error: current package believes it's in a workspace when it's not: workspace: /c2/Cargo.toml")
			}
		}, "(cargo metadata fails in ossprey's copy of the workspace with error: current package believes it's in a workspace when it's not: workspace: /c2/Cargo.toml; either a Cargo.toml names"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, ws := cargoProject(t)
			writeFile(t, ws.Lock, "version = 4\n# before\n")
			if tc.prepare != nil {
				tc.prepare(t, root, ws)
			}
			before := projectState(t, root)
			swap(t, func(_ context.Context, _ string, args []string) error {
				t.Errorf("cargo %v ran", args)
				return nil
			}, cleanSBOM)
			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: strings.Fields(tc.args)})
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.Is(err, ErrBlocked) {
				t.Errorf("Run = %v, want an error naming %q", err, tc.want)
			}
			if out != "" {
				t.Errorf("printed %q, want only main's error line", out)
			}
			if after := projectState(t, root); !reflect.DeepEqual(after, before) {
				t.Errorf("the project changed")
			}
		})
	}
	for _, args := range []string{"add -p a evil", "update"} {
		t.Run("no credential on "+args, func(t *testing.T) {
			root, _ := cargoProject(t)
			unsetEnv(t, "OSSPREY_API_KEY")
			ex := &stubExec{}
			swap(t, ex.fn, check.Run)
			_, want := quietOutput(t, context.Background(), Options{Bin: "npm", Args: []string{"install", "left-pad@1.0.0"}})
			if want == nil || ex.called {
				t.Fatalf("npm install = %v, npm ran = %v; want a credentials error before npm", want, ex.called)
			}
			before := projectState(t, root)
			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: strings.Fields(args)})
			if err == nil || err.Error() != want.Error() || out != "" {
				t.Fatalf("Run = %v, output %q; want %v alone", err, out, want)
			}
			if !reflect.DeepEqual(projectState(t, root), before) {
				t.Error("the project changed")
			}
		})
	}
}

// ossprey's --config comes last before any `--`, since the last --config beats the variable and every earlier --config (verified with cargo 1.97.0 and 1.99.1).
func TestCargoRedirectArgs(t *testing.T) {
	lock := filepath.Join("scratch", `a"b\c`, "Cargo.lock")
	cfg := "--config resolver.lockfile-path=" + tomlString(lock)
	for _, tc := range []struct{ args, want string }{
		{"update", "update " + cfg},
		{"--config k=v update -p serde", "--config k=v update -p serde " + cfg},
		{"update --config resolver.lockfile-path=\"Cargo.lock\"", "update --config resolver.lockfile-path=\"Cargo.lock\" " + cfg},
		{"update -- --config x", "update " + cfg + " -- --config x"},
	} {
		got := cargoRedirectArgs(strings.Fields(tc.args), lock)
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%q: %q, want %q", tc.args, got, tc.want)
		}
		if at := redirectedLock(nil, got); at != lock {
			t.Errorf("%q: cargo would lock %q, want %q", tc.args, at, lock)
		}
	}
}

// A blocked command leaves every project file as it was, byte for byte and the same file, and writes nothing (OSS-2553).
func TestRunCargo_BlockLeavesTheProjectAsItWas(t *testing.T) {
	for _, tc := range []struct {
		args    string
		lock    bool
		symlink bool
	}{
		{"add -p a evil", false, true},
		{"add -p a evil", true, true},
		{"update", false, false},
		{"update", true, false},
		{"generate-lockfile", false, false},
		{"fetch", true, false},
	} {
		t.Run(fmt.Sprintf("%s, lock %v", tc.args, tc.lock), func(t *testing.T) {
			if tc.symlink {
				needSymlinks(t)
			}
			root, ws := cargoProject(t)
			if tc.lock {
				writeFile(t, ws.Lock, "version = 4\n# before\n")
			}
			before := projectState(t, root)
			infos := map[string]fs.FileInfo{}
			for p := range before {
				infos[p], _ = os.Stat(p)
			}
			f := &fakeCargo{t: t, root: root, lock: evilLock}
			swapCargo(t, f)
			swap(t, func(_ context.Context, _ string, args []string) error {
				t.Errorf("cargo %v ran after a block", args)
				return nil
			}, cleanSBOM)
			noLanding(t)
			var req scanRequest
			var scanned string
			swapScan(t, lockScan(t, &req, &scanned, evilSBOM))

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: strings.Fields(tc.args)})
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("Run = %v, want ErrBlocked", err)
			}
			if len(f.runs) != 1 || scanned != evilLock {
				t.Errorf("cargo ran %d times, scanned %q; want one run and its lock checked", len(f.runs), scanned)
			}
			if !req.Installed || req.SubmitOnly || req.CargoConfigDir != root || filepath.Base(req.Dir) != filepath.Base(root) {
				t.Errorf("scan request %+v", req)
			}
			if after := projectState(t, root); !reflect.DeepEqual(after, before) {
				t.Errorf("project = %v, want %v", after, before)
			}
			for p, fi := range infos {
				if now, err := os.Stat(p); err != nil || !os.SameFile(fi, now) {
					t.Errorf("%s is another file now (%v)", p, err)
				}
			}
			for _, line := range []string{"Installation blocked.", "Error: WARNING: evil:1.0.0 contains malware", "ossprey: blocked `cargo " + tc.args + "`\nossprey: the project was not changed\n"} {
				if !strings.Contains(out, line) {
					t.Errorf("output lacks %q:\n%s", line, out)
				}
			}
			if entries, _ := os.ReadDir(filepath.Join(os.Getenv("XDG_CACHE_HOME"), "ossprey")); len(entries) != 0 {
				t.Errorf("the mirror is still there: %v", entries)
			}
		})
	}
}

// A clean add writes the lock and then the manifest, each keeping its mode, a linked lock through its link as cargo writes one, and prints the one verdict line (OSS-2553).
func TestRunCargoAdd_CleanLandsTheLockThenTheManifest(t *testing.T) {
	needSymlinks(t)
	for _, lock := range []string{"none", "file", "link"} {
		lockExisted := lock != "none"
		t.Run("lock "+lock, func(t *testing.T) {
			root, ws := cargoProject(t)
			member := filepath.Join(root, "a", "Cargo.toml")
			if err := os.Chmod(member, 0o600); err != nil {
				t.Fatal(err)
			}
			target := ws.Lock
			if lock == "link" {
				target = filepath.Join(root, "shared.lock")
				if err := os.Symlink("shared.lock", ws.Lock); err != nil {
					t.Fatal(err)
				}
			}
			if lockExisted {
				writeFile(t, target, "version = 4\n# before\n")
				if err := os.Chmod(target, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			rootManifest := readFile(t, filepath.Join(root, "Cargo.toml"))
			f := &fakeCargo{t: t, root: root, lock: evilLock}
			swapCargo(t, f)
			swap(t, nil, cleanSBOM)
			landed := landings(t)
			var req scanRequest
			var scanned string
			swapScan(t, lockScan(t, &req, &scanned, cleanCrates))

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if want := "ossprey: no malware found in 2 packages in Cargo.lock\n"; out != want {
				t.Errorf("output = %q, want %q", out, want)
			}
			if want := []string{ws.Lock, member}; !reflect.DeepEqual(*landed, want) {
				t.Errorf("wrote %v, want %v in that order", *landed, want)
			}
			if got := readFile(t, target); got != evilLock {
				t.Errorf("lock = %q, want cargo's", got)
			}
			if fi, err := os.Lstat(ws.Lock); err != nil || (fi.Mode()&fs.ModeSymlink != 0) != (lock == "link") {
				t.Errorf("Cargo.lock is a link: %v (%v), want %v", fi.Mode()&fs.ModeSymlink != 0, err, lock == "link")
			}
			if got := readFile(t, member); got != memberManifest+addedEvil {
				t.Errorf("member manifest = %q, want cargo's", got)
			}
			if got := readFile(t, filepath.Join(root, "Cargo.toml")); got != rootManifest {
				t.Errorf("root manifest = %q, want it untouched", got)
			}
			if runtime.GOOS != "windows" {
				for p, want := range map[string]fs.FileMode{member: 0o600, ws.Lock: map[bool]fs.FileMode{true: 0o640, false: 0o666 &^ umask(t)}[lockExisted]} {
					if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
						t.Errorf("%s mode %v (%v), want %v", p, fi.Mode().Perm(), err, want)
					}
				}
			}
			if run := f.runs[0]; run.dir == root || !strings.HasPrefix(run.dir, canonicalDir(os.Getenv("XDG_CACHE_HOME"))) {
				t.Errorf("cargo add ran in %s, want the mirror", run.dir)
			}
			if got, want := cargoErrOut.(*bytes.Buffer).String(), "     Locking 1 package to "+ws.Lock+"\n"; got != want {
				t.Errorf("cargo's stderr = %q, want %q naming the project's lock", got, want)
			}
		})
	}
}

// A clean update resolves from the project's lock and writes the new one, keeping its mode, a linked lock through its link as cargo writes one, and prints the one verdict line (OSS-2553).
func TestRunCargoUpdate_CleanLandsTheLock(t *testing.T) {
	for _, lock := range []string{"none", "file", "link"} {
		lockExisted := lock != "none"
		t.Run("lock "+lock, func(t *testing.T) {
			if lock == "link" {
				needSymlinks(t)
			}
			root, ws := cargoProject(t)
			target := ws.Lock
			if lock == "link" {
				target = filepath.Join(root, "shared.lock")
				if err := os.Symlink("shared.lock", ws.Lock); err != nil {
					t.Fatal(err)
				}
			}
			old := ""
			if lockExisted {
				old = "version = 4\n# before\n"
				writeFile(t, target, old)
				if err := os.Chmod(target, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			f := &fakeCargo{t: t, root: root, lock: evilLock}
			swapCargo(t, f)
			swap(t, nil, cleanSBOM)
			landed := landings(t)
			var req scanRequest
			var scanned string
			swapScan(t, lockScan(t, &req, &scanned, cleanCrates))

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if want := "ossprey: no malware found in 2 packages in Cargo.lock\n"; out != want {
				t.Errorf("output = %q, want %q", out, want)
			}
			if f.runs[0].seen != old || scanned != evilLock {
				t.Errorf("cargo started from %q and %q was scanned, want the project's lock and then cargo's", f.runs[0].seen, scanned)
			}
			if want := []string{ws.Lock}; !reflect.DeepEqual(*landed, want) {
				t.Errorf("wrote %v, want %v", *landed, want)
			}
			if got := readFile(t, target); got != evilLock {
				t.Errorf("lock = %q, want cargo's", got)
			}
			if fi, err := os.Lstat(ws.Lock); err != nil || (fi.Mode()&fs.ModeSymlink != 0) != (lock == "link") {
				t.Errorf("Cargo.lock is a link: %v (%v), want %v", fi.Mode()&fs.ModeSymlink != 0, err, lock == "link")
			}
			if runtime.GOOS != "windows" {
				want := map[bool]fs.FileMode{true: 0o640, false: 0o666 &^ umask(t)}[lockExisted]
				if fi, err := os.Stat(ws.Lock); err != nil || fi.Mode().Perm() != want {
					t.Errorf("lock mode %v (%v), want %v", fi.Mode().Perm(), err, want)
				}
			}
			if got, want := cargoErrOut.(*bytes.Buffer).String(), "     Locking 1 package to "+ws.Lock+"\n"; got != want {
				t.Errorf("cargo's stderr = %q, want %q naming the project's lock", got, want)
			}
		})
	}
}

// umask is the process's file creation mask, read from a new file.
func umask(t *testing.T) fs.FileMode {
	p := filepath.Join(t.TempDir(), "f")
	fh, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o777)
	if err != nil {
		t.Fatal(err)
	}
	fh.Close()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return 0o777 &^ fi.Mode().Perm()
}

// A clean update that changed nothing rewrites nothing, as cargo never rewrites an unchanged lock (verified with cargo 1.99.1).
func TestRunCargoUpdate_UnchangedBytesAreNotRewritten(t *testing.T) {
	root, ws := cargoProject(t)
	writeFile(t, ws.Lock, evilLock)
	before, err := os.Stat(ws.Lock)
	if err != nil {
		t.Fatal(err)
	}
	swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock})
	swap(t, nil, cleanSBOM)
	noLanding(t)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return cleanCrates(), nil })
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
	if err != nil || out != "ossprey: no malware found in 2 packages in Cargo.lock\n" {
		t.Errorf("Run = %v, output %q", err, out)
	}
	if now, err := os.Stat(ws.Lock); err != nil || !os.SameFile(before, now) || !now.ModTime().Equal(before.ModTime()) {
		t.Errorf("the lock was rewritten (%v)", err)
	}
}

// A project file changed while the check ran stops the landing whole, so the edit is kept and the lock never runs ahead of the manifest (OSS-2553).
func TestRunCargoAdd_ChangedDuringTheCheckLandsNothing(t *testing.T) {
	needSymlinks(t)
	for _, edited := range []string{"Cargo.lock", filepath.Join("a", "Cargo.toml")} {
		t.Run(edited, func(t *testing.T) {
			root, ws := cargoProject(t)
			writeFile(t, ws.Lock, "version = 4\n# before\n")
			swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock})
			swap(t, nil, cleanSBOM)
			noLanding(t)
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
				writeFile(t, filepath.Join(root, edited), "# edited meanwhile\n")
				return cleanCrates(), nil
			})
			before := projectState(t, root)
			before[filepath.Join(root, edited)] = "# edited meanwhile\n"
			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
			if want := edited + " changed while ossprey checked it, so nothing was written; run the command again"; err == nil || err.Error() != want || out != "" {
				t.Errorf("Run = %v, output %q; want %q alone", err, out, want)
			}
			if !reflect.DeepEqual(projectState(t, root), before) {
				t.Error("the project changed beyond the edit")
			}
		})
	}
}

// A manifest rename that fails after the lock's puts the lock back, or removes a new one, so the project never keeps a lock its manifests do not match (OSS-2553).
func TestRunCargoAdd_FailedRenamePutsTheLockBack(t *testing.T) {
	needSymlinks(t)
	for _, lockExisted := range []bool{false, true} {
		t.Run(fmt.Sprintf("lock %v", lockExisted), func(t *testing.T) {
			root, ws := cargoProject(t)
			if lockExisted {
				writeFile(t, ws.Lock, "version = 4\n# before\n")
			}
			swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock})
			swap(t, nil, cleanSBOM)
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return cleanCrates(), nil })
			before := projectState(t, root)
			landed := landings(t)
			rename := commitFn
			commitFn = func(s staged) error {
				if s.path == ws.Manifests[1] {
					return errors.New("injected")
				}
				return rename(s)
			}
			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
			if want := "could not write " + filepath.Join("a", "Cargo.toml") + " (injected), so ossprey put back Cargo.lock and the project is as it was"; err == nil || err.Error() != want || out != "" {
				t.Errorf("Run = %v, output %q; want %q alone", err, out, want)
			}
			if want := map[bool][]string{false: {ws.Lock}, true: {ws.Lock, ws.Lock}}[lockExisted]; !reflect.DeepEqual(*landed, want) {
				t.Errorf("renamed %v, want %v", *landed, want)
			}
			if !reflect.DeepEqual(projectState(t, root), before) {
				t.Error("the project was not put back")
			}
		})
	}
}

// A lock changed while the check of an update ran is kept and nothing lands (OSS-2553).
func TestRunCargoUpdate_ChangedDuringTheCheckLandsNothing(t *testing.T) {
	root, ws := cargoProject(t)
	writeFile(t, ws.Lock, "version = 4\n# before\n")
	swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock})
	swap(t, nil, cleanSBOM)
	noLanding(t)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
		writeFile(t, ws.Lock, "# edited meanwhile\n")
		return cleanCrates(), nil
	})
	before := projectState(t, root)
	before[ws.Lock] = "# edited meanwhile\n"
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
	if want := "Cargo.lock changed while ossprey checked it, so nothing was written; run the command again"; err == nil || err.Error() != want || out != "" {
		t.Errorf("Run = %v, output %q; want %q alone", err, out, want)
	}
	if !reflect.DeepEqual(projectState(t, root), before) {
		t.Error("the project changed beyond the edit")
	}
}

// A check that cannot be made, or that the platform made for no crate, refuses with the project unchanged, as a gating npm install does (OSS-2553).
func TestRunCargo_CheckErrorFailsClosed(t *testing.T) {
	unchecked := func() *ossbom.SBOM {
		s := cleanCrates()
		for _, c := range []string{"pkg:cargo/serde@1.0.228", "pkg:cargo/itoa@1.0.15"} {
			s.Findings = append(s.Findings, ossbom.Finding{Purl: c, Type: "UNSUPPORTED"})
		}
		return s
	}
	for _, tc := range []struct {
		name string
		scan func(context.Context, scanRequest) (*ossbom.SBOM, error)
		want string
	}{
		{"api down", func(context.Context, scanRequest) (*ossbom.SBOM, error) { return nil, errors.New("api down") },
			"Cargo.lock not checked (api down); the project was not changed"},
		{"checked none", func(context.Context, scanRequest) (*ossbom.SBOM, error) { return unchecked(), nil },
			"the platform checked none of the 2 packages in Cargo.lock (Rust is checked on Teams and Enterprise plans); the project was not changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, ws := cargoProject(t)
			writeFile(t, ws.Lock, "version = 4\n# before\n")
			before := projectState(t, root)
			swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock})
			swap(t, nil, cleanSBOM)
			noLanding(t)
			swapScan(t, tc.scan)
			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
			if err == nil || err.Error() != tc.want || errors.Is(err, ErrBlocked) || out != "" {
				t.Errorf("Run = %v, output %q; want %q alone", err, out, tc.want)
			}
			if !reflect.DeepEqual(projectState(t, root), before) {
				t.Error("the project changed")
			}
		})
	}
}

// A lock with no crates to check is still the clean result, so it lands, with a note under OSSPREY_VERBOSE (OSS-2553).
func TestRunCargo_NoComponentsLands(t *testing.T) {
	root, ws := cargoProject(t)
	swapCargo(t, &fakeCargo{t: t, root: root, lock: "version = 4\n"})
	swap(t, nil, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return ossbom.New(ossbom.Environment{}), nil })
	out, err := verboseOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"generate-lockfile"}})
	if err != nil || !strings.Contains(out, "ossprey: found no dependencies to check in Cargo.lock\n") {
		t.Errorf("Run = %v, output %q; want the note", err, out)
	}
	if got, err := os.ReadFile(ws.Lock); err != nil || string(got) != "version = 4\n" {
		t.Errorf("lock = %q (%v), want cargo's", got, err)
	}
}

// cargo colours a terminal under its own auto rules, which ossprey's pipe would hide, so ossprey asks for colour only where cargo would give it (verified with cargo 1.99.1).
func TestCargoColours(t *testing.T) {
	for _, tc := range []struct {
		tty  bool
		env  map[string]string
		want bool
	}{
		{true, map[string]string{"TERM": "xterm"}, true},
		{false, map[string]string{"TERM": "xterm"}, false},
		{true, map[string]string{"TERM": "xterm", "NO_COLOR": "1"}, false},
		{true, map[string]string{"TERM": "xterm", "NO_COLOR": ""}, true},
		{true, map[string]string{"TERM": "xterm", "CLICOLOR": "0"}, false},
		{true, map[string]string{"TERM": "dumb"}, runtime.GOOS == "windows"},
		{true, map[string]string{"TERM": "dumb", "CI": "1"}, true},
		{true, map[string]string{"TERM": "dumb", "CLICOLOR": "1"}, true},
		{true, map[string]string{}, runtime.GOOS == "windows"},
	} {
		for _, k := range []string{"TERM", "NO_COLOR", "CLICOLOR", "CI"} {
			unsetEnv(t, k)
		}
		for k, v := range tc.env {
			t.Setenv(k, v)
		}
		if got := cargoColours(tc.tty); got != tc.want {
			t.Errorf("tty %v, %v: %v, want %v", tc.tty, tc.env, got, tc.want)
		}
	}
}

// A cargo that writes the project's lock despite the redirect has it put back and the run fails, the lock unchecked (OSS-2553).
func TestRunCargo_TripwirePutsBackAndFails(t *testing.T) {
	for _, lockExisted := range []bool{false, true} {
		t.Run(fmt.Sprintf("lock %v", lockExisted), func(t *testing.T) {
			root, ws := cargoProject(t)
			if lockExisted {
				writeFile(t, ws.Lock, "version = 4\n# before\n")
			}
			before := projectState(t, root)
			swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock, ignore: true})
			swap(t, nil, cleanSBOM)
			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
			kept, _ := filepath.Glob(filepath.Join(root, "Cargo.lock.ossprey-found-*"))
			if len(kept) != 1 || readFile(t, kept[0]) != evilLock {
				t.Fatalf("kept %v, want one file holding what was found", kept)
			}
			// Another program may have written it, so what was found is kept beside it.
			if want := "Cargo.lock changed while `cargo update` ran, by a cargo ignoring the scratch copy ossprey gave it or by another program, so it was put back unchecked; what was found is kept in " + filepath.Base(kept[0]); err == nil || err.Error() != want || out != "" {
				t.Errorf("Run = %v, output %q; want %q", err, out, want)
			}
			before[kept[0]] = evilLock
			if !reflect.DeepEqual(projectState(t, root), before) {
				t.Error("the project was not put back")
			}
		})
	}
}

// cargo's own failure is its exit code, and nothing is checked or written.
func TestRunCargo_FailurePassesThrough(t *testing.T) {
	root, ws := cargoProject(t)
	writeFile(t, ws.Lock, "version = 4\n# before\n")
	before := projectState(t, root)
	exit101 := errors.New("exit status 101")
	swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock, err: exit101})
	swap(t, nil, cleanSBOM)
	noLanding(t)
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
	if !errors.Is(err, exit101) || out != "" {
		t.Errorf("Run = %v, output %q; want cargo's own error alone", err, out)
	}
	if got, want := cargoErrOut.(*bytes.Buffer).String(), "     Locking 1 package to "+ws.Lock+"\n"; got != want {
		t.Errorf("cargo's stderr = %q, want %q naming the project's lock", got, want)
	}
	if !reflect.DeepEqual(projectState(t, root), before) {
		t.Error("the project changed")
	}
}

// A cargo add that edits the manifest and locks nothing lands nothing, since the next build would resolve that manifest unchecked.
func TestRunCargoAdd_NoLockLandsNothing(t *testing.T) {
	needSymlinks(t)
	root, _ := cargoProject(t)
	before := projectState(t, root)
	cargoRunFn = func(_ context.Context, dir string, _, _ []string, _ io.Writer) error {
		writeFile(t, filepath.Join(dir, "a", "Cargo.toml"), memberManifest+addedEvil)
		return nil
	}
	swap(t, nil, cleanSBOM)
	noLanding(t)
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
	if want := "`cargo add -p a evil` left no Cargo.lock, so nothing was checked and the project was not changed"; err == nil || err.Error() != want || out != "" {
		t.Errorf("Run = %v, output %q; want %q", err, out, want)
	}
	if !reflect.DeepEqual(projectState(t, root), before) {
		t.Error("the project changed")
	}
}

// A generate-lockfile that locks nothing lands nothing and says nothing was checked.
func TestRunCargoGenerateLockfile_NoLockLandsNothing(t *testing.T) {
	root, _ := cargoProject(t)
	before := projectState(t, root)
	cargoRunFn = func(context.Context, string, []string, []string, io.Writer) error { return nil }
	swap(t, nil, cleanSBOM)
	noLanding(t)
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"generate-lockfile"}})
	if want := "`cargo generate-lockfile` left no Cargo.lock, so nothing was checked and the project was not changed"; err == nil || err.Error() != want || out != "" {
		t.Errorf("Run = %v, output %q; want %q", err, out, want)
	}
	if !reflect.DeepEqual(projectState(t, root), before) {
		t.Error("the project changed")
	}
}

// fetch locks with update --workspace, which downloads no crate, from the project's lock and with every fetch option but --target, then fetches the checked lock with --locked (OSS-2553).
func TestRunCargoFetch_ResolvesThenFetchesLocked(t *testing.T) {
	for _, tc := range []struct{ args, resolve, fetch string }{
		{"fetch", "update --workspace", "fetch --locked"},
		{"fetch --offline --target x86_64-unknown-linux-gnu", "update --workspace --offline", "fetch --offline --target x86_64-unknown-linux-gnu --locked"},
		{"-q fetch -m a/Cargo.toml --frozen", "-q update --workspace -m a/Cargo.toml --frozen", "-q fetch -m a/Cargo.toml --frozen"},
		{"--locked fetch --config k=v", "--locked update --workspace --config k=v", "--locked fetch --config k=v"},
		{"fetch -Zgc --locked", "update --workspace -Z gc --locked", "fetch -Zgc --locked"},
		{"fetch -qv --color never --target=x --manifest-path=a/Cargo.toml", "update --workspace -q -v --color never --manifest-path=a/Cargo.toml", "fetch -qv --color never --target=x --manifest-path=a/Cargo.toml --locked"},
		{"fetch --target -vv --quiet", "update --workspace -v -v --quiet", "fetch --target -vv --quiet --locked"},
	} {
		t.Run(tc.args, func(t *testing.T) {
			root, ws := cargoProject(t)
			writeFile(t, ws.Lock, "version = 4\n# before\n")
			var order []string
			f := &fakeCargo{t: t, root: root, lock: evilLock}
			swapCargo(t, f)
			ex := &stubExec{}
			swap(t, func(ctx context.Context, bin string, args []string) error {
				order = append(order, "fetch")
				if readFile(t, ws.Lock) != evilLock {
					t.Error("fetch ran before the checked lock landed")
				}
				return ex.fn(ctx, bin, args)
			}, cleanSBOM)
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
				order = append(order, "scan")
				return cleanCrates(), nil
			})
			if _, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: strings.Fields(tc.args)}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if len(f.runs) != 1 {
				t.Fatalf("cargo ran %d times before the fetch", len(f.runs))
			}
			at := redirectedLock(f.runs[0].env, f.runs[0].args)
			if want := strings.Fields(tc.resolve + " --config resolver.lockfile-path=" + tomlString(at)); !slices.Equal(f.runs[0].args, want) {
				t.Errorf("resolved with %q, want %q", f.runs[0].args, want)
			}
			// cargo resolves from nothing when the redirect names no lock, so the project's goes there first (verified).
			if f.runs[0].seen != "version = 4\n# before\n" {
				t.Errorf("the scratch lock held %q when cargo ran, want the project's", f.runs[0].seen)
			}
			if !slices.Equal(ex.args, strings.Fields(tc.fetch)) || !slices.Equal(order, []string{"scan", "fetch"}) {
				t.Errorf("fetched with %q after %v, want %q after the scan", ex.args, order, tc.fetch)
			}
		})
	}
}

// update --dry-run with no lock writes a whole one to the redirect (verified with cargo 1.99.1), so nothing is ever checked or written, and no credential is needed.
func TestRunCargoUpdate_DryRunNeverLands(t *testing.T) {
	for _, args := range []string{"update --dry-run", "update -qn", "update -p evil -p --dry-run"} {
		root, ws := cargoProject(t)
		unsetEnv(t, "OSSPREY_API_KEY")
		f := &fakeCargo{t: t, root: root, lock: evilLock}
		swapCargo(t, f)
		swap(t, nil, cleanSBOM)
		noLanding(t)
		if out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: strings.Fields(args)}); err != nil || out != "" || len(f.runs) != 1 {
			t.Errorf("%s: Run = %v, output %q, %d runs; want cargo run once and nothing else", args, err, out, len(f.runs))
		}
		if _, err := os.Stat(ws.Lock); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: wrote a lock (%v)", args, err)
		}
	}
}

// cargo add --dry-run writes nothing anywhere (verified with cargo 1.97.0 and 1.99.1), so it is handed to cargo as typed.
func TestRunCargoAdd_DryRunIsForwardedAsIs(t *testing.T) {
	for _, args := range [][]string{{"add", "--dry-run", "evil"}, {"+stable", "add", "-qn", "evil"}} {
		cargoProject(t)
		cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) {
			t.Error("a dry run reads no workspace")
			return cargoWorkspace{}, nil
		}
		ex := &stubExec{}
		swap(t, ex.fn, cleanSBOM)
		if out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args}); err != nil || out != "" || !slices.Equal(ex.args, args) {
			t.Errorf("Run = %v, output %q, handed %q; want %q as typed", err, out, ex.args, args)
		}
	}
}

// cargo's messages name the user's files, not the scratch lock or the mirror, even split across writes (OSS-2553).
func TestCargoStderrSpellsTheProjectPaths(t *testing.T) {
	var out strings.Builder
	w := newCargoStderr(&out, "/s/x/Cargo.lock", "/p/Cargo.lock", "/m", "")
	for _, chunk := range []string{"error: cannot update the lock file /s/x/Car", "go.lock because --locked was passed\n", "  Updating /m/p/a\r  Done /m/p/a/Cargo.toml", "\nlast /s/x/Cargo.lock"} {
		if n, err := w.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	w.Flush()
	if want := "error: cannot update the lock file /p/Cargo.lock because --locked was passed\n  Updating /p/a\r  Done /p/a/Cargo.toml\nlast /p/Cargo.lock"; out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

// The mirror has real directories down to the working directory, the -C directory, the root and each member as cargo spells them, copies of the lock and manifests, and links for everything else, each .cargo included, so cargo add writes nothing through a link (verified with cargo 1.97.0 and 1.99.1).
func TestBuildCargoMirror(t *testing.T) {
	needSymlinks(t)
	root, ws := cargoProject(t)
	for _, d := range []string{"src", filepath.Join("a", "src"), filepath.Join("a", "deep"), "target", "docs", ".cargo", filepath.Join("a", ".cargo"), "crates", filepath.Join("vendor-src", "b", "src")} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "README.md"), "hi\n")
	writeFile(t, filepath.Join(root, "vendor-src", "b", "Cargo.toml"), memberManifest)
	// cargo reaches a member through a linked directory as `members = ["crates/*"]` spells it (verified with cargo 1.99.1).
	if err := os.Symlink(filepath.Join("..", "vendor-src", "b"), filepath.Join(root, "crates", "b")); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "crates", "b", "Cargo.toml")
	ws.Manifests = append(ws.Manifests, linked)
	lock := cargoFile{path: ws.Lock, existed: true, data: []byte(evilLock), mode: 0o640}
	manifest := cargoFile{path: ws.Manifests[1], existed: true, data: []byte(memberManifest), mode: 0o600}
	member := cargoFile{path: linked, existed: true, data: []byte(memberManifest), mode: 0o644}
	cwd, run := filepath.Join(root, "a", "deep"), filepath.Join(root, "docs")
	mi, err := buildCargoMirror(ws, []cargoFile{lock, manifest, member}, cwd, run)
	if err != nil {
		t.Fatal(err)
	}
	defer mi.remove()
	for _, d := range []string{cwd, run, root, filepath.Join(root, "a"), filepath.Join(root, "crates", "b"), filepath.Dir(root), filepath.VolumeName(root) + string(filepath.Separator)} {
		if fi, err := os.Lstat(mirrorPath(mi.s, d)); err != nil || !fi.IsDir() {
			t.Errorf("%s is not a real directory in the mirror (%v)", d, err)
		}
	}
	for _, f := range []cargoFile{lock, manifest, member} {
		fi, err := os.Lstat(mi.at(f.path))
		if err != nil || !fi.Mode().IsRegular() || readFile(t, mi.at(f.path)) != string(f.data) {
			t.Errorf("%s is not a copy in the mirror (%v)", f.path, err)
		} else if runtime.GOOS != "windows" && fi.Mode().Perm() != f.mode {
			t.Errorf("%s copy mode %v, want %v", f.path, fi.Mode().Perm(), f.mode)
		}
	}
	for _, p := range []string{filepath.Join(root, "src"), filepath.Join(root, "a", "src"), filepath.Join(root, "target"), filepath.Join(root, "README.md"), filepath.Join(root, ".cargo"), filepath.Join(root, "a", ".cargo"), filepath.Join(root, "crates", "b", "src")} {
		if to, err := os.Readlink(mirrorPath(mi.s, p)); err != nil || to != p {
			t.Errorf("%s in the mirror links to %q (%v), want the project's", p, to, err)
		}
	}

	t.Chdir(cwd)
	dep := filepath.Join(filepath.Dir(root), "local")
	for _, tc := range []struct{ args, want string }{
		{"add evil", "add evil"},
		{"add --manifest-path " + ws.Manifests[1] + " evil", "add --manifest-path " + mi.at(ws.Manifests[1]) + " evil"},
		{"add --manifest-path=" + ws.Manifests[1] + " evil", "add --manifest-path " + mi.at(ws.Manifests[1]) + " evil"},
		{"add -qm ../a/Cargo.toml -p a evil", "add -q --manifest-path " + mi.at(ws.Manifests[1]) + " -p a evil"},
		{"add -p -m ../a/Cargo.toml evil", "add -p --manifest-path " + mi.at(ws.Manifests[1]) + " evil"},
		{"add -p-m evil", "add -p=-m evil"},
		{"add -m ../crates/b/Cargo.toml evil", "add --manifest-path " + mi.at(linked) + " evil"},
		{"-Zunstable-options -C docs add evil", "-Z unstable-options -C " + mirrorPath(mi.s, run) + " add evil"},
		{"add --path " + dep, "add --path " + mirrorPath(mi.s, dep)},
		{"add --path=" + dep, "add --path " + mirrorPath(mi.s, dep)},
		{"add --path ../local", "add --path ../local"},
		{"add evil -- --manifest-path x", "add evil -- --manifest-path x"},
	} {
		if got, err := mi.args(strings.Fields(tc.args)); err != nil || strings.Join(got, " ") != tc.want {
			t.Errorf("%q: %q (%v), want %q", tc.args, got, err, tc.want)
		}
	}
	for _, v := range []string{filepath.Join(t.TempDir(), "Cargo.toml"), filepath.Join("..", "vendor-src", "b", "Cargo.toml")} {
		if _, err := mi.args([]string{"add", "--manifest-path", v, "evil"}); err == nil {
			t.Errorf("--manifest-path %s names no manifest cargo metadata spelled, so it has no copy in the mirror", v)
		}
	}

	// A lock that appears after the snapshot is never linked, or cargo would write the project's through the link (OSS-2553).
	writeFile(t, ws.Lock, "version = 4\n")
	mi2, err := buildCargoMirror(ws, []cargoFile{{path: ws.Lock}}, root, root)
	if err != nil {
		t.Fatal(err)
	}
	defer mi2.remove()
	if _, err := os.Lstat(mi2.at(ws.Lock)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the mirror holds %s (%v), want nothing there", mi2.at(ws.Lock), err)
	}
	// Nor under another spelling of its directory, which Windows and macOS make the same mirror directory when only case or a short name differs (OSS-2553).
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	mi3, err := buildCargoMirror(ws, []cargoFile{{path: ws.Lock}}, alias, alias)
	if err != nil {
		t.Fatal(err)
	}
	defer mi3.remove()
	if _, err := os.Lstat(mi3.at(filepath.Join(alias, "Cargo.lock"))); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the mirror holds the lock under %s (%v), want nothing there", alias, err)
	}
}

// cargo must find the project's root and members in the mirror, all as their copies there, or cargo add could write a manifest it reaches through a link (OSS-2553).
func TestCargoMirrorSameWorkspace(t *testing.T) {
	root := filepath.Join(filepath.VolumeName(os.TempDir())+string(filepath.Separator), "p")
	mi := &cargoMirror{s: filepath.Join(t.TempDir(), "m"), real: map[string]bool{filepath.VolumeName(root) + string(filepath.Separator): true}}
	ws := cargoWorkspace{Lock: filepath.Join(root, "Cargo.lock"), Manifests: []string{filepath.Join(root, "Cargo.toml"), filepath.Join(root, "a", "Cargo.toml"), filepath.Join(root, "b", "Cargo.toml")}}
	at := func(ps ...string) []string {
		var out []string
		for _, p := range ps {
			out = append(out, mi.at(p))
		}
		return out
	}
	for _, tc := range []struct {
		name string
		got  cargoWorkspace
		want string
	}{
		{"the same, in another order", cargoWorkspace{Lock: mi.at(ws.Lock), Manifests: at(ws.Manifests[0], ws.Manifests[2], ws.Manifests[1])}, ""},
		{"another root", cargoWorkspace{Lock: mi.at(filepath.Join(filepath.Dir(root), "Cargo.lock")), Manifests: at(ws.Manifests...)}, "it would take " + filepath.Dir(root) + " as the workspace root, not " + root},
		{"a member more", cargoWorkspace{Lock: mi.at(ws.Lock), Manifests: at(append(ws.Manifests, filepath.Join(root, "c", "Cargo.toml"))...)}, "it would take " + filepath.Join(root, "c", "Cargo.toml") + " as a member too"},
		{"a member less", cargoWorkspace{Lock: mi.at(ws.Lock), Manifests: at(ws.Manifests[:2]...)}, "it would not take " + ws.Manifests[2] + " as a member"},
		{"a member outside the mirror", cargoWorkspace{Lock: mi.at(ws.Lock), Manifests: append(at(ws.Manifests[:2]...), ws.Manifests[2])}, "it would take " + ws.Manifests[2] + " as a member too"},
	} {
		err := mi.sameWorkspace(tc.got, ws)
		if (err == nil) != (tc.want == "") || err != nil && err.Error() != tc.want {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// After cargo add, the mirror must still stand for the project: a path dependency the add brought in that the project would take as a member, and the mirror cannot, left its dev-dependencies out of the checked lock, and a copy's path climbing out of the mirror names another directory in the project (OSS-2553).
func TestCargoMirrorAdded(t *testing.T) {
	top, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, out := filepath.Join(top, "p"), filepath.Join(top, "out")
	mi := &cargoMirror{s: filepath.Join(top, "m"), real: map[string]bool{filepath.VolumeName(root) + string(filepath.Separator): true}}
	ws := cargoWorkspace{Lock: filepath.Join(root, "Cargo.lock"), Manifests: []string{filepath.Join(root, "Cargo.toml"), filepath.Join(root, "a", "Cargo.toml")}}
	crate := func(dir, extra string) string {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "Cargo.toml"), "[package]\nname = \"x\"\nversion = \"0.1.0\"\n"+extra)
		return dir
	}
	under, outside := crate(filepath.Join(root, "foo"), ""), crate(filepath.Join(out, "x"), "")
	absolute := crate(mi.at(filepath.Join(out, "y")), "workspace = '"+root+"'\n")
	relative := crate(mi.at(filepath.Join(out, "z")), "workspace = \"../../p\"\n")
	before := cargoWorkspace{Lock: mi.at(ws.Lock), Manifests: []string{mi.at(ws.Manifests[0]), mi.at(ws.Manifests[1])}}
	withDeps := func(deps ...string) cargoWorkspace {
		w := before
		w.Deps = deps
		return w
	}
	vol, _ := filepath.Rel(filepath.VolumeName(root)+string(filepath.Separator), filepath.Join(root, "a"))
	climb := strings.Repeat("../", len(strings.Split(vol, string(filepath.Separator)))+1) + "x"
	manifest := func(dep string) []cargoFile {
		return []cargoFile{{path: ws.Lock, existed: true, data: []byte("version = 4\n")}, {path: ws.Manifests[0], existed: true, data: []byte("[workspace]\nmembers = [\"a\"]\n")}, {path: ws.Manifests[1], existed: true, data: []byte("[package]\nname = \"a\"\n\n[dependencies]\nx = { path = '" + dep + "' }\n")}}
	}
	plain := manifest("../foo")
	for _, tc := range []struct {
		name          string
		before, after cargoWorkspace
		files         []cargoFile
		want          string
	}{
		{"a new path dependency under the root, outside the mirror", before, withDeps(under), plain, "would not take " + under + " as a member"},
		{"a new path dependency outside the project", before, withDeps(outside), plain, ""},
		{"an old one under the root", withDeps(under), withDeps(under), plain, ""},
		{"a new one naming its workspace by an absolute path", before, withDeps(absolute), plain, "would not take " + absolute + " as a member"},
		{"a new one naming its workspace relatively", before, withDeps(relative), plain, ""},
		{"a new member", before, cargoWorkspace{Lock: before.Lock, Manifests: append(slices.Clone(before.Manifests), mi.at(filepath.Join(root, "v", "Cargo.toml"))), Deps: []string{mi.at(filepath.Join(root, "v"))}}, plain, ""},
		{"a copy's path climbing out of the mirror", before, before, manifest(climb), "would hold the path \"" + climb + "\""},
		{"a copy's absolute path", before, before, manifest(outside), ""},
		{"another root", before, cargoWorkspace{Lock: mi.at(filepath.Join(top, "Cargo.lock"))}, plain, "rooted at " + mi.at(top)},
	} {
		err := mi.added(tc.before, tc.after, ws, tc.files)
		if (err == nil) != (tc.want == "") || err != nil && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	// cargo takes a dependency spelled under the root as a member though a link leads it elsewhere, since it compares spellings.
	t.Run("a new path dependency spelled under the root through a link", func(t *testing.T) {
		needSymlinks(t)
		if err := os.Symlink(out, filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(root, "link", "x")
		if err := mi.added(before, withDeps(linked), ws, plain); err == nil || !strings.Contains(err.Error(), "would not take "+linked+" as a member") {
			t.Errorf("%v, want %s refused", err, linked)
		}
	})
}

// cargo follows no path in package.metadata or workspace.metadata, so one there climbing out of the mirror refuses nothing, while a dependency's still refuses, one named metadata too (OSS-2553).
func TestCargoMirrorLeavesSkipsMetadata(t *testing.T) {
	vol := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	mi := &cargoMirror{s: filepath.Join(t.TempDir(), "m"), real: map[string]bool{vol: true}}
	manifest := filepath.Join(vol, "p", "a", "Cargo.toml")
	climb := "../../../assets"
	for _, tc := range []struct{ name, data, want string }{
		{"package.metadata", "[package]\nname = \"a\"\n\n[package.metadata.docs]\npath = \"" + climb + "\"\n", ""},
		{"workspace.metadata", "[workspace]\n\n[workspace.metadata]\nassets = { path = \"" + climb + "\" }\n", ""},
		{"project.metadata", "[project]\nname = \"a\"\nmetadata = { path = \"" + climb + "\" }\n", ""},
		{"a dependency", "[package]\nname = \"a\"\n\n[dependencies]\nx = { path = \"" + climb + "\" }\n", climb},
		{"a dependency named metadata", "[package]\nname = \"a\"\n\n[dependencies]\nmetadata = { path = \"" + climb + "\" }\n", climb},
		{"a workspace dependency named metadata", "[workspace.dependencies]\nmetadata = { path = \"" + climb + "\" }\n", climb},
	} {
		got, err := mi.leaves(cargoFile{path: manifest, existed: true, data: []byte(tc.data)})
		if err != nil || got != tc.want {
			t.Errorf("%s: %q (%v), want %q", tc.name, got, err, tc.want)
		}
	}
}

// Rust reads a drive letter in either case as one drive and any other volume as spelled (OSS-2553).
func TestSameVolume(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"C:", "c:", true},
		{"C:", "D:", false},
		{`\\srv\share`, `\\srv\share`, true},
		{`\\srv\share`, `\\SRV\share`, false},
		{`\\?\C:`, "C:", false},
		{"", "", true},
	} {
		if got := sameVolume(tc.a, tc.b); got != tc.want {
			t.Errorf("sameVolume(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// cargo names what it means on the lines after an error ending in a colon, such as the workspace a member believes it is in (OSS-2553).
func TestFirstErrorLineKeepsWhatAColonIntroduces(t *testing.T) {
	stderr := "error: current package believes it's in a workspace when it's not:\ncurrent:   /p/Cargo.toml\nworkspace: /c2/Cargo.toml\n\nthis may be fixable by adding\n"
	if got, want := firstErrorLine(stderr, nil), "error: current package believes it's in a workspace when it's not: current:   /p/Cargo.toml workspace: /c2/Cargo.toml"; got != want {
		t.Errorf("firstErrorLine = %q, want %q", got, want)
	}
	if got, want := firstErrorLine("error: no such command\n\nhelp: x\n", nil), "error: no such command"; got != want {
		t.Errorf("firstErrorLine = %q, want %q", got, want)
	}
}

// Each Windows volume gets a directory in the mirror no other volume gets, in any case, and one a Windows directory name can hold (OSS-2553).
func TestMirrorVolumeNamesEachVolumeApart(t *testing.T) {
	seen := map[string]string{}
	for _, vol := range []string{"", `C:`, `c:`, `D:`, `\\server\share_name`, `\\server_share\name`, `\\?\C:`, `\\?\UNC\server\share`} {
		got := mirrorVolume(vol)
		if isDrive(vol) && got != vol[:1] || !isDrive(vol) && vol != "" && (len(got) < 2 || strings.ContainsAny(got, `\/:*?"<>|`)) {
			t.Errorf("%q: %q, want its letter for a drive, else a name of two or more legal characters", vol, got)
		}
		if other, ok := seen[strings.ToLower(got)]; ok && !strings.EqualFold(vol, other) {
			t.Errorf("%q and %q share the mirror directory %q", vol, other, got)
		}
		seen[strings.ToLower(got)] = vol
	}
}

// A cargo config above the mirror that cargo would not read for the project would apply to cargo add there (verified), so the mirror is refused, unless it is CARGO_HOME's.
func TestBuildCargoMirrorRefusesAConfigAboveIt(t *testing.T) {
	needSymlinks(t)
	_, ws := cargoProject(t)
	cache := os.Getenv("XDG_CACHE_HOME")
	if err := os.Mkdir(filepath.Join(cache, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(cache, ".cargo", "config.toml"), "[patch.crates-io]\nitoa = { path = \"x\" }\n")
	t.Setenv("CARGO_HOME", t.TempDir())
	_, err := buildCargoMirror(ws, nil, ws.ConfigDir, ws.ConfigDir)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(canonicalDir(cache), ".cargo", "config.toml")) {
		t.Errorf("err = %v, want the config named", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(cache, "ossprey")); len(entries) != 0 {
		t.Errorf("the refused mirror is still there: %v", entries)
	}
	// cargo reads CARGO_HOME's config once by its canonical path, so ~/.cargo above the cache is no extra config (verified).
	t.Setenv("CARGO_HOME", filepath.Join(cache, ".cargo"))
	mi, err := buildCargoMirror(ws, nil, ws.ConfigDir, ws.ConfigDir)
	if err != nil {
		t.Fatalf("CARGO_HOME above the mirror: %v", err)
	}
	mi.remove()
}

// Passive puts nothing in front of cargo: it runs, then the lock is posted without polling.
func TestRunCargoAdd_Passive(t *testing.T) {
	root, ws := cargoProject(t)
	var order []string
	inner := cargoWorkspaceFn
	cargoWorkspaceFn = func(ctx context.Context, args []string) (cargoWorkspace, error) {
		order = append(order, "workspace")
		return inner(ctx, args)
	}
	cargoVersionFn = func(context.Context, string, []string) (string, error) {
		t.Error("passive asks no version")
		return "", nil
	}
	swap(t, func(ctx context.Context, bin string, args []string) error {
		order = append(order, "cargo")
		writeFile(t, filepath.Join(root, "a", "Cargo.toml"), memberManifest+addedEvil)
		writeFile(t, ws.Lock, evilLock)
		return nil
	}, cleanSBOM)
	var req scanRequest
	var scanned string
	scan := lockScan(t, &req, &scanned, evilSBOM)
	swapScan(t, func(ctx context.Context, r scanRequest) (*ossbom.SBOM, error) {
		order = append(order, "scan")
		return scan(ctx, r)
	})

	if err := Run(context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}, Passive: true}); err != nil {
		t.Fatalf("Run = %v, want nil: passive never blocks", err)
	}
	if want := []string{"cargo", "workspace", "scan"}; !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	if !req.SubmitOnly || !req.Installed || scanned != evilLock {
		t.Errorf("scan request %+v of %q, want the new lock posted without polling", req, scanned)
	}
	if got := readFile(t, filepath.Join(root, "a", "Cargo.toml")); got == memberManifest {
		t.Error("passive restores nothing")
	}
}

// Passive posts the lock a failed command left, and still returns cargo's error.
func TestRunCargoFetch_PassiveFailurePostsTheLock(t *testing.T) {
	_, ws := cargoProject(t)
	exit101 := errors.New("exit status 101")
	swap(t, func(context.Context, string, []string) error {
		writeFile(t, ws.Lock, evilLock)
		return exit101
	}, cleanSBOM)
	var req scanRequest
	var scanned string
	swapScan(t, lockScan(t, &req, &scanned, evilSBOM))
	if err := Run(context.Background(), Options{Bin: "cargo", Args: []string{"fetch"}, Passive: true}); !errors.Is(err, exit101) {
		t.Fatalf("Run = %v, want cargo's own error", err)
	}
	if !req.SubmitOnly || scanned != evilLock {
		t.Errorf("scan request %+v of %q, want the lock posted", req, scanned)
	}
}

// Passive warns about a lock it cannot post, a moved or script one even after a failure, while a failure for want of a workspace leaves cargo's error alone.
func TestRunCargo_PassiveWorkspaceErrors(t *testing.T) {
	exit101 := errors.New("exit status 101")
	noWorkspace := errors.New("cargo metadata: error: could not find `Cargo.toml` in `/empty` or any parent directory")
	for _, tc := range []struct {
		wsErr, runErr error
		want          string
	}{
		{errLockfileMoved, exit101, "ossprey: warning: could not post scan (a resolver.lockfile-path may move it); the install was not blocked (passive)\n"},
		{errScriptLock, exit101, "ossprey: warning: could not post scan (a cargo script keeps it in the build directory); the install was not blocked (passive)\n"},
		{noWorkspace, exit101, ""},
		{noWorkspace, nil, "ossprey: warning: could not post scan (" + noWorkspace.Error() + "); the install was not blocked (passive)\n"},
	} {
		cargoProject(t)
		cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return cargoWorkspace{}, tc.wsErr }
		swap(t, func(context.Context, string, []string) error { return tc.runErr }, cleanSBOM)
		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"fetch", "--offline"}, Passive: true})
		if !errors.Is(err, tc.runErr) || out != tc.want {
			t.Errorf("%v, cargo %v: Run = %v, output %q; want %q", tc.wsErr, tc.runErr, err, out, tc.want)
		}
	}
}

// cargo add --dry-run with no lock writes nothing, so passive posts nothing and says so only when verbose.
func TestRunCargoAdd_PassiveDryRunWithNoLockSaysNothing(t *testing.T) {
	cargoProject(t)
	args := []string{"add", "--dry-run", "serde"}
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args, Passive: true})
	if err != nil || !ex.called || out != "" {
		t.Errorf("Run = %v, cargo ran = %v, output %q; want cargo run and nothing printed", err, ex.called, out)
	}
	out, _ = verboseOutput(t, context.Background(), Options{Bin: "cargo", Args: args, Passive: true})
	if !strings.Contains(out, "ossprey: `cargo add --dry-run serde` left no Cargo.lock; nothing posted") {
		t.Errorf("verbose output lacks the reason:\n%s", out)
	}
}

// The credential is resolved from the forwarder's own API settings, before cargo, and a run that checks nothing never asks for one.
func TestRunCargoAdd_AsksForACredentialOnlyToCheck(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		args                   []string
		passive, skip, unknown bool
		want                   []string
	}{
		{"gating", []string{"update"}, false, false, false, []string{"credential for https://api.test with k"}},
		{"passive", []string{"update"}, true, false, false, []string{"cargo"}},
		{"skip-ci", []string{"update"}, false, true, false, []string{"cargo"}},
		{"unreadable workspace", []string{"update"}, false, false, true, nil},
		{"dry run", []string{"update", "--dry-run"}, false, false, false, []string{"cargo"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := cargoProject(t)
			if tc.unknown {
				cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return cargoWorkspace{}, errLockfileMoved }
			}
			var order []string
			old := cargoCredentialFn
			cargoCredentialFn = func(_ context.Context, apiURL, apiKey string) error {
				order = append(order, "credential for "+apiURL+" with "+apiKey)
				return errors.New("no credentials")
			}
			t.Cleanup(func() { cargoCredentialFn = old })
			f := &fakeCargo{t: t, root: root, lock: evilLock}
			cargoRunFn = func(ctx context.Context, dir string, env, args []string, stderr io.Writer) error {
				order = append(order, "cargo")
				return f.run(ctx, dir, env, args, stderr)
			}
			swap(t, func(context.Context, string, []string) error {
				order = append(order, "cargo")
				return nil
			}, cleanSBOM)
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return cleanCrates(), nil })

			opts := Options{Bin: "cargo", Args: tc.args, APIURL: "https://api.test", APIKey: "k", Passive: tc.passive, SkipCI: tc.skip}
			_, err := quietOutput(t, context.Background(), opts)
			if refused := !tc.passive && !tc.skip && tc.name != "dry run"; (err != nil) != refused {
				t.Errorf("Run = %v, want an error only when the run is refused", err)
			}
			if !reflect.DeepEqual(order, tc.want) {
				t.Errorf("order = %v, want %v", order, tc.want)
			}
		})
	}
}

func TestRunCargoInstall_BlockedBeforeCargoRuns(t *testing.T) {
	ex := &stubExec{}
	var got []check.Spec
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o.Specs
		return malwareSBOM(ctx, o)
	})
	latest := func(context.Context, string, string) (string, error) { return "2.0.0", nil }
	err := Run(context.Background(), Options{Bin: "cargo", Args: []string{"install", "evil", "--vers", "1.0.0", "other"}, ResolveLatest: latest})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Run = %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("a blocked cargo install must not run cargo")
	}
	want := []check.Spec{{Ecosystem: "cargo", Name: "evil", Version: "1.0.0"}, {Ecosystem: "cargo", Name: "other", Version: "1.0.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("checked %+v, want %+v", got, want)
	}
}

// Only the named crates are checked, and the line says the dependencies were not.
func TestRunCargoInstall_SaysDependenciesWereNotChecked(t *testing.T) {
	ex := &stubExec{}
	_, chk := checkedSpecs(t)
	swap(t, ex.fn, chk)
	swapExpand(t, expandInstall)
	latest := func(context.Context, string, string) (string, error) { return "14.1.1", nil }
	args := []string{"+stable", "install", "--locked", "ripgrep"}
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args, ResolveLatest: latest})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, line := range []string{
		"ossprey: warning: could not resolve the dependencies of ripgrep (not supported for cargo install); checking the named packages only\n",
		"ossprey: no malware found in 1 package (1 requested; dependencies not resolved), forwarding to cargo\n",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	}
	if !ex.called || !reflect.DeepEqual(ex.args, args) {
		t.Errorf("handoff = %v (called %v), want %v untouched", ex.args, ex.called, args)
	}
}

// A crate from git, a path or another registry is not on crates.io, so it forwards unchecked and says why only when verbose.
func TestRunCargoInstall_FromElsewhereForwardsUnchecked(t *testing.T) {
	for _, args := range [][]string{
		{"install", "--git", "https://github.com/BurntSushi/ripgrep", "ripgrep"},
		{"install", "--path", "."},
		{"install", "--registry", "corp", "tool"},
		{"install", "--index", "sparse+https://crates.corp.example/", "tool"},
		{"install", "--index", "https://例子.test/rust-lang/crates.io-index", "tool"},
		{"install"},
	} {
		ex := &stubExec{}
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			t.Errorf("cargo %v: nothing from crates.io was named, so nothing is checked", args)
			return nil, nil
		})
		out, err := verboseOutput(t, context.Background(), Options{Bin: "cargo", Args: args})
		if err != nil || !ex.called {
			t.Fatalf("cargo %v: Run = %v, forwarded = %v", args, err, ex.called)
		}
		if !strings.Contains(out, "no crates.io crate named") {
			t.Errorf("cargo %v: verbose output lacks the reason:\n%s", args, out)
		}
		if out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args}); err != nil || out != "" {
			t.Errorf("cargo %v: quiet Run = %v, output %q; want nothing printed", args, err, out)
		}
	}
}

// crates.io named by --registry or --index, or by no flag at all, is checked; a default registry elsewhere is not.
func TestRunCargoInstall_RegistryDecidesTheCheck(t *testing.T) {
	corp := "[registries.corp]\nindex = \"sparse+https://crates.corp.example/\"\n"
	for _, tc := range []struct {
		name, config, env string
		args              []string
		checked           bool
	}{
		{"crates.io by name", "", "", []string{"install", "--registry", "crates-io", "itoa"}, true},
		{"crates.io by name, joined", "", "", []string{"install", "--registry=crates-io", "itoa"}, true},
		{"crates.io's sparse index", "", "", []string{"install", "--index", "sparse+https://index.crates.io/", "itoa"}, true},
		{"crates.io's git index", "", "", []string{"install", "--index=https://github.com/rust-lang/crates.io-index", "itoa"}, true},
		{"corp by default in CARGO_HOME", corp + "[registry]\ndefault = \"corp\"\n", "", []string{"install", "itoa"}, false},
		{"corp by default, crates.io by name", corp + "[registry]\ndefault = \"corp\"\n", "", []string{"install", "--registry", "crates-io", "itoa"}, true},
		{"corp by CARGO_REGISTRY_DEFAULT", corp, "corp", []string{"install", "itoa"}, false},
		{"corp by --config", corp, "", []string{"--config", `registry.default="corp"`, "install", "itoa"}, false},
		{"crates-io by default", "[registry]\ndefault = \"crates-io\"\n", "", []string{"install", "itoa"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("CARGO_HOME", home)
			writeFile(t, filepath.Join(home, "config.toml"), tc.config)
			t.Setenv("CARGO_REGISTRY_DEFAULT", tc.env)
			if tc.env == "" {
				unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
			}
			ex := &stubExec{}
			checked := false
			swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
				checked = true
				return cleanSBOM(ctx, o)
			})
			latest := func(context.Context, string, string) (string, error) { return "1.0.19", nil }
			if err := Run(context.Background(), Options{Bin: "cargo", Args: tc.args, ResolveLatest: latest}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if checked != tc.checked || !ex.called {
				t.Errorf("checked = %v, forwarded = %v; want checked %v and forwarded", checked, ex.called, tc.checked)
			}
		})
	}
}

func TestRunCargoInstall_Passive(t *testing.T) {
	ex := &stubExec{}
	var submitted check.Options
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		submitted = o
		return malwareSBOM(ctx, o)
	})
	latest := func(context.Context, string, string) (string, error) { return "14.1.1", nil }
	if err := Run(context.Background(), Options{Bin: "cargo", Args: []string{"install", "ripgrep"}, Passive: true, ResolveLatest: latest}); err != nil {
		t.Fatalf("Run = %v, want nil: passive never blocks", err)
	}
	if !ex.called {
		t.Error("passive must run cargo install")
	}
	if !submitted.SubmitOnly || len(submitted.Specs) != 1 || submitted.Specs[0].Name != "ripgrep" {
		t.Errorf("submitted %+v, want ripgrep posted without polling", submitted)
	}
}

// Every other cargo command reaches cargo untouched, with no lookup at all.
func TestRunCargoPassesEverythingElseThrough(t *testing.T) {
	old := cargoWorkspaceFn
	cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) {
		t.Error("a pass-through must not look up the workspace")
		return cargoWorkspace{}, nil
	}
	t.Cleanup(func() { cargoWorkspaceFn = old })
	for _, args := range [][]string{{"build"}, {"+nightly", "test"}, {"run", "--", "add"}, {"install", "--list"}, {"add", "--help"}, {"remove", "serde"}} {
		ex := &stubExec{}
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			t.Errorf("cargo %v must not be checked", args)
			return nil, nil
		})
		if err := Run(context.Background(), Options{Bin: "cargo", Args: args}); err != nil {
			t.Fatalf("cargo %v: %v", args, err)
		}
		if !ex.called || !reflect.DeepEqual(ex.args, args) {
			t.Errorf("cargo %v: forwarded %v (called %v)", args, ex.args, ex.called)
		}
	}
}

func TestCargoWorkspaceFlags(t *testing.T) {
	for _, tc := range []struct{ rest, want string }{
		{"-p a serde", ""},
		{"--manifest-path a/Cargo.toml serde", "--manifest-path a/Cargo.toml"},
		{"--manifest-path=a/Cargo.toml serde", "--manifest-path a/Cargo.toml"},
		{"-m a/Cargo.toml serde", "--manifest-path a/Cargo.toml"},
		{"-ma/Cargo.toml serde", "--manifest-path a/Cargo.toml"},
		{"--config k=v -Zunstable-options serde", "--config k=v -Z unstable-options"},
		{"-qm other/Cargo.toml serde", "--manifest-path other/Cargo.toml"},
		{"-qmother/Cargo.toml serde", "--manifest-path other/Cargo.toml"},
		{"-vm=other/Cargo.toml serde", "--manifest-path other/Cargo.toml"},
		{"-qZ unstable-options serde", "-Z unstable-options"},
		{"-pm serde", ""},
		{"-Fm serde", ""},
		{"serde -- -m x", ""},
	} {
		if got := strings.Join(cargoWorkspaceFlags(strings.Fields(tc.rest)), " "); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.rest, got, tc.want)
		}
	}
}

// -C may be grouped with switches or carry its value attached, as clap reads it.
func TestCargoConfigDirReadsGroupedShorts(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	want, err := filepath.EvalSymlinks(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	for _, globals := range []string{"-C sub", "-qC sub", "-qCsub", "-vC=sub", "-Z unstable-options -qC sub", "-qZ unstable-options -C sub"} {
		if got := cargoConfigDir(strings.Fields(globals)); got != want {
			t.Errorf("cargo %s: %s, want %s", globals, got, want)
		}
	}
}

func TestLockfileMoved(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	t.Setenv("CARGO_HOME", home)
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	sub := filepath.Join(project, "sub")
	if err := os.MkdirAll(filepath.Join(project, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if lockfileMoved([]string{"add", "serde"}, sub) {
		t.Fatal("nothing sets resolver.lockfile-path yet")
	}
	if !lockfileMoved([]string{"--config", `resolver.lockfile-path="x/Cargo.lock"`, "add", "serde"}, sub) {
		t.Error("missed --config on the command line")
	}
	file := filepath.Join(project, "extra.toml")
	writeFile(t, file, "[resolver]\nlockfile-path = \"x/Cargo.lock\"\n")
	if !lockfileMoved([]string{"add", "--config=" + file, "serde"}, sub) {
		t.Error("missed a --config file")
	}
	writeFile(t, filepath.Join(project, ".cargo", "config.toml"), "[resolver]\nlockfile-path = \"x/Cargo.lock\"\n")
	if !lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("missed an ancestor's .cargo/config.toml")
	}
	if err := os.Remove(filepath.Join(project, ".cargo", "config.toml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, "config.toml"), "resolver.lockfile-path = \"x/Cargo.lock\"\n")
	if !lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("missed CARGO_HOME's config.toml")
	}
	if err := os.Remove(filepath.Join(home, "config.toml")); err != nil {
		t.Fatal(err)
	}
	// cargo merges an included file, which may set lockfile-path, so any include counts.
	include := "include = [\"lock.toml\"]\n"
	writeFile(t, filepath.Join(project, ".cargo", "config.toml"), include)
	if !lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("missed an include in an ancestor's .cargo/config.toml")
	}
	if err := os.Remove(filepath.Join(project, ".cargo", "config.toml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(home, "config.toml"), include)
	if !lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("missed an include in CARGO_HOME's config.toml")
	}
	if err := os.Remove(filepath.Join(home, "config.toml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, include)
	if !lockfileMoved([]string{"--config", file, "add", "serde"}, sub) {
		t.Error("missed an include in a --config file")
	}
	if !lockfileMoved([]string{"--config", `include=["lock.toml"]`, "add", "serde"}, sub) {
		t.Error("missed an include on the command line")
	}
	writeFile(t, filepath.Join(project, ".cargo", "config.toml"), "[build]\njobs = 4\n# include nothing\n")
	if lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("a config with no include or lockfile-path moves nothing")
	}
	// TOML decodes escapes in a quoted key, and cargo 1.99.1 moved the lock for each of these.
	for _, escaped := range []string{
		"[resolver]\n\"lockfile\\u002dpath\" = \"x/Cargo.lock\"\n",
		"[\"resolv\\u0065r\"]\n\"lockfile\\u002dpath\" = \"x/Cargo.lock\"\n",
		"resolver.\"lockfile\\u002dpath\" = \"x/Cargo.lock\"\n",
	} {
		writeFile(t, filepath.Join(project, ".cargo", "config.toml"), escaped)
		if !lockfileMoved([]string{"add", "serde"}, sub) {
			t.Errorf("missed an escaped key: %q", escaped)
		}
	}
	if !lockfileMoved([]string{"--config", `resolver."lockfile\u002dpath"="x/Cargo.lock"`, "add", "serde"}, sub) {
		t.Error("missed an escaped key on the command line")
	}
	// cargo 1.99.1 reads only the legacy config when both are at one level.
	writeFile(t, filepath.Join(project, ".cargo", "config.toml"), "[resolver]\nlockfile-path = \"x/Cargo.lock\"\n")
	writeFile(t, filepath.Join(project, ".cargo", "config"), "[build]\njobs = 4\n")
	if lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("a config.toml beside config is not read, so it moves nothing")
	}
	writeFile(t, filepath.Join(project, ".cargo", "config"), "[resolver]\nlockfile-path = \"x/Cargo.lock\"\n")
	writeFile(t, filepath.Join(project, ".cargo", "config.toml"), "[build]\njobs = 4\n")
	if !lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("missed the legacy config beside config.toml")
	}
	if err := os.Remove(filepath.Join(project, ".cargo", "config")); err != nil {
		t.Fatal(err)
	}
	// A config the bounded parser refuses may set it.
	for name, refused := range map[string]string{
		"too deep":  "x = " + strings.Repeat("[", 17) + strings.Repeat("]", 17) + "\n",
		"too long":  "x = \"" + strings.Repeat("a", 5000) + "\"\n",
		"too large": "# " + strings.Repeat("x", catalog.CargoManifestLimit) + "\n",
	} {
		writeFile(t, filepath.Join(project, ".cargo", "config.toml"), refused)
		if !lockfileMoved([]string{"add", "serde"}, sub) {
			t.Errorf("a config %s to read may move it", name)
		}
		writeFile(t, file, refused)
		if !lockfileMoved([]string{"add", "--config", file, "serde"}, sub) {
			t.Errorf("a --config file %s to read may move it", name)
		}
	}
	writeFile(t, filepath.Join(project, ".cargo", "config.toml"), "[build]\njobs = 4\n")
	if lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("a readable config with no lockfile-path moves nothing")
	}
	t.Setenv("CARGO_RESOLVER_LOCKFILE_PATH", "x/Cargo.lock")
	if !lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("missed CARGO_RESOLVER_LOCKFILE_PATH")
	}
}

// cargo 1.99.1 reads a --config or level config that is a directory as an error, so it counts as one that may move the lock, while cargo install fails on it with the crate still checked (OSS-2553).
func TestCargoConfigThatIsADirectoryMayMoveTheLock(t *testing.T) {
	assertIrregularConfig(t, func(p string) error { return os.Mkdir(p, 0o755) })
}

// assertIrregularConfig makes each config cargo reads with mk, which is not a regular file, and wants it to count as one that may move the lock but not to set registry.default.
func assertIrregularConfig(t *testing.T, mk func(string) error) {
	t.Helper()
	base := t.TempDir()
	home, project := filepath.Join(base, "home"), filepath.Join(base, "project")
	for _, d := range []string{home, filepath.Join(project, ".cargo")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CARGO_HOME", home)
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
	t.Chdir(project)
	if lockfileMoved([]string{"generate-lockfile"}, project) || cargoDefaultRegistry([]string{"install", "x"}) != "" {
		t.Fatal("nothing sets either key yet")
	}
	arg := filepath.Join(base, "arg.toml")
	if err := mk(arg); err != nil {
		t.Fatal(err)
	}
	if !lockfileMoved([]string{"--config", arg, "generate-lockfile"}, project) {
		t.Error("a --config file that is not a regular file may move the lock")
	}
	if got := cargoDefaultRegistry([]string{"install", "--config", arg, "x"}); got != "" {
		t.Errorf("a --config file that is not a regular file: %q, want the crates.io crate checked", got)
	}
	if got := cargoDefaultRegistry([]string{"--config", `registry.default="corp"`, "install", "--config", arg, "x"}); got != "corp" {
		t.Errorf("a --config file that is not a regular file after one that sets corp: %q, want corp", got)
	}
	if err := mk(filepath.Join(project, ".cargo", "config.toml")); err != nil {
		t.Fatal(err)
	}
	if !lockfileMoved([]string{"generate-lockfile"}, project) {
		t.Error("a level config that is not a regular file may move the lock")
	}
	if err := mk(filepath.Join(home, "config.toml")); err != nil {
		t.Fatal(err)
	}
	if got := cargoDefaultRegistry([]string{"install", "x"}); got != "" {
		t.Errorf("CARGO_HOME's config that is not a regular file: %q, want the crates.io crate checked", got)
	}
}

// Only the setting moves the lock: cargo 1.99.1 reads none of these as one, so naming the words must not skip the check (OSS-2553).
func TestLockfileMovedReadsOnlyTheSetting(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	t.Setenv("CARGO_HOME", home)
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	t.Chdir(project)
	if err := os.Mkdir(filepath.Join(project, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(project, "lockfile-path.toml"), "[net]\nretry = 2\n")
	set := `resolver.lockfile-path="alt/Cargo.lock"`
	for _, args := range [][]string{
		{"add", "lockfile-path-helper"},
		{"add", "-p", "lockfile-path", "itoa"},
		{"generate-lockfile", "--manifest-path", "lockfile-path/Cargo.toml"},
		{"generate-lockfile", "--manifest-path=lockfile-path/Cargo.toml"},
		{"generate-lockfile", "--config", "lockfile-path.toml"},
		{"generate-lockfile", "--config", `alias.lp="lockfile-path"`},
		{"generate-lockfile", "--config", "resolver.lockfile_path=\"alt/Cargo.lock\""},
		{"-Zlockfile-path", "generate-lockfile"},
		{"update", "--", "--config", set},
		{"add", "--", "--config=" + set},
	} {
		if lockfileMoved(args, project) {
			t.Errorf("cargo %v moves no lock", args)
		}
	}
	for _, config := range []string{
		"# lockfile-path = \"alt/Cargo.lock\"\n[resolver]\n# lockfile-path = \"alt/Cargo.lock\"\n",
		"[alias]\nlp = \"lockfile-path\"\n\n[env]\nX = \"resolver.lockfile-path = alt\"\n",
	} {
		writeFile(t, filepath.Join(project, ".cargo", "config.toml"), config)
		if lockfileMoved([]string{"generate-lockfile"}, project) {
			t.Errorf("config %q moves no lock", config)
		}
		writeFile(t, filepath.Join(home, "config.toml"), config)
		if lockfileMoved([]string{"generate-lockfile", "--config", filepath.Join(home, "config.toml")}, project) {
			t.Errorf("--config file %q moves no lock", config)
		}
	}
	// Each spelling cargo 1.99.1 moved the lock for, before the verb and after it.
	for _, args := range [][]string{
		{"--config", set, "generate-lockfile"},
		{"generate-lockfile", "--config", set},
		{"generate-lockfile", "--config=" + set},
		{"add", "itoa", "--config", `resolver."lockfile-path"="alt/Cargo.lock"`},
		{"-q", "--config", set, "update", "-p", "itoa"},
	} {
		if !lockfileMoved(args, project) {
			t.Errorf("missed cargo %v", args)
		}
	}
	for _, config := range []string{
		"[resolver]\nlockfile-path = \"alt/Cargo.lock\"\n",
		"resolver = { lockfile-path = \"alt/Cargo.lock\" }\n",
		"resolver.lockfile-path = \"alt/Cargo.lock\"\n",
	} {
		writeFile(t, filepath.Join(project, ".cargo", "config.toml"), config)
		if !lockfileMoved([]string{"generate-lockfile"}, project) {
			t.Errorf("missed config %q", config)
		}
	}
}

// A relative CARGO_HOME is joined to where cargo runs, -C's directory included, as cargo 1.99.1 joins it.
func TestLockfileMovedReadsARelativeHomeWhereCargoRuns(t *testing.T) {
	project := t.TempDir()
	sub := filepath.Join(project, "sub")
	if err := os.MkdirAll(filepath.Join(sub, "h"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sub, "h", "config.toml"), "[resolver]\nlockfile-path = \"x/Cargo.lock\"\n")
	t.Setenv("CARGO_HOME", "h")
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	t.Chdir(project)
	if !lockfileMoved([]string{"-Z", "unstable-options", "-C", "sub", "fetch"}, sub) {
		t.Error("missed the lockfile-path in the relative CARGO_HOME under -C's directory")
	}
	if lockfileMoved([]string{"fetch"}, project) {
		t.Error("read a relative CARGO_HOME from a directory cargo does not run in")
	}
}

// The real cargo names the lock and every manifest a command may rewrite, a member outside the root's directory included.
func TestReadCargoWorkspaceWithCargo(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not installed")
	}
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	t.Setenv("CARGO_HOME", t.TempDir())
	dir := t.TempDir()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	root, member := filepath.Join(dir, "root"), filepath.Join(dir, "outside", "m")
	for _, d := range []string{filepath.Join(root, "src"), filepath.Join(member, "src")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "Cargo.toml"), "[package]\nname = \"rootpkg\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\nmembers = [\"../outside/m\"]\n")
	writeFile(t, filepath.Join(root, "src", "main.rs"), "fn main() {}\n")
	writeFile(t, filepath.Join(member, "Cargo.toml"), "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition = \"2021\"\nworkspace = \"../../root\"\n")
	writeFile(t, filepath.Join(member, "src", "lib.rs"), "")
	t.Chdir(member)

	ws, err := readCargoWorkspace(context.Background(), []string{"add", "itoa"})
	if err != nil {
		t.Fatal(err)
	}
	// Compared as files, since cargo and Go may spell one path differently on Windows.
	same := func(a, b string) bool {
		fa, errA := os.Stat(a)
		fb, errB := os.Stat(b)
		return errA == nil && errB == nil && os.SameFile(fa, fb)
	}
	if filepath.Base(ws.Lock) != "Cargo.lock" || !same(filepath.Dir(ws.Lock), root) {
		t.Errorf("lock = %s, want the root's", ws.Lock)
	}
	if len(ws.Manifests) != 2 || !slices.ContainsFunc(ws.Manifests, func(p string) bool { return same(p, filepath.Join(root, "Cargo.toml")) }) ||
		!slices.ContainsFunc(ws.Manifests, func(p string) bool { return same(p, filepath.Join(member, "Cargo.toml")) }) {
		t.Errorf("manifests = %v, want the root's and the member's", ws.Manifests)
	}
	if !same(ws.ConfigDir, member) {
		t.Errorf("config dir = %s, want %s", ws.ConfigDir, member)
	}
	if _, err := os.Stat(ws.Lock); !errors.Is(err, os.ErrNotExist) {
		t.Error("cargo metadata --no-deps must not write a lock")
	}

	// --manifest-path after the verb names another workspace than the one cargo runs in.
	other := filepath.Join(dir, "other")
	if err := os.MkdirAll(filepath.Join(other, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(other, "Cargo.toml"), "[package]\nname = \"other\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	writeFile(t, filepath.Join(other, "src", "lib.rs"), "")
	if ws, err = readCargoWorkspace(context.Background(), []string{"add", "--manifest-path", filepath.Join(other, "Cargo.toml"), "itoa"}); err != nil {
		t.Fatal(err)
	}
	if !same(filepath.Dir(ws.Lock), other) || len(ws.Manifests) != 1 || !same(ws.Manifests[0], filepath.Join(other, "Cargo.toml")) {
		t.Errorf("--manifest-path: lock %s, manifests %v; want the other workspace's", ws.Lock, ws.Manifests)
	}

	// A lock cargo would write elsewhere is not checked.
	if err := os.MkdirAll(filepath.Join(member, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(member, ".cargo", "config.toml"), "include = [\"lock.toml\"]\n")
	writeFile(t, filepath.Join(member, ".cargo", "lock.toml"), "[resolver]\nlockfile-path = \"locks/Cargo.lock\"\n")
	if _, err := readCargoWorkspace(context.Background(), []string{"add", "itoa"}); !errors.Is(err, errLockfileMoved) {
		t.Errorf("a config include: err = %v, want errLockfileMoved", err)
	}
	if err := os.Remove(filepath.Join(member, ".cargo", "config.toml")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CARGO_RESOLVER_LOCKFILE_PATH", filepath.Join(dir, "elsewhere", "Cargo.lock"))
	if _, err := readCargoWorkspace(context.Background(), []string{"add", "itoa"}); !errors.Is(err, errLockfileMoved) {
		t.Errorf("CARGO_RESOLVER_LOCKFILE_PATH: err = %v, want errLockfileMoved", err)
	}
}

// cargo 1.99.1 locks a -Zscript manifest under its build directory, not beside the script, so a project lock there is not the one to check (OSS-2553).
func TestReadCargoWorkspaceRefusesACargoScript(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not installed")
	}
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	t.Setenv("CARGO_HOME", t.TempDir())
	t.Setenv("RUSTC_BOOTSTRAP", "1")
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "Cargo.toml"), "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	writeFile(t, filepath.Join(dir, "src", "lib.rs"), "")
	writeFile(t, filepath.Join(dir, "Cargo.lock"), "version = 4\n")
	writeFile(t, filepath.Join(dir, "s.rs"), "---\n[package]\nedition = \"2024\"\n---\nfn main() {}\n")
	t.Chdir(dir)
	for _, args := range [][]string{
		{"-Zscript", "generate-lockfile", "--manifest-path", "s.rs"},
		{"update", "-Zscript", "-ms.rs"},
	} {
		if ws, err := readCargoWorkspace(context.Background(), args); !errors.Is(err, errScriptLock) {
			t.Errorf("cargo %v: lock %s (%v), want errScriptLock", args, ws.Lock, err)
		}
	}
	if _, err := readCargoWorkspace(context.Background(), []string{"-Zscript", "generate-lockfile"}); err != nil {
		t.Errorf("the project beside the script: %v", err)
	}
}

// Registry trust for the copied lock reads the configs where cargo runs, through scan and catalog, not those around the copy.
func TestRunCargoAdd_TrustReadsTheConfigsWhereCargoRuns(t *testing.T) {
	// itoa keeps the first scan from coming back empty, which would rescan through scanProject's fallback.
	corpLock := "version = 4\n\n[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+https://crates.corp.example/internal/\"\nchecksum = \"aaaa\"\n\n" +
		"[[package]]\nname = \"itoa\"\nversion = \"1.0.15\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"bbbb\"\n"
	replace := "[source.corp]\nregistry = \"sparse+https://crates.corp.example/internal/\"\nreplace-with = \"elsewhere\"\n"
	policy, err := trust.Parse([]string{"https://crates.corp.example/internal/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, replaced := range []bool{false, true} {
		t.Run(map[bool]string{false: "no replacement", true: "a replacement"}[replaced], func(t *testing.T) {
			t.Setenv("CARGO_HOME", t.TempDir())
			root, _ := cargoProject(t)
			if replaced {
				if err := os.Mkdir(filepath.Join(root, ".cargo"), 0o755); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(root, ".cargo", "config.toml"), replace)
			}
			var sent []string
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					SBOM struct {
						Components []struct {
							Purl string `json:"purl"`
						} `json:"components"`
					} `json:"sbom"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				for _, c := range body.SBOM.Components {
					sent = append(sent, c.Purl)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"components": [], "vulnerabilities": []}`))
			}))
			t.Cleanup(api.Close)
			swapCargo(t, &fakeCargo{t: t, root: root, lock: corpLock})
			swap(t, nil, cleanSBOM)
			swapScan(t, scanProject)

			if _, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}, APIURL: api.URL, APIKey: "k", Trust: policy}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if checked := slices.ContainsFunc(sent, func(p string) bool { return strings.Contains(p, "acme-sparse") }); checked != replaced {
				t.Errorf("sent %v; want acme-sparse checked %v", sent, replaced)
			}
		})
	}
}

// cargo reads a relative --config file from where it runs after -C, so a file of that name where ossprey started is not the one (OSS-2553).
func TestCargoConfigFileIsReadWhereCargoRuns(t *testing.T) {
	start, dir := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(start, "c.toml"), "ok = 1\n")
	writeFile(t, filepath.Join(dir, "c.toml"), "[resolver]\nlockfile-path = \"alt/Cargo.lock\"\n\n[registry]\ndefault = \"corp\"\n")
	t.Setenv("CARGO_HOME", t.TempDir())
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
	t.Chdir(start)
	if !lockfileMoved([]string{"-Zunstable-options", "-C", dir, "--config", "c.toml", "generate-lockfile"}, dir) {
		t.Error("lockfile-path in the -C directory's c.toml not seen")
	}
	if got := cargoDefaultRegistry([]string{"-Zunstable-options", "-C", dir, "--config", "c.toml", "install", "x"}); got != "corp" {
		t.Errorf("registry.default from the -C directory's c.toml = %q, want corp", got)
	}
}
