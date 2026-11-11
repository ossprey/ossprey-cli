package forward

import (
	"context"
	"errors"
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
)

// cargoMode is the path a cargo command takes: refused until its lock can be checked, checked before it runs, or passed straight through.
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
		// A release that ends like an archive name is still a pin, which cargo 1.99.1 installs (OSS-2553).
		{"tool@1.2.3-beta.zip", "", crate("tool", "1.2.3-beta.zip"), nil},
		{"tool@1.2.3+build.tar.gz", "", crate("tool", "1.2.3+build.tar.gz"), nil},
		{"tool@=1.2.3-a.tgz tool@1.2.3-a.tgz", "", crate("tool", "1.2.3-a.tgz"), nil},
		{"--version 1.2.3-x.whl tool", "", crate("tool", "1.2.3-x.whl"), nil},
		{"--vers=1.2.3-a.tar.bz2 tool", "", crate("tool", "1.2.3-a.tar.bz2"), nil},
		{"--version 1.2.3+b.tar tool", "", crate("tool", "1.2.3+b.tar"), nil},
	} {
		got := parseCargoInstall(strings.Fields(tc.args), tc.defaultRegistry, func(r string) bool { return r == "crates-io" || r == "cio" })
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

func TestRunCargoInstall_BlockedBeforeCargoRuns(t *testing.T) {
	ex := &stubExec{}
	var got []check.Spec
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o.Specs
		return malwareSBOM(ctx, o)
	})
	err := Run(context.Background(), Options{Bin: "cargo", Args: []string{"install", "evil", "--vers", "1.0.0", "other"}})
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

// A pin whose release ends like an archive name is checked before cargo runs, not forwarded unchecked (OSS-2553).
func TestRunCargoInstall_ChecksAReleaseNamedLikeAnArchive(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		version string
	}{
		{[]string{"install", "tool@1.2.3-beta.zip"}, "1.2.3-beta.zip"},
		{[]string{"install", "--version", "1.2.3+build.tar.gz", "tool"}, "1.2.3+build.tar.gz"},
	} {
		ex := &stubExec{}
		var got []check.Spec
		swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
			got = o.Specs
			return malwareSBOM(ctx, o)
		})
		if err := Run(context.Background(), Options{Bin: "cargo", Args: tc.args}); !errors.Is(err, ErrBlocked) || ex.called {
			t.Errorf("cargo %v: Run = %v, cargo ran %v; want ErrBlocked before cargo runs", tc.args, err, ex.called)
		}
		if want := []check.Spec{{Ecosystem: "cargo", Name: "tool", Version: tc.version}}; !reflect.DeepEqual(got, want) {
			t.Errorf("cargo %v: checked %+v, want %+v", tc.args, got, want)
		}
	}
}

// Each crate is checked at the release cargo takes from crates.io's index for what was typed, not at crates.io's latest or as typed (OSS-2553).
func TestRunCargoInstall_ChecksTheReleaseCargoTakes(t *testing.T) {
	for _, tc := range []struct {
		args          []string
		req, released string
	}{
		{[]string{"install", "itoa@^0.4"}, "^0.4", "0.4.8"},
		{[]string{"install", "--version", "<1", "itoa"}, "<1", "0.4.8"},
		{[]string{"install", "itoa@1.0.14+zzz"}, "=1.0.14+zzz", "1.0.14"},
		{[]string{"install", "wasi@0.11.0"}, "=0.11.0", "0.11.0+wasi-snapshot-preview1"},
		{[]string{"install", "itoa"}, "", "1.0.19"},
	} {
		ex := &stubExec{}
		var got []check.Spec
		swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
			got = o.Specs
			return malwareSBOM(ctx, o)
		})
		name, _, _ := strings.Cut(tc.args[len(tc.args)-1], "@")
		var asked []string
		cargoReleaseFn = func(_ context.Context, n, req string) ([]string, error) {
			asked = append(asked, n+" "+req)
			return []string{tc.released}, nil
		}
		latest := func(context.Context, string, string) (string, error) { return "9.9.9", nil }
		if err := Run(context.Background(), Options{Bin: "cargo", Args: tc.args, ResolveLatest: latest}); !errors.Is(err, ErrBlocked) || ex.called {
			t.Errorf("cargo %v: Run = %v, cargo ran %v; want ErrBlocked before cargo runs", tc.args, err, ex.called)
		}
		if want := []string{name + " " + tc.req}; !reflect.DeepEqual(asked, want) {
			t.Errorf("cargo %v: looked up %q, want %q", tc.args, asked, want)
		}
		if want := []check.Spec{{Ecosystem: "cargo", Name: name, Version: tc.released}}; !reflect.DeepEqual(got, want) {
			t.Errorf("cargo %v: checked %+v, want %+v", tc.args, got, want)
		}
	}
}

// An install whose release cannot be found in crates.io's index is refused with exit code 2, every crate unchecked and cargo never run (OSS-2553).
func TestRunCargoInstall_RefusesWhenTheReleaseCannotBeFound(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		t.Errorf("checked %+v; nothing is checked when a crate cannot be looked up", o.Specs)
		return cleanSBOM(ctx, o)
	})
	cargoReleaseFn = func(_ context.Context, name, req string) ([]string, error) {
		if name == "ripgrep" {
			return nil, errors.New("registry request: connection refused")
		}
		return []string{"1.0.19"}, nil
	}
	latest := func(_ context.Context, _, name string) (string, error) {
		if name == "ripgrep" {
			return "", errors.New("registry request: connection refused")
		}
		return "1.0.19", nil
	}
	// The error names only the verb, since the rest of the line may hold a credential.
	args := []string{"+stable", "--config", `http.proxy="http://user:secret@proxy.example:3128"`, "install", "itoa", "ripgrep"}
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args, ResolveLatest: latest})
	want := "did not run `cargo install`: could not tell which release of ripgrep cargo would install (registry request: connection refused), so it was not checked"
	if err == nil || err.Error() != want || errors.Is(err, ErrBlocked) || ex.called || out != "" {
		t.Errorf("Run = %v, output %q, cargo ran %v; want %q alone", err, out, ex.called, want)
	}
}

// Only the named crates are checked, and the line says the dependencies were not.
func TestRunCargoInstall_SaysDependenciesWereNotChecked(t *testing.T) {
	ex := &stubExec{}
	_, chk := checkedSpecs(t)
	swap(t, ex.fn, chk)
	swapExpand(t, expandInstall)
	cargoReleaseFn = stubCargoReleases("14.1.1")
	args := []string{"+stable", "install", "--locked", "ripgrep"}
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args})
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
	cio := "[registries.cio]\nindex = \"sparse+https://index.crates.io/\"\n"
	for _, tc := range []struct {
		name, config, env string
		args              []string
		checked           bool
	}{
		{"crates.io by name", "", "", []string{"install", "--registry", "crates-io", "itoa"}, true},
		{"crates.io by name, joined", "", "", []string{"install", "--registry=crates-io", "itoa"}, true},
		{"crates.io's sparse index", "", "", []string{"install", "--index", "sparse+https://index.crates.io/", "itoa"}, true},
		{"crates.io's git index", "", "", []string{"install", "--index=https://github.com/rust-lang/crates.io-index", "itoa"}, true},
		// cargo 1.99.1 reads sparse+ in any case, and keeps a backslash in a sparse+ URL, so this host is mirror.example (OSS-2553).
		{"crates.io's sparse index in capitals", "", "", []string{"install", "--index", "SPARSE+https://index.crates.io/", "itoa"}, true},
		{"a mirror behind a backslash", "", "", []string{"install", "--index", `sparse+https://index.crates.io\@mirror.example/../`, "itoa"}, false},
		// cargo parses a sparse+ URL again as https, where each of these is crates.io's index.
		{"crates.io past a backslash and ..", "", "", []string{"install", "--index", `sparse+https://index.crates.io/\../`, "itoa"}, true},
		{"crates.io past a slash and a backslash", "", "", []string{"install", "--index", `sparse+https:/\index.crates.io/`, "itoa"}, true},
		{"crates.io behind backslashed userinfo", "", "", []string{"install", "--index", `sparse+https://mirror.example\@index.crates.io/`, "itoa"}, true},
		{"crates.io's host with a trailing dot", "", "", []string{"install", "--index", "sparse+https://index.crates.io./", "itoa"}, true},
		{"crates.io's host in full-width letters", "", "", []string{"install", "--index", "sparse+https://ｉｎｄｅｘ.crates.io/", "itoa"}, true},
		{"corp by default in CARGO_HOME", corp + "[registry]\ndefault = \"corp\"\n", "", []string{"install", "itoa"}, false},
		{"corp by default, crates.io by name", corp + "[registry]\ndefault = \"corp\"\n", "", []string{"install", "--registry", "crates-io", "itoa"}, true},
		{"corp by CARGO_REGISTRY_DEFAULT", corp, "corp", []string{"install", "itoa"}, false},
		{"corp by --config", corp, "", []string{"--config", `registry.default="corp"`, "install", "itoa"}, false},
		{"crates-io by default", "[registry]\ndefault = \"crates-io\"\n", "", []string{"install", "itoa"}, true},
		// cargo 1.99.1 reads a registry whose index is crates.io's as crates.io (OSS-2553).
		{"crates.io under another name", cio, "", []string{"install", "--registry", "cio", "itoa"}, true},
		{"crates.io under another name by default", cio + "[registry]\ndefault = \"cio\"\n", "", []string{"install", "itoa"}, true},
		{"crates.io under another name by CARGO_REGISTRY_DEFAULT", cio, "cio", []string{"install", "itoa"}, true},
		{"crates.io under another name by --config", "", "", []string{"--config", `registries.cio.index="sparse+https://index.crates.io/"`, "install", "--registry=cio", "itoa"}, true},
		{"another name moved off crates.io by --config", cio, "", []string{"--config", `registries.cio.index="sparse+https://crates.corp.example/"`, "install", "--registry", "cio", "itoa"}, false},
		{"another name with no index", "", "", []string{"install", "--registry", "cio", "itoa"}, false},
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
			cargoReleaseFn = stubCargoReleases("1.0.19")
			if err := Run(context.Background(), Options{Bin: "cargo", Args: tc.args}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if checked != tc.checked || !ex.called {
				t.Errorf("checked = %v, forwarded = %v; want checked %v and forwarded", checked, ex.called, tc.checked)
			}
		})
	}
}

// cargo reads a registry's index from CARGO_REGISTRIES_<NAME>_INDEX, its name in capitals with '-' as '_', over the configs (OSS-2553).
func TestCargoRegistryIsCratesIoReadsTheEnvironment(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CARGO_HOME", home)
	writeFile(t, filepath.Join(home, "config.toml"), "[registries.my-cio]\nindex = \"sparse+https://crates.corp.example/\"\n")
	args := []string{"install", "--registry", "my-cio", "itoa"}
	if cargoRegistryIsCratesIo(args, "my-cio") {
		t.Error("my-cio's index is crates.corp.example in CARGO_HOME")
	}
	t.Setenv("CARGO_REGISTRIES_MY_CIO_INDEX", "sparse+https://index.crates.io/")
	if !cargoRegistryIsCratesIo(args, "my-cio") {
		t.Error("CARGO_REGISTRIES_MY_CIO_INDEX names crates.io's index over the config")
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

// In gating mode the verbs that only lock are refused before cargo runs or anything is checked, naming only the verb, and passive and skip-ci hand them to cargo as typed.
func TestRunCargo_LockingCommandsAreRefused(t *testing.T) {
	for _, tc := range []struct{ line, verb string }{
		{"add serde", "add"},
		{"add --dry-run serde", "add"},
		{"+nightly update", "update"},
		{"update --dry-run", "update"},
		{"-q generate-lockfile", "generate-lockfile"},
		{"fetch --locked", "fetch"},
		{`--config http.proxy="http://user:secret@proxy.example:3128" update`, "update"},
		{`add --config http.proxy="http://user:secret@proxy.example:3128" serde`, "add"},
	} {
		args := strings.Fields(tc.line)
		ex := &stubExec{}
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			t.Errorf("cargo %s was checked", tc.line)
			return nil, nil
		})
		want := "did not run `cargo " + tc.verb + "`: ossprey does not check `cargo " + tc.verb + "` yet"
		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args})
		if err == nil || err.Error() != want || errors.Is(err, ErrBlocked) || out != "" || ex.called {
			t.Errorf("cargo %s: Run = %v, output %q, cargo ran %v; want %q alone", tc.line, err, out, ex.called, want)
		}
		for _, opts := range []Options{{Bin: "cargo", Args: args, Passive: true}, {Bin: "cargo", Args: args, SkipCI: true}} {
			ex := &stubExec{}
			swap(t, ex.fn, nil)
			if out, err := quietOutput(t, context.Background(), opts); err != nil || out != "" || !ex.called || !reflect.DeepEqual(ex.args, args) {
				t.Errorf("cargo %s (passive %v): Run = %v, output %q, forwarded %v (called %v)", tc.line, opts.Passive, err, out, ex.args, ex.called)
			}
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

// On Windows -C lands where cargo's chdir puts it: rooted on this drive, relative to this drive under the working directory, and relative to another drive as Abs places it (OSS-2553).
func TestCargoChdirPlacesWindowsPathsByVolume(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only Windows has rooted and drive-relative paths")
	}
	t.Chdir(t.TempDir())
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	vol, other := filepath.VolumeName(wd), "Q:"
	if strings.EqualFold(vol, other) {
		other = "R:"
	}
	elsewhere, err := filepath.Abs(other + "x")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ dir, want string }{
		{`\x`, vol + `\x`},
		{vol + "sub", filepath.Join(wd, "sub")},
		{other + "x", elsewhere},
		{`sub\..\x`, filepath.Join(wd, "x")},
	} {
		globals := []string{"-Zunstable-options", "-C", tc.dir}
		if got := cargoChdir(globals); got != tc.want {
			t.Errorf("cargo %v from %s: %s, want %s", globals, wd, got, tc.want)
		}
	}
}

// cargo 1.99.1 install fails on a --config or CARGO_HOME config that is a directory, so the forwarder reads it as setting no registry.default and the crate is still checked (OSS-2553).
func TestCargoInstallChecksACrateWhoseConfigIsADirectory(t *testing.T) {
	assertIrregularConfig(t, func(p string) error { return os.Mkdir(p, 0o755) })
}

// assertIrregularConfig makes each config cargo install reads with mk, which is not a regular file, and wants it not to set registry.default.
func assertIrregularConfig(t *testing.T, mk func(string) error) {
	t.Helper()
	base := t.TempDir()
	home, project := filepath.Join(base, "home"), filepath.Join(base, "project")
	for _, d := range []string{home, project} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CARGO_HOME", home)
	unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
	t.Chdir(project)
	if cargoDefaultRegistry([]string{"install", "x"}) != "" {
		t.Fatal("nothing sets registry.default yet")
	}
	arg := filepath.Join(base, "arg.toml")
	if err := mk(arg); err != nil {
		t.Fatal(err)
	}
	if got := cargoDefaultRegistry([]string{"install", "--config", arg, "x"}); got != "" {
		t.Errorf("a --config file that is not a regular file: %q, want the crates.io crate checked", got)
	}
	if got := cargoDefaultRegistry([]string{"--config", `registry.default="corp"`, "install", "--config", arg, "x"}); got != "corp" {
		t.Errorf("a --config file that is not a regular file after one that sets corp: %q, want corp", got)
	}
	if err := mk(filepath.Join(home, "config.toml")); err != nil {
		t.Fatal(err)
	}
	if got := cargoDefaultRegistry([]string{"install", "x"}); got != "" {
		t.Errorf("CARGO_HOME's config that is not a regular file: %q, want the crates.io crate checked", got)
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
	if got := cargoDefaultRegistry([]string{"-Zunstable-options", "-C", dir, "--config", "c.toml", "install", "x"}); got != "corp" {
		t.Errorf("registry.default from the -C directory's c.toml = %q, want corp", got)
	}
}
