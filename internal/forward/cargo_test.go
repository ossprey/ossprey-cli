package forward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// cargoMode is the path a cargo command takes: checked after it runs, before it runs, or passed straight through.
func cargoMode(args []string) string {
	m, _ := Lookup("cargo")
	if _, ok := m.runFirstAt(args); ok {
		return "after"
	}
	if _, ok := m.installAt(args); ok {
		return "before"
	}
	return "through"
}

func TestCargoDetection(t *testing.T) {
	for _, tc := range []struct{ args, want string }{
		{"add serde", "after"},
		{"add serde@=1.0.100", "after"},
		{"add serde@1.0 --features derive tokio", "after"},
		{"add --git https://github.com/serde-rs/serde foo", "after"},
		{"add --path ../x", "after"},
		{"+nightly add serde", "after"},
		{"--config k=v add serde", "after"},
		{"--config=k=v add serde", "after"},
		{"-Z unstable-options -C sub add serde", "after"},
		{"--color always -v update", "after"},
		{"update", "after"},
		{"update -p serde --precise 1.0.100", "after"},
		{"generate-lockfile", "after"},
		{"fetch", "after"},
		{"install ripgrep", "before"},
		{"install --vers 14.1.0 ripgrep", "before"},
		{"install --path .", "before"},
		{"+stable install ripgrep", "before"},
		// clap reads a group of shorts as cargo 1.99.1 does: a value short takes the rest, else the next token.
		{"-qZ unstable-options install ripgrep", "before"},
		{"-Z unstable-options -qC sub add serde", "after"},
		{"-qCsub add serde", "after"},
		{"add --help", "through"},
		{"update -h", "through"},
		{"add -qh serde", "through"},
		{"update -vh", "through"},
		{"add -Fh serde", "after"},
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
		{"-Zunstable-options -C-h add serde", "after"},
		{"add -p-h serde", "after"},
		// An optional value never takes an option token, so the help after it is help (cargo 1.99.1).
		{"install --bin --help ripgrep", "through"},
		{"install --example -h ripgrep", "through"},
		{"install --target -qh ripgrep", "through"},
		{"install --bin rg ripgrep", "before"},
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
	runFirst := [][]string{{"add", "--help"}, {"update", "--help"}, {"fetch", "--help"}, {"generate-lockfile", "--help"}}
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
		{runFirst, cargoRunFirstShorts, nil, func(name string, _ bool) bool { return !strings.HasPrefix(name, "--") }},
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

const memberManifest = "[package]\nname = \"a\"\nversion = \"0.1.0\"\n"

// cargoProject is a workspace with one member and no lock yet, the working directory, and what the forwarder finds for it.
func cargoProject(t *testing.T) (string, cargoWorkspace) {
	t.Helper()
	root := t.TempDir()
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
	ws := cargoWorkspace{
		Lock:      filepath.Join(root, "Cargo.lock"),
		Manifests: []string{filepath.Join(root, "Cargo.toml"), filepath.Join(root, "a", "Cargo.toml")},
		ConfigDir: root,
	}
	old := cargoWorkspaceFn
	cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return ws, nil }
	t.Cleanup(func() { cargoWorkspaceFn = old })
	return root, ws
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

// addEvil is a `cargo add -p a evil` that rewrites the member's manifest and the workspace lock.
func addEvil(t *testing.T, root string, ran *bool) func(context.Context, string, []string) error {
	return func(_ context.Context, bin string, args []string) error {
		*ran = true
		writeFile(t, filepath.Join(root, "a", "Cargo.toml"), memberManifest+"\n[dependencies]\nevil = \"1\"\n")
		writeFile(t, filepath.Join(root, "Cargo.lock"), evilLock)
		return nil
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

// A blocked add puts back the exact bytes of every file it changed, removes a lock it created, and exits 1.
func TestRunCargoAdd_BlockRestoresWhatItChanged(t *testing.T) {
	for _, lockExisted := range []bool{false, true} {
		name := map[bool]string{false: "a new lock", true: "an existing lock"}[lockExisted]
		t.Run(name, func(t *testing.T) {
			root, ws := cargoProject(t)
			oldLock := "version = 4\n# before\n"
			if lockExisted {
				writeFile(t, ws.Lock, oldLock)
				if err := os.Chmod(ws.Lock, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			rootManifest := readFile(t, filepath.Join(root, "Cargo.toml"))
			ran := false
			swap(t, addEvil(t, root, &ran), cleanSBOM)
			var req scanRequest
			var scanned string
			swapScan(t, lockScan(t, &req, &scanned, evilSBOM))

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("Run = %v, want ErrBlocked", err)
			}
			if !ran {
				t.Fatal("cargo add must run before its lock is checked")
			}
			if scanned != evilLock {
				t.Errorf("scanned lock %q, want what cargo wrote", scanned)
			}
			if !req.Installed || req.SubmitOnly || req.CargoConfigDir != root || filepath.Base(req.Dir) != filepath.Base(root) {
				t.Errorf("scan request %+v", req)
			}
			if got := readFile(t, filepath.Join(root, "a", "Cargo.toml")); got != memberManifest {
				t.Errorf("member manifest = %q, want it restored", got)
			}
			if got := readFile(t, filepath.Join(root, "Cargo.toml")); got != rootManifest {
				t.Errorf("root manifest = %q, want it untouched", got)
			}
			member := filepath.Join("a", "Cargo.toml")
			want := "ossprey: undid `cargo add -p a evil`: restored " + member + ", removed Cargo.lock\n"
			if lockExisted {
				if got := readFile(t, ws.Lock); got != oldLock {
					t.Errorf("lock = %q, want its old bytes", got)
				}
				if fi, err := os.Stat(ws.Lock); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
					t.Errorf("lock mode = %v, want 0640", fi.Mode().Perm())
				}
				want = "ossprey: undid `cargo add -p a evil`: restored " + member + ", restored Cargo.lock\n"
			} else if _, err := os.Stat(ws.Lock); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the lock cargo created is still there (%v)", err)
			}
			for _, line := range []string{"Installation blocked.", "Error: WARNING: evil:1.0.0 contains malware", "ossprey: blocked `cargo add -p a evil`\n", want} {
				if !strings.Contains(out, line) {
					t.Errorf("output lacks %q:\n%s", line, out)
				}
			}
		})
	}
}

// A block undoes only what is still as cargo left it, and names a file changed again while the check ran.
func TestRunCargoAdd_BlockLeavesFilesChangedAgain(t *testing.T) {
	member := filepath.Join("a", "Cargo.toml")
	for _, tc := range []struct {
		name, again, kept, undid string
	}{
		{"the manifest edited again", member, member, "removed Cargo.lock"},
		{"a newer lock", "Cargo.lock", "Cargo.lock", "restored " + member},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := cargoProject(t)
			ran := false
			swap(t, addEvil(t, root, &ran), cleanSBOM)
			mine := "# written while the check ran\n"
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
				writeFile(t, filepath.Join(root, tc.again), mine)
				return evilSBOM(), nil
			})

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("Run = %v, want ErrBlocked", err)
			}
			if got := readFile(t, filepath.Join(root, tc.again)); got != mine {
				t.Errorf("%s = %q, want the edit made after cargo exited kept", tc.again, got)
			}
			if tc.again == member {
				if _, err := os.Stat(filepath.Join(root, "Cargo.lock")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the lock cargo created is still there (%v)", err)
				}
			} else if got := readFile(t, filepath.Join(root, member)); got != memberManifest {
				t.Errorf("member manifest = %q, want it restored", got)
			}
			for _, line := range []string{
				"ossprey: undid `cargo add -p a evil`: " + tc.undid + "\n",
				"ossprey: warning: did not undo `cargo add -p a evil` in " + tc.kept + ", changed again after cargo exited\n",
			} {
				if !strings.Contains(out, line) {
					t.Errorf("output lacks %q:\n%s", line, out)
				}
			}
		})
	}
}

// A permission change made while the check ran counts as a change, so a block leaves that file alone (OSS-2553).
func TestRunCargoAdd_BlockLeavesAFileWhoseModeChangedAgain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps no POSIX permission bits")
	}
	member := filepath.Join("a", "Cargo.toml")
	root, _ := cargoProject(t)
	ran := false
	swap(t, addEvil(t, root, &ran), cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
		if err := os.Chmod(filepath.Join(root, member), 0o600); err != nil {
			t.Fatal(err)
		}
		return evilSBOM(), nil
	})

	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Run = %v, want ErrBlocked", err)
	}
	fi, err := os.Stat(filepath.Join(root, member))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("%s mode = %v, want the 0600 set after cargo exited kept", member, fi.Mode().Perm())
	}
	if line := "ossprey: warning: did not undo `cargo add -p a evil` in " + member + ", changed again after cargo exited\n"; !strings.Contains(out, line) {
		t.Errorf("output lacks %q:\n%s", line, out)
	}
}

// A manifest or lock over the bound is never read whole: the lock goes unchecked with the warning, and a manifest is left as cargo left it (OSS-2553).
func TestRunCargoAdd_FileOverTheBoundIsNeverReadWhole(t *testing.T) {
	big := func(t *testing.T, p string) {
		t.Helper()
		writeFile(t, p, "")
		if err := os.Truncate(p, catalog.CargoProofLimit+1); err != nil {
			t.Fatal(err)
		}
	}
	added := "\n[dependencies]\nevil = \"1\"\n"
	t.Run("the lock", func(t *testing.T) {
		root, ws := cargoProject(t)
		big(t, ws.Lock)
		swap(t, func(context.Context, string, []string) error {
			writeFile(t, filepath.Join(root, "a", "Cargo.toml"), memberManifest+added)
			return nil
		}, cleanSBOM)

		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
		want := fmt.Sprintf("ossprey: warning: Cargo.lock not checked after `cargo add -p a evil` (read %s: over the %d byte limit); cargo's changes are kept\n", ws.Lock, catalog.CargoProofLimit)
		if out != want {
			t.Errorf("output = %q, want %q", out, want)
		}
	})
	t.Run("a manifest", func(t *testing.T) {
		root, ws := cargoProject(t)
		manifest := filepath.Join(root, "a", "Cargo.toml")
		big(t, manifest)
		swap(t, func(context.Context, string, []string) error {
			f, err := os.OpenFile(manifest, os.O_WRONLY|os.O_APPEND, 0)
			if err == nil {
				_, err = f.WriteString(added)
				f.Close()
			}
			writeFile(t, ws.Lock, evilLock)
			return err
		}, cleanSBOM)
		swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return evilSBOM(), nil })

		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
		if !errors.Is(err, ErrBlocked) {
			t.Fatalf("Run = %v, want ErrBlocked", err)
		}
		if fi, err := os.Stat(manifest); err != nil || fi.Size() != catalog.CargoProofLimit+1+int64(len(added)) {
			t.Errorf("%s changed after cargo exited (%v), want it left as cargo left it", manifest, err)
		}
		if line := "ossprey: undid `cargo add -p a evil`: removed Cargo.lock\n"; !strings.Contains(out, line) {
			t.Errorf("output lacks %q:\n%s", line, out)
		}
	})
}

// cargo add --dry-run with no lock writes nothing, so nothing is checked or posted and nothing is said unless verbose.
func TestRunCargoAdd_DryRunWithNoLockSaysNothing(t *testing.T) {
	cargoProject(t)
	args := []string{"add", "--dry-run", "serde"}
	for _, passive := range []bool{false, true} {
		ex := &stubExec{}
		swap(t, ex.fn, cleanSBOM)
		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: args, Passive: passive})
		if err != nil || !ex.called || out != "" {
			t.Errorf("passive %v: Run = %v, cargo ran = %v, output %q; want cargo run and nothing printed", passive, err, ex.called, out)
		}
		out, _ = verboseOutput(t, context.Background(), Options{Bin: "cargo", Args: args, Passive: passive})
		if !strings.Contains(out, "ossprey: `cargo add --dry-run serde` left no Cargo.lock; nothing ") {
			t.Errorf("passive %v: verbose output lacks the reason:\n%s", passive, out)
		}
	}
}

// A clean add keeps what cargo wrote and prints the one verdict line.
func TestRunCargoAdd_CleanKeepsTheChanges(t *testing.T) {
	root, ws := cargoProject(t)
	ran := false
	swap(t, addEvil(t, root, &ran), cleanSBOM)
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
	if got := readFile(t, ws.Lock); got != evilLock {
		t.Errorf("lock = %q, want cargo's", got)
	}
	if got := readFile(t, filepath.Join(root, "a", "Cargo.toml")); got == memberManifest {
		t.Error("a clean add must keep the manifest cargo wrote")
	}
}

// cargo's own failure that changed nothing is its exit code, and nothing is scanned.
func TestRunCargoAdd_FailurePassesThrough(t *testing.T) {
	_, ws := cargoProject(t)
	writeFile(t, ws.Lock, evilLock)
	exit101 := errors.New("exit status 101")
	swap(t, func(context.Context, string, []string) error { return exit101 }, cleanSBOM)
	for _, passive := range []bool{false, true} {
		if passive {
			// Passive posts the lock even so, but only when there is one.
			if err := os.Remove(ws.Lock); err != nil {
				t.Fatal(err)
			}
		}
		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}, Passive: passive})
		if !errors.Is(err, exit101) || out != "" {
			t.Errorf("passive %v: Run = %v, output %q; want cargo's own error alone", passive, err, out)
		}
	}
}

// cargo fetch locks before it downloads, so a lock a failed command wrote is checked, and undone on a block.
func TestRunCargoFetch_FailureAfterLockingIsChecked(t *testing.T) {
	exit101 := errors.New("exit status 101")
	for _, tc := range []struct {
		name    string
		sbom    func() *ossbom.SBOM
		want    error
		wantOut string
	}{
		{"blocked", evilSBOM, ErrBlocked, "ossprey: undid `cargo fetch`: removed Cargo.lock\n"},
		{"clean", cleanCrates, exit101, "ossprey: no malware found in 2 packages in Cargo.lock\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ws := cargoProject(t)
			swap(t, func(context.Context, string, []string) error {
				writeFile(t, ws.Lock, evilLock)
				return exit101
			}, cleanSBOM)
			var req scanRequest
			var scanned string
			swapScan(t, lockScan(t, &req, &scanned, tc.sbom))

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"fetch"}})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Run = %v, want %v", err, tc.want)
			}
			if scanned != evilLock || !strings.HasSuffix(out, tc.wantOut) {
				t.Errorf("scanned %q, output:\n%s\nwant it to end %q", scanned, out, tc.wantOut)
			}
		})
	}
}

// cargo add edits Cargo.toml before it resolves, so a failure that changed only manifests says they were not checked.
func TestRunCargoAdd_FailureAfterEditingTheManifestWarns(t *testing.T) {
	root, _ := cargoProject(t)
	exit101 := errors.New("exit status 101")
	swap(t, func(context.Context, string, []string) error {
		writeFile(t, filepath.Join(root, "a", "Cargo.toml"), memberManifest+"\n[dependencies]\nevil = \"1\"\n")
		return exit101
	}, cleanSBOM)
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
	if !errors.Is(err, exit101) {
		t.Fatalf("Run = %v, want cargo's own error", err)
	}
	want := "ossprey: warning: `cargo add -p a evil` failed after changing " + filepath.Join("a", "Cargo.toml") + ", which was not checked\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

// A failed command with no workspace to check (here a moved lock, which a failed fetch --offline still writes) warns and keeps cargo's error.
func TestRunCargoFetch_FailureWithNoWorkspaceStillWarns(t *testing.T) {
	exit101 := errors.New("exit status 101")
	for _, tc := range []struct {
		passive bool
		want    string
	}{
		{false, "ossprey: warning: Cargo.lock not checked after `cargo fetch --offline` (a resolver.lockfile-path may move it); cargo's changes are kept\n"},
		{true, "ossprey: warning: could not post scan (a resolver.lockfile-path may move it); the install was not blocked (passive)\n"},
	} {
		root, _ := cargoProject(t)
		cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return cargoWorkspace{}, errLockfileMoved }
		swap(t, func(context.Context, string, []string) error {
			if err := os.MkdirAll(filepath.Join(root, "alt"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "alt", "Cargo.lock"), evilLock)
			return exit101
		}, cleanSBOM)
		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"fetch", "--offline"}, Passive: tc.passive})
		if !errors.Is(err, exit101) || out != tc.want {
			t.Errorf("passive %v: Run = %v, output %q; want cargo's error and %q", tc.passive, err, out, tc.want)
		}
	}
}

// cargo failing for want of a workspace changed nothing, so its error is the only line, gating or passive; a command that succeeded still warns.
func TestRunCargoAdd_FailureWithNoWorkspaceSaysNothing(t *testing.T) {
	exit101 := errors.New("exit status 101")
	noWorkspace := errors.New("cargo metadata: error: could not find `Cargo.toml` in `/empty` or any parent directory")
	for _, tc := range []struct {
		passive bool
		runErr  error
		want    string
	}{
		{false, exit101, ""},
		{true, exit101, ""},
		{false, nil, "ossprey: warning: Cargo.lock not checked after `cargo add itoa --offline` (" + noWorkspace.Error() + "); cargo's changes are kept\n"},
		{true, nil, "ossprey: warning: could not post scan (" + noWorkspace.Error() + "); the install was not blocked (passive)\n"},
	} {
		cargoProject(t)
		cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return cargoWorkspace{}, noWorkspace }
		swap(t, func(context.Context, string, []string) error { return tc.runErr }, cleanSBOM)
		out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "itoa", "--offline"}, Passive: tc.passive})
		if !errors.Is(err, tc.runErr) || out != tc.want {
			t.Errorf("passive %v, cargo %v: Run = %v, output %q; want %q", tc.passive, tc.runErr, err, out, tc.want)
		}
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

// An API outage after cargo has run keeps its changes and says so in one line.
func TestRunCargoAdd_PlatformErrorFailsOpenOutLoud(t *testing.T) {
	root, ws := cargoProject(t)
	ran := false
	swap(t, addEvil(t, root, &ran), cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return nil, errors.New("api down") })

	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "serde"}})
	if err != nil {
		t.Fatalf("Run = %v, want nil: cargo has already run", err)
	}
	if want := "ossprey: warning: Cargo.lock not checked after `cargo add serde` (api down); cargo's changes are kept\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
	if got := readFile(t, ws.Lock); got != evilLock {
		t.Errorf("lock = %q, want cargo's kept", got)
	}
}

// With no credential a gating cargo add stops before cargo runs, on the error a gating npm install stops on.
func TestRunCargoAdd_NoCredentialStopsBeforeCargoRuns(t *testing.T) {
	root, ws := cargoProject(t)
	unsetEnv(t, "OSSPREY_API_KEY")
	ex := &stubExec{}
	swap(t, ex.fn, check.Run)
	_, want := quietOutput(t, context.Background(), Options{Bin: "npm", Args: []string{"install", "left-pad@1.0.0"}})
	if want == nil || ex.called {
		t.Fatalf("npm install = %v, npm ran = %v; want a credentials error before npm", want, ex.called)
	}

	ran := false
	swap(t, addEvil(t, root, &ran), check.Run)
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("Run = %v, want %v", err, want)
	}
	if ran {
		t.Error("cargo ran with no credential to check its lock")
	}
	if _, err := os.Stat(ws.Lock); !errors.Is(err, os.ErrNotExist) || out != "" {
		t.Errorf("lock %v, output %q; want nothing written and nothing printed", err, out)
	}
}

// The credential is resolved from the forwarder's own API settings, and a run that checks nothing never asks for one.
func TestRunCargoAdd_AsksForACredentialOnlyToCheck(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		passive, skip, unknown bool
		want                   []string
	}{
		{"gating", false, false, false, []string{"credential for https://api.test with k"}},
		{"passive", true, false, false, []string{"cargo"}},
		{"skip-ci", false, true, false, []string{"cargo"}},
		{"unreadable workspace", false, false, true, []string{"cargo"}},
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
			add := addEvil(t, root, new(bool))
			swap(t, func(ctx context.Context, bin string, args []string) error {
				order = append(order, "cargo")
				return add(ctx, bin, args)
			}, cleanSBOM)
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return cleanCrates(), nil })

			opts := Options{Bin: "cargo", Args: []string{"add", "serde"}, APIURL: "https://api.test", APIKey: "k", Passive: tc.passive, SkipCI: tc.skip}
			_, err := quietOutput(t, context.Background(), opts)
			if gating := !tc.passive && !tc.skip && !tc.unknown; (err != nil) != gating {
				t.Errorf("Run = %v, want an error only when the credential stops it", err)
			}
			if !reflect.DeepEqual(order, tc.want) {
				t.Errorf("order = %v, want %v", order, tc.want)
			}
		})
	}
}

// A workspace cargo metadata cannot read still runs cargo, and the line says nothing was checked.
func TestRunCargoAdd_UnreadableWorkspaceRunsCargoAndWarns(t *testing.T) {
	cargoProject(t)
	cargoWorkspaceFn = func(context.Context, []string) (cargoWorkspace, error) { return cargoWorkspace{}, errLockfileMoved }
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
	if err != nil || !ex.called {
		t.Fatalf("Run = %v, cargo ran = %v; want cargo run and nil", err, ex.called)
	}
	if want := "ossprey: warning: Cargo.lock not checked after `cargo update` (a resolver.lockfile-path may move it); cargo's changes are kept\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

// Passive puts nothing in front of cargo: it runs, then the lock is posted without polling.
func TestRunCargoAdd_Passive(t *testing.T) {
	root, _ := cargoProject(t)
	var order []string
	inner := cargoWorkspaceFn
	cargoWorkspaceFn = func(ctx context.Context, args []string) (cargoWorkspace, error) {
		order = append(order, "workspace")
		return inner(ctx, args)
	}
	ran := false
	add := addEvil(t, root, &ran)
	swap(t, func(ctx context.Context, bin string, args []string) error {
		order = append(order, "cargo")
		return add(ctx, bin, args)
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

// cargo install builds as it goes, so a block stops it before cargo starts.
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
			root, ws := cargoProject(t)
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
			swap(t, func(context.Context, string, []string) error {
				writeFile(t, ws.Lock, corpLock)
				return nil
			}, cleanSBOM)
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
