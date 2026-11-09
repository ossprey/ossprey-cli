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

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
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
		{"add --help", "through"},
		{"update -h", "through"},
		{"install --list", "through"},
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

func TestParseSpecsCargoInstall(t *testing.T) {
	m, _ := Lookup("cargo")
	crate := func(name, version string) []check.Spec {
		return []check.Spec{{Ecosystem: "cargo", Name: name, Version: version}}
	}
	ripgrep := crate("ripgrep", "")
	for _, tc := range []struct {
		args    string
		specs   []check.Spec
		nonPkgs []string
	}{
		{"ripgrep", ripgrep, nil},
		{"--vers 14.1.0 ripgrep", crate("ripgrep", "14.1.0"), nil},
		{"--version=14.1.0 ripgrep fd-find", append(crate("ripgrep", "14.1.0"), crate("fd-find", "14.1.0")...), nil},
		{"ripgrep@14.1.0", crate("ripgrep", "14.1.0"), nil},
		{"ripgrep@=14.1.0", crate("ripgrep", "14.1.0"), nil},
		{"ripgrep@^14", []check.Spec{{Ecosystem: "cargo", Name: "ripgrep", Constraint: "^14"}}, nil},
		{"--version ^14 ripgrep", []check.Spec{{Ecosystem: "cargo", Name: "ripgrep", Constraint: "^14"}}, nil},
		{"--path .", nil, []string{"--path ."}},
		{"--git https://github.com/BurntSushi/ripgrep ripgrep", nil, []string{"ripgrep", "--git https://github.com/BurntSushi/ripgrep"}},
		{"--registry corp ripgrep", nil, []string{"ripgrep", "--registry corp"}},
		{"--index sparse+https://crates.corp.example/ ripgrep", nil, []string{"ripgrep", "--index sparse+https://crates.corp.example/"}},
		{"--bin rg ripgrep", ripgrep, nil},
		{"--target x86_64-unknown-linux-gnu --root /opt -F a,b -j 4 --profile release ripgrep", ripgrep, nil},
		{"--features=derive --locked --force -f ripgrep", ripgrep, nil},
		{"--config k=v -Z unstable-options ripgrep", ripgrep, nil},
		{"./local", nil, []string{"./local"}},
	} {
		got := ParseSpecs(m, strings.Fields(tc.args))
		if !reflect.DeepEqual(got.Specs, tc.specs) || !reflect.DeepEqual(got.NonPackages, tc.nonPkgs) {
			t.Errorf("cargo install %s: specs %+v, non-packages %q; want %+v, %q", tc.args, got.Specs, got.NonPackages, tc.specs, tc.nonPkgs)
		}
	}
}

// clapHelpFlags reads clap's help, short-only options and optional values included: the options taking a value, and those that do not.
func clapHelpFlags(help string) (takes, switches map[string]bool) {
	takes, switches = map[string]bool{}, map[string]bool{}
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
			} else {
				switches[n] = true
			}
		}
	}
	return takes, switches
}

func TestCargoFlagTablesMatchCargo(t *testing.T) {
	cargo, err := exec.LookPath("cargo")
	if err != nil {
		t.Skip("cargo not installed")
	}
	for _, tc := range []struct {
		args   []string
		table  map[string]bool
		hidden []string
	}{
		{[]string{"--help"}, globalValueFlags["cargo"], nil},
		{[]string{"install", "--help"}, valueFlags["cargo"], []string{"--vers"}},
	} {
		out, err := exec.Command(cargo, tc.args...).Output()
		if err != nil {
			t.Skipf("cargo %v: %v", tc.args, err)
		}
		takes, switches := clapHelpFlags(string(out))
		if len(takes) == 0 {
			t.Fatalf("cargo %v: read no options from %q", tc.args, out)
		}
		for f := range takes {
			if !tc.table[f] {
				t.Errorf("cargo %v: %s takes a value but is missing from the table", tc.args, f)
			}
		}
		for f := range tc.table {
			switch {
			case switches[f]:
				t.Errorf("cargo %v: %s is a switch, and listing it swallows the token after it", tc.args, f)
			case !takes[f] && !slices.Contains(tc.hidden, f):
				t.Errorf("cargo %v: %s is not one of its options", tc.args, f)
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

// cargo's own failure is its exit code, and nothing is scanned.
func TestRunCargoAdd_FailurePassesThrough(t *testing.T) {
	cargoProject(t)
	exit101 := errors.New("exit status 101")
	swap(t, func(context.Context, string, []string) error { return exit101 }, cleanSBOM)
	if err := Run(context.Background(), Options{Bin: "cargo", Args: []string{"add", "nope"}}); !errors.Is(err, exit101) {
		t.Fatalf("Run = %v, want cargo's own error", err)
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
	if want := "ossprey: warning: Cargo.lock not checked after `cargo update` (resolver.lockfile-path moves it); cargo's changes are kept\n"; out != want {
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
	}
}

func TestRunCargoInstall_Passive(t *testing.T) {
	ex := &stubExec{}
	var submitted check.Options
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		submitted = o
		return malwareSBOM(context.Background(), o)
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
		{"serde -- -m x", ""},
	} {
		if got := strings.Join(cargoWorkspaceFlags(strings.Fields(tc.rest)), " "); got != tc.want {
			t.Errorf("%q: %q, want %q", tc.rest, got, tc.want)
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
	t.Setenv("CARGO_RESOLVER_LOCKFILE_PATH", "x/Cargo.lock")
	if !lockfileMoved([]string{"add", "serde"}, sub) {
		t.Error("missed CARGO_RESOLVER_LOCKFILE_PATH")
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
}
