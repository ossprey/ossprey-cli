//go:build smoke

// The cargo forwarder against the real cargo and a fake API: add, update, generate-lockfile and fetch resolve into scratch and only a clean lock reaches the project, and install is blocked before it builds.

package smoke

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// cargoEnv is forwardEnv with cargo's caches in scratch and rustup still finding its toolchains under the real home.
func cargoEnv(t *testing.T, apiURL string) []string {
	t.Helper()
	needBin(t, "cargo")
	if testing.Short() {
		t.Skip("reads the crates.io index")
	}
	home := t.TempDir()
	rustup := os.Getenv("RUSTUP_HOME")
	if rustup == "" {
		if h, err := os.UserHomeDir(); err == nil {
			rustup = filepath.Join(h, ".rustup")
		}
	}
	var env []string
	for _, kv := range forwardEnv(home, apiURL, os.Getenv("PATH")) {
		if k, _, _ := strings.Cut(kv, "="); k != "CARGO_HOME" && k != "RUSTUP_HOME" && k != "CARGO_RESOLVER_LOCKFILE_PATH" {
			env = append(env, kv)
		}
	}
	return append(env, "CARGO_HOME="+filepath.Join(home, ".cargo"), "RUSTUP_HOME="+rustup)
}

// shortTempDir is a temp dir, links resolved, named without the test's name, since the add mirror nests a project's whole path under the cache and Windows limits a working directory to 260 characters.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "o")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// cargoHome is the CARGO_HOME env sets.
func cargoHome(env []string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "CARGO_HOME="); ok {
			return v
		}
	}
	return ""
}

const smokeManifest = "[package]\nname = \"ossprey-smoke\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n"

// cargoCrate is a binary crate with the dependency lines deps, locked first with none when locked.
func cargoCrate(t *testing.T, env []string, deps string, locked bool) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"Cargo.toml": smokeManifest, filepath.Join("src", "main.rs"): "fn main() {}\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if locked {
		cargoRun(t, dir, env, "generate-lockfile", "--offline")
	}
	if deps != "" {
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(smokeManifest+deps+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// cargoRun runs the real cargo in dir, failing the test when it fails.
func cargoRun(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("cargo", args...)
	cmd.Dir, cmd.Env = dir, env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cargo %v: %v\n%s", args, err, out)
	}
}

// fileState is a file's bytes and the file itself, so a rewrite with the same bytes still shows.
type fileState struct {
	data []byte
	info fs.FileInfo
}

func stateOf(t *testing.T, p string) fileState {
	t.Helper()
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		return fileState{}
	}
	data, rerr := os.ReadFile(p)
	if err != nil || rerr != nil {
		t.Fatalf("%s: %v %v", p, err, rerr)
	}
	return fileState{data, info}
}

// same reports whether a and b are the same file with the same bytes, or both missing.
func (a fileState) same(b fileState) bool {
	if a.info == nil || b.info == nil {
		return a.info == nil && b.info == nil
	}
	return string(a.data) == string(b.data) && os.SameFile(a.info, b.info)
}

// downloaded are the .crate files cargo has put in CARGO_HOME's cache.
func downloaded(t *testing.T, home string) []string {
	t.Helper()
	var got []string
	_ = filepath.WalkDir(filepath.Join(home, "registry", "cache"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, ".crate") {
			got = append(got, d.Name())
		}
		return nil
	})
	return got
}

// A blocked command leaves Cargo.toml and Cargo.lock as they were, the same files with the same bytes, writes nothing under target/, and downloads no crate (OSS-2553).
func TestCargoBlockedLeavesTheProjectAsItWas(t *testing.T) {
	for _, tc := range []struct {
		name   string
		deps   string
		locked bool
		args   []string
	}{
		{"add", "", true, []string{"add", "itoa@=1.0.15"}},
		{"add with no lock", "", false, []string{"add", "itoa@=1.0.15"}},
		{"update", `itoa = "=1.0.15"`, true, []string{"update"}},
		{"generate-lockfile", `itoa = "=1.0.15"`, false, []string{"generate-lockfile"}},
		{"fetch", `itoa = "=1.0.15"`, false, []string{"fetch"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, "pkg:cargo/itoa@1.0.15")
			env := cargoEnv(t, api.URL)
			dir := cargoCrate(t, env, tc.deps, tc.locked)
			manifest, lock := filepath.Join(dir, "Cargo.toml"), filepath.Join(dir, "Cargo.lock")
			beforeManifest, beforeLock := stateOf(t, manifest), stateOf(t, lock)
			target := emptyTarget(t, dir)

			res := runForwardEnv(t, dir, env, binPath, append([]string{"cargo"}, tc.args...)...)
			if res.exitCode != 1 || !strings.Contains(res.stderr, "ossprey: the project was not changed") {
				t.Fatalf("exit %d, want 1 and the block\nstderr: %s", res.exitCode, res.stderr)
			}
			if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
				t.Errorf("target/ holds %v (%v), want nothing", entries, err)
			}
			if !stateOf(t, manifest).same(beforeManifest) || !stateOf(t, lock).same(beforeLock) {
				t.Errorf("Cargo.toml or Cargo.lock changed\nstderr: %s", res.stderr)
			}
			if got := downloaded(t, cargoHome(env)); len(got) != 0 {
				t.Errorf("downloaded %v, want nothing", got)
			}
			if _, purls := api.stats(); !slices.Contains(purls, "pkg:cargo/itoa@1.0.15") {
				t.Errorf("submitted %v, want the crate cargo resolved", purls)
			}
		})
	}
}

// emptyTarget makes dir's target/, where cargo writes .rustc_info.json unless CARGO_CACHE_RUSTC_INFO=0 (verified with cargo 1.99.1).
func emptyTarget(t *testing.T, dir string) string {
	t.Helper()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	return target
}

// A clean add writes the manifest and the lock cargo resolved, and the one verdict line, and nothing under target/.
func TestCargoAddCleanLandsTheManifestAndLock(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := cargoCrate(t, env, "", false)
	target := emptyTarget(t, dir)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 0 || !strings.Contains(res.stderr, "ossprey: no malware found in 1 package in Cargo.lock") {
		t.Fatalf("exit %d, want 0 and the verdict\nstderr: %s", res.exitCode, res.stderr)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Errorf("target/ holds %v (%v), want nothing", entries, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); !strings.Contains(string(got), `itoa = "=1.0.15"`) {
		t.Errorf("Cargo.toml = %q, want cargo's edit", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.lock")); !strings.Contains(string(got), "name = \"itoa\"\nversion = \"1.0.15\"") {
		t.Errorf("Cargo.lock = %q, want itoa locked", got)
	}
	if _, purls := api.stats(); !slices.Contains(purls, "pkg:cargo/itoa@1.0.15") {
		t.Errorf("submitted %v, want the crate from the new lock", purls)
	}
}

// An absolute --path lands as plain cargo writes it, relative to the manifest, not climbing out through the mirror (OSS-2553).
func TestCargoAddAnAbsolutePath(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	base := t.TempDir()
	dirs := map[string]string{}
	for _, name := range []string{"local", "checked", "plain"} {
		dirs[name] = filepath.Join(base, name)
		if err := os.Rename(cargoCrate(t, env, "", false), dirs[name]); err != nil {
			t.Fatal(err)
		}
	}
	local := filepath.Join(base, "local", "Cargo.toml")
	if err := os.WriteFile(local, []byte(strings.Replace(smokeManifest, "ossprey-smoke", "local", 1)), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runForwardEnv(t, dirs["checked"], env, binPath, "cargo", "add", "--offline", "--path", dirs["local"])
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	cargoRun(t, dirs["plain"], env, "add", "--offline", "--path", dirs["local"])
	got, _ := os.ReadFile(filepath.Join(dirs["checked"], "Cargo.toml"))
	want, _ := os.ReadFile(filepath.Join(dirs["plain"], "Cargo.toml"))
	if string(got) != string(want) {
		t.Errorf("Cargo.toml = %q, want plain cargo's %q", got, want)
	}
}

// A clean fetch lands the lock it checked and downloads exactly that.
func TestCargoFetchCleanDownloadsTheCheckedLock(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := cargoCrate(t, env, `itoa = "=1.0.15"`, false)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "fetch")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.lock")); !strings.Contains(string(got), "name = \"itoa\"\nversion = \"1.0.15\"") {
		t.Errorf("Cargo.lock = %q, want itoa locked", got)
	}
	if got := downloaded(t, cargoHome(env)); !slices.Equal(got, []string{"itoa-1.0.15.crate"}) {
		t.Errorf("downloaded %v, want the checked crate alone", got)
	}
}

// In a workspace, add from a member's directory, with -p and with --manifest-path writes the member's manifest and the root's lock through the mirror, a member reached through a linked directory included, and a block leaves every file as it was (OSS-2553).
func TestCargoAddInAWorkspaceMember(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	files := map[string]string{
		"Cargo.toml": "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
	}
	for _, m := range []string{"app", "lib", filepath.Join("..", "..", "far")} {
		files[filepath.Join("crates", m, "Cargo.toml")] = fmt.Sprintf("[package]\nname = %q\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n", filepath.Base(m))
		files[filepath.Join("crates", m, "src", "lib.rs")] = ""
	}
	for name, data := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// cargo reaches crates/far through the link without resolving it (verified with cargo 1.99.1).
	if err := os.Symlink(filepath.Join("..", "..", "far"), filepath.Join(root, "crates", "far")); err != nil {
		t.Fatal(err)
	}
	lib, far := filepath.Join(root, "crates", "lib"), filepath.Join(base, "far")
	for _, args := range [][]string{{"add", "-p", "far", "itoa@=1.0.15"}, {"add", "--manifest-path", filepath.Join("crates", "far", "Cargo.toml"), "--dev", "itoa@=1.0.15"}} {
		res := runForwardEnv(t, root, env, binPath, append([]string{"cargo"}, args...)...)
		if res.exitCode != 0 {
			t.Fatalf("cargo %v: exit %d\nstderr: %s", args, res.exitCode, res.stderr)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(far, "Cargo.toml")); !strings.Contains(string(got), "[dependencies]\nitoa = \"=1.0.15\"\n\n[dev-dependencies]\nitoa = \"=1.0.15\"\n") {
		t.Errorf("the linked member's manifest = %q, want both of cargo's edits", got)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "Cargo.lock")); !strings.Contains(string(got), "name = \"app\"") || !strings.Contains(string(got), "name = \"lib\"") || !strings.Contains(string(got), "name = \"itoa\"") {
		t.Errorf("the root's lock = %q, want every member and itoa", got)
	}

	res := runForwardEnv(t, lib, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(lib, "Cargo.toml")); !strings.Contains(string(got), `itoa = "=1.0.15"`) {
		t.Errorf("the member's manifest = %q, want cargo's edit", got)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "Cargo.lock")); !strings.Contains(string(got), "name = \"itoa\"") {
		t.Errorf("the root's lock = %q, want itoa locked", got)
	}

	api.mu.Lock()
	api.malware = "pkg:cargo/itoa@1.0.15"
	api.mu.Unlock()
	paths := []string{filepath.Join(root, "Cargo.toml"), filepath.Join(root, "Cargo.lock"), filepath.Join(lib, "Cargo.toml"), filepath.Join(root, "crates", "app", "Cargo.toml"), filepath.Join(far, "Cargo.toml")}
	var before []fileState
	for _, p := range paths {
		before = append(before, stateOf(t, p))
	}
	for _, args := range [][]string{{"add", "-p", "app", "itoa@=1.0.15"}, {"add", "-p", "far", "--build", "itoa@=1.0.15"}} {
		if res = runForwardEnv(t, lib, env, binPath, append([]string{"cargo"}, args...)...); res.exitCode != 1 {
			t.Fatalf("cargo %v: exit %d, want 1\nstderr: %s", args, res.exitCode, res.stderr)
		}
	}
	for i, p := range paths {
		if !stateOf(t, p).same(before[i]) {
			t.Errorf("%s changed", p)
		}
	}
}

// cargoTree writes files under base, each a crate with a src/lib.rs when it names a [package].
func cargoTree(t *testing.T, base string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(base, name)
		if err := os.MkdirAll(filepath.Join(filepath.Dir(p), "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(data, "[package]") {
			if err := os.WriteFile(filepath.Join(filepath.Dir(p), "src", "lib.rs"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// treeState is every file under dir and its state.
func treeState(t *testing.T, dir string) map[string]fileState {
	t.Helper()
	got := map[string]fileState{}
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			got[p] = stateOf(t, p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func crateManifest(name, extra string) string {
	return fmt.Sprintf("[package]\nname = %q\nversion = \"0.1.0\"\nedition = \"2021\"\n%s", name, extra)
}

// An absolute path in a Cargo.toml leads cargo out of ossprey's copy of the workspace, where `add -p` wrote a manifest it reached through a link before the check, a crate the add brought in was a member only in the project, so the checked lock lacked its dev-dependencies, and a path cargo rewrote named another directory in the project; so the add is refused and the project is left as it was (OSS-2553).
func TestCargoAddRefusesAWorkspaceItsCopyCannotHold(t *testing.T) {
	excluded := func(base string) map[string]string {
		return map[string]string{
			"Cargo.toml":          fmt.Sprintf("[workspace]\nmembers = [\"crates/*\"]\nexclude = ['%s']\nresolver = \"2\"\n", filepath.Join(base, "crates", "b")),
			"crates/a/Cargo.toml": crateManifest("a", ""),
			"crates/b/Cargo.toml": crateManifest("b", ""),
		}
	}
	for _, tc := range []struct {
		name  string
		files func(base string) map[string]string
		cwd   string
		args  []string
		want  string
	}{
		{"an absolute exclude, adding to the excluded crate", excluded, ".", []string{"add", "-p", "b", "itoa@=1.0.15"}, "cargo would see another workspace in ossprey's copy of it, since"},
		{"an absolute exclude in an outer manifest the copy links", excluded, filepath.Join("crates", "b"), []string{"add", "-p", "a", "itoa@=1.0.15"}, "cargo would see another workspace in ossprey's copy of it, since"},
		{"an absolute path dependency under a workspace root", func(base string) map[string]string {
			return map[string]string{
				"Cargo.toml":     crateManifest("app", fmt.Sprintf("\n[workspace]\n\n[dependencies]\nfoo = { path = '%s' }\n", filepath.Join(base, "foo"))),
				"foo/Cargo.toml": crateManifest("foo", ""),
			}
		}, ".", []string{"add", "itoa@=1.0.15"}, "cargo would see another workspace in ossprey's copy of it, since"},
		{"an absolute package.workspace", func(base string) map[string]string {
			return map[string]string{
				"ws/Cargo.toml": "[workspace]\nmembers = [\"../m\"]\nresolver = \"2\"\n",
				"m/Cargo.toml":  crateManifest("m", fmt.Sprintf("workspace = '%s'\n", filepath.Join(base, "ws"))),
			}
		}, "m", []string{"add", "itoa@=1.0.15"}, "cargo metadata fails in ossprey's copy of the workspace with error: current package believes it's in a workspace when it's not"},
		{"an absolute [workspace.dependencies] path the add first uses", func(base string) map[string]string {
			return map[string]string{
				"Cargo.toml":          fmt.Sprintf("[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n\n[workspace.dependencies]\nfoo = { path = '%s' }\n", filepath.Join(base, "foo")),
				"crates/a/Cargo.toml": crateManifest("a", ""),
				"foo/Cargo.toml":      crateManifest("foo", "\n[dev-dependencies]\nitoa = \"=1.0.15\"\n"),
			}
		}, filepath.Join("crates", "a"), []string{"add", "foo"}, "after the add, since it would not take "},
		{"a crate outside the project naming its root by an absolute package.workspace", func(base string) map[string]string {
			return map[string]string{
				"proj/Cargo.toml":          "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
				"proj/crates/a/Cargo.toml": crateManifest("a", ""),
				"outside/x/Cargo.toml":     crateManifest("x", fmt.Sprintf("workspace = '%s'\n\n[dev-dependencies]\nitoa = \"=1.0.15\"\n", filepath.Join(base, "proj"))),
			}
		}, filepath.Join("proj", "crates", "a"), []string{"add", "--path", filepath.Join("..", "..", "..", "outside", "x")}, "after the add, since it would not take "},
		{"an absolute path dependency cargo add writes again", func(base string) map[string]string {
			return map[string]string{
				"Cargo.toml":     crateManifest("app", fmt.Sprintf("\n[dependencies]\nfoo = { path = '%s' }\n", filepath.Join(base, "foo"))),
				"foo/Cargo.toml": crateManifest("foo", ""),
			}
		}, ".", []string{"add", "--dev", "foo"}, "Cargo.toml would hold the path \""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newFakeAPI(t, "pkg:cargo/itoa@1.0.15")
			cache := shortTempDir(t)
			env := append(cargoEnv(t, api.URL), "LOCALAPPDATA="+cache, "XDG_CACHE_HOME="+cache)
			base := shortTempDir(t)
			cargoTree(t, base, tc.files(base))
			before := treeState(t, base)

			res := runForwardEnv(t, filepath.Join(base, tc.cwd), env, binPath, append([]string{"cargo"}, tc.args...)...)
			if res.exitCode != 2 || !strings.Contains(res.stderr, tc.want) || !strings.Contains(res.stderr, "absolute path") && !strings.Contains(res.stderr, "relative to its Cargo.toml") {
				t.Errorf("exit %d, want 2 and the refusal\nstderr: %s", res.exitCode, res.stderr)
			}
			after := treeState(t, base)
			for p, s := range before {
				if !after[p].same(s) {
					t.Errorf("%s changed", p)
				}
			}
			for p := range after {
				if _, ok := before[p]; !ok {
					t.Errorf("%s was written", p)
				}
			}
			if n, _ := api.stats(); n != 0 {
				t.Errorf("the API got %d requests, want none", n)
			}
		})
	}
}

// An absolute path dependency under a crate with no workspace is no member, so an add that leaves it alone runs and lands what plain cargo writes.
func TestCargoAddAnAbsolutePathDependency(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := func(crate string) string {
		return crateManifest("app", fmt.Sprintf("\n[dependencies]\nfoo = { path = '%s' }\n", filepath.Join(base, crate, "foo")))
	}
	cargoTree(t, base, map[string]string{"checked/foo/Cargo.toml": crateManifest("foo", ""), "checked/Cargo.toml": app("checked"), "plain/foo/Cargo.toml": crateManifest("foo", ""), "plain/Cargo.toml": app("plain")})

	res := runForwardEnv(t, filepath.Join(base, "checked"), env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	cargoRun(t, filepath.Join(base, "plain"), env, "add", "itoa@=1.0.15")
	for _, name := range []string{"Cargo.toml", "Cargo.lock"} {
		got, _ := os.ReadFile(filepath.Join(base, "checked", name))
		want, _ := os.ReadFile(filepath.Join(base, "plain", name))
		if len(want) == 0 || strings.ReplaceAll(string(got), "checked", "plain") != string(want) {
			t.Errorf("%s = %q, want plain cargo's %q", name, got, want)
		}
	}
}

// cargo's error names the redirected lock, which the user reads as the project's (OSS-2553).
func TestCargoLockedFailureNamesTheProjectLock(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := cargoCrate(t, env, `itoa = "=1.0.15"`, true)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "update", "--locked")
	if res.exitCode != 101 {
		t.Fatalf("exit %d, want cargo's 101\nstderr: %s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, filepath.Join(dir, "Cargo.lock")) || strings.Contains(res.stderr, "ossprey-cargo-") {
		t.Errorf("stderr names the scratch lock, want the project's:\n%s", res.stderr)
	}
}

// A cargo older than 1.97 ignores the redirect and writes the project's lock (verified with 1.96.0 and 1.80.0), so it never runs (OSS-2553).
func TestCargoOlderThan197IsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake cargo is a shell script")
	}
	bin := t.TempDir()
	// Only +old is 1.96.0, so a probe that dropped the toolchain would pass the gate and run it (verified with cargo 1.96.0).
	fake := "#!/bin/sh\nfor a; do [ \"$a\" = -V ] && { [ \"$1\" = +old ] && echo 'cargo 1.96.0 (30a34c682 2026-05-25)' || echo 'cargo 1.99.1 (5f94df478 2026-08-27)'; exit 0; }; done\necho \"$@\" >> \"$(dirname \"$0\")/ran\"\n"
	if err := os.WriteFile(filepath.Join(bin, "cargo"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	api := newFakeAPI(t, "")
	env := forwardEnv(t.TempDir(), api.URL, bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	lock := "version = 4\n"
	for name, data := range map[string]string{"Cargo.toml": smokeManifest, "Cargo.lock": lock} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "itoa"}, {"update"}, {"generate-lockfile"}, {"fetch"}, {"add", "--dry-run", "itoa"}} {
		res := runForwardEnv(t, dir, env, binPath, append([]string{"cargo", "+old"}, args...)...)
		if res.exitCode != 2 || !strings.Contains(res.stderr, "ossprey needs cargo 1.97 or later") || !strings.Contains(res.stderr, "cargo 1.96.0 (30a34c682 2026-05-25)") {
			t.Errorf("cargo +old %v: exit %d, want 2 and the refusal\nstderr: %s", args, res.exitCode, res.stderr)
		}
	}
	if ran, err := os.ReadFile(filepath.Join(bin, "ran")); err == nil {
		t.Errorf("cargo ran: %s", ran)
	}
	for name, want := range map[string]string{"Cargo.toml": smokeManifest, "Cargo.lock": lock} {
		if got, _ := os.ReadFile(filepath.Join(dir, name)); string(got) != want {
			t.Errorf("%s = %q, want it untouched", name, got)
		}
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("%d API requests, want none", n)
	}
}

// A resolver.lockfile-path puts the lock where ossprey does not land it, so the command is refused before cargo writes anything there.
func TestCargoMovedLockIsRefused(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := cargoCrate(t, env, `itoa = "=1.0.15"`, false)
	if err := os.MkdirAll(filepath.Join(dir, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cargo", "config.toml"), []byte("[resolver]\nlockfile-path = \"alt/Cargo.lock\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runForwardEnv(t, dir, env, binPath, "cargo", "fetch")
	if res.exitCode != 2 || !strings.Contains(res.stderr, "error: did not run `cargo fetch`: its Cargo.lock cannot be checked (a resolver.lockfile-path may move it)") {
		t.Fatalf("exit %d, want 2 and the refusal\nstderr: %s", res.exitCode, res.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "alt")); !os.IsNotExist(err) {
		t.Errorf("cargo wrote the moved lock (%v)", err)
	}
	if got := downloaded(t, cargoHome(env)); len(got) != 0 {
		t.Errorf("downloaded %v, want nothing", got)
	}
}

// With no Cargo.toml, a gating command is refused on cargo's own error line, and passive leaves cargo's error alone.
func TestCargoAddWithNoWorkspace(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := t.TempDir()
	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa", "--offline")
	if res.exitCode != 2 || !strings.Contains(res.stderr, "did not run `cargo add itoa --offline`") || !strings.Contains(res.stderr, "could not find `Cargo.toml`") {
		t.Errorf("gating: exit %d, want 2 and cargo's error in the refusal\nstderr: %s", res.exitCode, res.stderr)
	}
	res = runForwardEnv(t, dir, append(slices.Clone(env), "OSSPREY_PASSIVE=1"), binPath, "cargo", "add", "itoa", "--offline")
	if res.exitCode != 101 || !strings.Contains(res.stderr, "could not find `Cargo.toml`") || strings.Contains(res.stderr, "ossprey:") {
		t.Errorf("passive: exit %d, want cargo's 101 and its error alone\nstderr: %s", res.exitCode, res.stderr)
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("%d API requests, want none", n)
	}
}

// With no Cargo.toml, a gating update is refused on cargo's own error line, and passive leaves cargo's error alone.
func TestCargoUpdateWithNoWorkspace(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := t.TempDir()
	res := runForwardEnv(t, dir, env, binPath, "cargo", "update", "--offline")
	if res.exitCode != 2 || !strings.Contains(res.stderr, "did not run `cargo update --offline`") || !strings.Contains(res.stderr, "could not find `Cargo.toml`") {
		t.Errorf("gating: exit %d, want 2 and cargo's error in the refusal\nstderr: %s", res.exitCode, res.stderr)
	}
	res = runForwardEnv(t, dir, append(slices.Clone(env), "OSSPREY_PASSIVE=1"), binPath, "cargo", "update", "--offline")
	if res.exitCode != 101 || !strings.Contains(res.stderr, "could not find `Cargo.toml`") || strings.Contains(res.stderr, "ossprey:") {
		t.Errorf("passive: exit %d, want cargo's 101 and its error alone\nstderr: %s", res.exitCode, res.stderr)
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("%d API requests, want none", n)
	}
}

// Passive runs cargo first and posts the lock it wrote, never blocking.
func TestCargoAddPassivePostsTheLock(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/itoa@1.0.15")
	env := append(cargoEnv(t, api.URL), "OSSPREY_PASSIVE=1")
	dir := cargoCrate(t, env, "", false)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); !strings.Contains(string(got), "itoa") {
		t.Errorf("Cargo.toml = %q, want cargo's edit kept", got)
	}
	if _, purls := api.stats(); !slices.Contains(purls, "pkg:cargo/itoa@1.0.15") {
		t.Errorf("submitted %v, want the lock posted", purls)
	}
}

// A path naming lockfile-path sets nothing, so cargo 1.99.1's lock is still checked, and a block through a relative --manifest-path leaves the project as it was.
func TestCargoAddInALockfilePathDirectoryIsChecked(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/itoa@1.0.15")
	env := cargoEnv(t, api.URL)
	parent := t.TempDir()
	dir := filepath.Join(parent, "lockfile-path")
	if err := os.Rename(cargoCrate(t, env, "", false), dir); err != nil {
		t.Fatal(err)
	}

	res := runForwardEnv(t, parent, env, binPath, "cargo", "add", "--manifest-path", "lockfile-path/Cargo.toml", "itoa@=1.0.15")
	if res.exitCode != 1 {
		t.Fatalf("exit %d, want 1\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); string(got) != smokeManifest {
		t.Errorf("Cargo.toml = %q, want it untouched", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); !os.IsNotExist(err) {
		t.Errorf("a Cargo.lock was written (%v)", err)
	}
}

// cargo 1.99.1 locks a -Zscript manifest under its build directory, where ossprey does not land it, so the command is refused before cargo runs (OSS-2553).
func TestCargoScriptIsRefused(t *testing.T) {
	api := newFakeAPI(t, "")
	env := append(cargoEnv(t, api.URL), "RUSTC_BOOTSTRAP=1")
	dir := cargoCrate(t, env, "", false)
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte("version = 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "---\n[package]\nedition = \"2024\"\n[dependencies]\nitoa = \"=1.0.15\"\n---\nfn main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "s.rs"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runForwardEnv(t, dir, env, binPath, "cargo", "-Zscript", "generate-lockfile", "--manifest-path", "s.rs")
	if res.exitCode != 2 || !strings.Contains(res.stderr, "its Cargo.lock cannot be checked (a cargo script keeps it in the build directory)") {
		t.Fatalf("exit %d, want 2 and the refusal\nstderr: %s", res.exitCode, res.stderr)
	}
	if _, err := os.Stat(filepath.Join(cargoHome(env), "build")); !os.IsNotExist(err) {
		t.Errorf("cargo ran and wrote under its build directory (%v)", err)
	}
}

func TestCargoInstallBlockedBeforeItBuilds(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/ripgrep@14.1.1")
	env := cargoEnv(t, api.URL)
	root := t.TempDir()

	res := runForwardEnv(t, t.TempDir(), env, binPath, "cargo", "install", "--root", root, "--vers", "14.1.1", "ripgrep")
	if res.exitCode != 1 {
		t.Fatalf("exit %d, want 1\nstderr: %s", res.exitCode, res.stderr)
	}
	if !dirEmpty(t, root) {
		t.Error("a blocked install must not reach cargo")
	}
}

// cargo 1.99.1 reads `-qF pcre2` as -q and -F pcre2, so only ripgrep is a crate.
func TestCargoInstallGroupedShortsAreNotCrates(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/ripgrep@14.1.1")
	env := cargoEnv(t, api.URL)
	root := t.TempDir()

	res := runForwardEnv(t, t.TempDir(), env, binPath, "cargo", "install", "--root", root, "-qF", "pcre2", "ripgrep@14.1.1")
	if res.exitCode != 1 {
		t.Fatalf("exit %d, want 1\nstderr: %s", res.exitCode, res.stderr)
	}
	if _, purls := api.stats(); !slices.Equal(purls, []string{"pkg:cargo/ripgrep@14.1.1"}) {
		t.Errorf("submitted %v, want ripgrep alone", purls)
	}
	if !dirEmpty(t, root) {
		t.Error("a blocked install must not reach cargo")
	}
}

// cargo 1.99.1 reads a piped --config again once the pipe is empty, so cargo install takes a crate from crates.io whatever the pipe set, and the crate is checked (OSS-2553).
func TestCargoInstallFromAPipedConfigIsChecked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/stdin")
	}
	api := newFakeAPI(t, "pkg:cargo/ripgrep@14.1.1")
	env := cargoEnv(t, api.URL)
	root := t.TempDir()
	cmd := exec.Command(binPath, "cargo", "--config", "/dev/stdin", "install", "--offline", "--root", root, "ripgrep@14.1.1")
	cmd.Dir, cmd.Env = t.TempDir(), env
	cmd.Stdin = strings.NewReader("[registry]\ndefault = \"corp\"\n[registries.corp]\nindex = \"sparse+https://corp.invalid/\"\n")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("Run = %v, want exit 1 on the block\nstderr: %s", err, stderr.String())
	}
	if _, purls := api.stats(); !slices.Equal(purls, []string{"pkg:cargo/ripgrep@14.1.1"}) {
		t.Errorf("submitted %v, want ripgrep checked", purls)
	}
	if !dirEmpty(t, root) {
		t.Error("a blocked install must not reach cargo")
	}
}

// cargo 1.99.1 joins a relative CARGO_HOME to its working directory and reads registry.default from the configs above it.
func TestCargoInstallReadsTheRegistryAboveARelativeHome(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/ripgrep@14.1.1")
	var env []string
	for _, kv := range cargoEnv(t, api.URL) {
		if k, _, _ := strings.Cut(kv, "="); k != "CARGO_HOME" {
			env = append(env, kv)
		}
	}
	env = append(env, "CARGO_HOME=.cargo", "CARGO_NET_RETRY=0")
	parent := t.TempDir()
	project := filepath.Join(parent, "project")
	if err := os.MkdirAll(filepath.Join(parent, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	corp := "[registry]\ndefault = \"corp\"\n[registries.corp]\nindex = \"sparse+https://corp.invalid/\"\n"
	if err := os.WriteFile(filepath.Join(parent, ".cargo", "config.toml"), []byte(corp), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()

	res := runForwardEnv(t, project, env, binPath, "cargo", "install", "--root", root, "ripgrep@14.1.1")
	if n, _ := api.stats(); n != 0 || res.exitCode == 1 {
		t.Fatalf("exit %d after %d API requests, want the corp crate forwarded unchecked\nstderr: %s", res.exitCode, n, res.stderr)
	}
	if !strings.Contains(res.stderr, "corp.invalid") {
		t.Errorf("cargo did not try the corp registry:\n%s", res.stderr)
	}
}

// noCredentialEnv is cargoEnv with no API key and an empty config directory, so the forwarder finds no credential.
func noCredentialEnv(t *testing.T, apiURL string) []string {
	t.Helper()
	var env []string
	for _, kv := range cargoEnv(t, apiURL) {
		if k, _, _ := strings.Cut(kv, "="); k != "OSSPREY_API_KEY" && k != "OSSPREY_CONFIG_DIR" {
			env = append(env, kv)
		}
	}
	return append(env, "OSSPREY_CONFIG_DIR="+t.TempDir())
}

func TestCargoAddWithoutACredentialStopsBeforeCargo(t *testing.T) {
	api := newFakeAPI(t, "")
	env := noCredentialEnv(t, api.URL)
	dir := cargoCrate(t, env, "", false)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 2 || !strings.Contains(res.stderr, "error: no credentials") {
		t.Fatalf("exit %d, want 2 on the credentials error\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); string(got) != smokeManifest {
		t.Errorf("Cargo.toml = %q, want cargo never run", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); !os.IsNotExist(err) {
		t.Errorf("a Cargo.lock was written (%v), want cargo never run", err)
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("the API got %d requests, want none", n)
	}
}

// A gating update with no credential stops before cargo runs, so no lock is written.
func TestCargoUpdateWithoutACredentialStopsBeforeCargo(t *testing.T) {
	api := newFakeAPI(t, "")
	env := noCredentialEnv(t, api.URL)
	deps := `itoa = "=1.0.15"`
	dir := cargoCrate(t, env, deps, false)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "update")
	if res.exitCode != 2 || !strings.Contains(res.stderr, "error: no credentials") {
		t.Fatalf("exit %d, want 2 on the credentials error\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); string(got) != smokeManifest+deps+"\n" {
		t.Errorf("Cargo.toml = %q, want it untouched", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); !os.IsNotExist(err) {
		t.Errorf("a Cargo.lock was written (%v), want cargo never run", err)
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("the API got %d requests, want none", n)
	}
}
