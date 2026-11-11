//go:build smoke

// The cargo forwarder against the real cargo and a fake API: update, generate-lockfile and fetch resolve into scratch and only a clean lock reaches the project, add is refused, and install is blocked before it builds.

package smoke

import (
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

// A lock another program swaps into the project after the checked one lands is not what the fetch downloads, though --locked alone would take it (OSS-2553).
func TestCargoFetchIgnoresALockSwappedInAfterTheCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the cargo in front of the real one is a shell script")
	}
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := cargoCrate(t, env, `itoa = "1"`, false)
	lock := filepath.Join(dir, "Cargo.lock")
	cargoRun(t, dir, env, "generate-lockfile")
	cargoRun(t, dir, env, "update", "-p", "itoa", "--precise", "1.0.14")
	swapped := filepath.Join(t.TempDir(), "Cargo.lock")
	if err := os.Rename(lock, swapped); err != nil {
		t.Fatal(err)
	}
	cargoRun(t, dir, env, "update", "-p", "itoa", "--precise", "1.0.15")

	// The swap lands after ossprey writes the checked lock and before cargo reads one.
	real, err := exec.LookPath("cargo")
	if err != nil {
		t.Fatal(err)
	}
	front := t.TempDir()
	script := "#!/bin/sh\nfor a; do [ \"$a\" = fetch ] && cp '" + swapped + "' '" + lock + "'; done\nexec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(front, "cargo"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	var fronted []string
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			kv = "PATH=" + front + string(os.PathListSeparator) + v
		}
		fronted = append(fronted, kv)
	}

	res := runForwardEnv(t, dir, fronted, binPath, "cargo", "fetch")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, want := stateOf(t, lock), stateOf(t, swapped); string(got.data) != string(want.data) {
		t.Fatalf("Cargo.lock = %q, want the swapped lock, or the test proves nothing", got.data)
	}
	if got := downloaded(t, cargoHome(env)); !slices.Equal(got, []string{"itoa-1.0.15.crate"}) {
		t.Errorf("downloaded %v, want the checked itoa 1.0.15 alone\nstderr: %s", got, res.stderr)
	}
	if verdict, fetched := strings.Index(res.stderr, "ossprey: no malware found"), strings.Index(res.stderr, "Downloaded itoa"); verdict < 0 || fetched < verdict {
		t.Errorf("want the verdict line before cargo's download lines\nstderr: %s", res.stderr)
	}
	if strings.Contains(res.stderr, "ossprey-cargo-") {
		t.Errorf("stderr names a scratch path:\n%s", res.stderr)
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

// In gating mode cargo add is refused after the version check, before cargo touches the project or the API is asked, and add --dry-run goes to cargo.
func TestCargoAddIsRefused(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := cargoCrate(t, env, "", true)
	manifest, lock := filepath.Join(dir, "Cargo.toml"), filepath.Join(dir, "Cargo.lock")
	beforeManifest, beforeLock := stateOf(t, manifest), stateOf(t, lock)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if want := "error: did not run `cargo add itoa@=1.0.15`: ossprey does not check `cargo add` yet"; res.exitCode != 2 || !strings.Contains(res.stderr, want) {
		t.Fatalf("exit %d, want 2 and %q\nstderr: %s", res.exitCode, want, res.stderr)
	}
	if !stateOf(t, manifest).same(beforeManifest) || !stateOf(t, lock).same(beforeLock) {
		t.Errorf("Cargo.toml or Cargo.lock changed\nstderr: %s", res.stderr)
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("%d API requests, want none", n)
	}

	// The fake cargo is a shell script that records what reaches it, so only POSIX checks what ran.
	if runtime.GOOS == "windows" {
		return
	}
	bin := t.TempDir()
	fake := "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/ran\"\n[ \"$1\" = -V ] && echo 'cargo 1.99.1 (5f94df478 2026-08-27)'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "cargo"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	env = forwardEnv(t.TempDir(), api.URL, bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	ran := filepath.Join(bin, "ran")
	for _, tc := range []struct {
		args []string
		exit int
		ran  string
	}{
		{[]string{"add", "itoa"}, 2, "-V\n"},
		{[]string{"add", "--dry-run", "itoa"}, 0, "-V\nadd --dry-run itoa\n"},
	} {
		os.Remove(ran)
		res := runForwardEnv(t, dir, env, binPath, append([]string{"cargo"}, tc.args...)...)
		if got, _ := os.ReadFile(ran); res.exitCode != tc.exit || string(got) != tc.ran {
			t.Errorf("cargo %v: exit %d, cargo ran %q; want %d and %q\nstderr: %s", tc.args, res.exitCode, got, tc.exit, tc.ran, res.stderr)
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

// cargoDownloads is the release real cargo downloads for an install line, read from its own output.
func cargoDownloads(t *testing.T, env []string, crate string, args ...string) string {
	t.Helper()
	res := runForwardEnv(t, t.TempDir(), env, "cargo", append([]string{"install", "--root", t.TempDir()}, args...)...)
	for _, line := range strings.Split(res.stderr, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Downloaded "+crate+" v"); ok {
			return strings.Fields(v)[0]
		}
	}
	t.Fatalf("cargo install %v downloaded no %s\nstderr: %s", args, crate, res.stderr)
	return ""
}

// The release checked is the one real cargo downloads: a range's highest match and a pin's release as crates.io spells it (OSS-2553).
func TestCargoInstallChecksTheReleaseCargoDownloads(t *testing.T) {
	for _, tc := range []struct{ crate, spec string }{
		{"itoa", "itoa@^0.4"},
		{"itoa", "itoa@1.0.14+zzz"},
		{"wasi", "wasi@0.11.0"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			v := cargoDownloads(t, cargoEnv(t, "http://127.0.0.1:9"), tc.crate, tc.spec)
			purl := "pkg:cargo/" + tc.crate + "@" + v
			api := newFakeAPI(t, purl)
			root := t.TempDir()
			res := runForwardEnv(t, t.TempDir(), cargoEnv(t, api.URL), binPath, "cargo", "install", "--root", root, tc.spec)
			if _, purls := api.stats(); res.exitCode != 1 || !slices.Equal(purls, []string{purl}) || !dirEmpty(t, root) {
				t.Errorf("exit %d, submitted %v; want %s alone checked and blocked before cargo runs\nstderr: %s", res.exitCode, purls, purl, res.stderr)
			}
		})
	}
}

// With crates.io's API unreachable the release comes from the index cargo reads, and with that unreachable too the install is refused before cargo runs (OSS-2553).
func TestCargoInstallLooksUpTheIndexCargoReads(t *testing.T) {
	dead := []string{"HTTPS_PROXY=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9"}
	latest := cargoDownloads(t, cargoEnv(t, "http://127.0.0.1:9"), "itoa", "itoa")
	api := newFakeAPI(t, "pkg:cargo/itoa@"+latest)
	root := t.TempDir()
	env := append(cargoEnv(t, api.URL), append(dead, "NO_PROXY=index.crates.io,static.crates.io", "no_proxy=index.crates.io,static.crates.io")...)
	res := runForwardEnv(t, t.TempDir(), env, binPath, "cargo", "install", "--root", root, "itoa")
	if _, purls := api.stats(); res.exitCode != 1 || !slices.Equal(purls, []string{"pkg:cargo/itoa@" + latest}) || !dirEmpty(t, root) {
		t.Errorf("API unreachable: exit %d, submitted %v; want itoa %s checked and blocked\nstderr: %s", res.exitCode, purls, latest, res.stderr)
	}

	api = newFakeAPI(t, "")
	env = append(cargoEnv(t, api.URL), append(dead, "NO_PROXY=", "no_proxy=")...)
	res = runForwardEnv(t, t.TempDir(), env, binPath, "cargo", "install", "--root", root, "itoa")
	if requests, _ := api.stats(); res.exitCode != 2 || requests != 0 || !strings.Contains(res.stderr, "did not run `cargo install --root") || !dirEmpty(t, root) {
		t.Errorf("index unreachable: exit %d, %d requests; want exit 2 before anything is asked or run\nstderr: %s", res.exitCode, requests, res.stderr)
	}
}

// cargo 1.99.1 reads a registry whose index is crates.io's as crates.io, by --registry or registry.default, so its crate is checked (OSS-2553).
func TestCargoInstallChecksCratesIoUnderAnotherName(t *testing.T) {
	for _, tc := range []struct {
		config string
		args   []string
	}{
		{"", []string{"--registry", "cio"}},
		{"[registry]\ndefault = \"cio\"\n", nil},
	} {
		api := newFakeAPI(t, "pkg:cargo/itoa@1.0.14")
		env := cargoEnv(t, api.URL)
		var home string
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, "CARGO_HOME="); ok {
				home = v
			}
		}
		if err := writeFile(home, "config.toml", "[registries.cio]\nindex = \"sparse+https://index.crates.io/\"\n"+tc.config); err != nil {
			t.Fatal(err)
		}
		root := t.TempDir()
		res := runForwardEnv(t, t.TempDir(), env, binPath, append(append([]string{"cargo", "install", "--root", root}, tc.args...), "itoa@1.0.14")...)
		if _, purls := api.stats(); res.exitCode != 1 || !slices.Equal(purls, []string{"pkg:cargo/itoa@1.0.14"}) || !dirEmpty(t, root) {
			t.Errorf("%q %v: exit %d, submitted %v; want itoa checked and blocked before cargo runs\nstderr: %s", tc.config, tc.args, res.exitCode, purls, res.stderr)
		}
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
