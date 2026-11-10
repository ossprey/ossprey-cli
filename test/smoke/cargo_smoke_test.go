//go:build smoke

// The cargo forwarder against the real cargo and a fake API: add runs first and is undone on a block, install is blocked before it builds.

package smoke

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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

// cargoCrate is a binary crate with no dependencies and no lock.
func cargoCrate(t *testing.T) (dir, manifest string) {
	t.Helper()
	dir = t.TempDir()
	manifest = "[package]\nname = \"ossprey-smoke\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n"
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"Cargo.toml": manifest, filepath.Join("src", "main.rs"): "fn main() {}\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, manifest
}

func TestCargoAddBlockedIsUndone(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/itoa@1.0.15")
	env := cargoEnv(t, api.URL)
	dir, manifest := cargoCrate(t)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 1 {
		t.Fatalf("exit %d, want 1\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); string(got) != manifest {
		t.Errorf("Cargo.toml = %q, want it restored", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); !os.IsNotExist(err) {
		t.Errorf("the Cargo.lock cargo created is still there (%v)", err)
	}
	if !strings.Contains(res.stderr, "ossprey: undid `cargo add itoa@=1.0.15`: restored Cargo.toml, removed Cargo.lock") {
		t.Errorf("stderr lacks the restore line:\n%s", res.stderr)
	}
}

func TestCargoAddCleanKeepsTheLock(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir, manifest := cargoCrate(t)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); string(got) == manifest {
		t.Error("a clean add must keep cargo's manifest")
	}
	if _, purls := api.stats(); !slices.Contains(purls, "pkg:cargo/itoa@1.0.15") {
		t.Errorf("submitted %v, want the crate from the new lock", purls)
	}
	if !strings.Contains(res.stderr, "ossprey: no malware found in 1 package in Cargo.lock") {
		t.Errorf("stderr lacks the verdict:\n%s", res.stderr)
	}
}

func TestCargoAddWithoutACredentialStopsBeforeCargo(t *testing.T) {
	api := newFakeAPI(t, "")
	var env []string
	for _, kv := range cargoEnv(t, api.URL) {
		if k, _, _ := strings.Cut(kv, "="); k != "OSSPREY_API_KEY" && k != "OSSPREY_CONFIG_DIR" {
			env = append(env, kv)
		}
	}
	env = append(env, "OSSPREY_CONFIG_DIR="+t.TempDir())
	dir, manifest := cargoCrate(t)

	res := runForwardEnv(t, dir, env, binPath, "cargo", "add", "itoa@=1.0.15")
	if res.exitCode != 2 || !strings.Contains(res.stderr, "error: no credentials") {
		t.Fatalf("exit %d, want 2 on the credentials error\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); string(got) != manifest {
		t.Errorf("Cargo.toml = %q, want cargo never run", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); !os.IsNotExist(err) {
		t.Errorf("a Cargo.lock was written (%v), want cargo never run", err)
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("the API got %d requests, want none", n)
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

// A failed fetch --offline still writes a lock that resolver.lockfile-path moved, so the unchecked change is named.
func TestCargoFetchFailingAfterAMovedLockWarns(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir, manifest := cargoCrate(t)
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(manifest+"itoa = \"=1.0.15\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The index is cached and the crate is not, so offline cargo locks and then fails to download.
	lock := exec.Command("cargo", "generate-lockfile")
	lock.Dir, lock.Env = dir, env
	if out, err := lock.CombinedOutput(); err != nil {
		t.Fatalf("cargo generate-lockfile: %v\n%s", err, out)
	}
	if err := os.Remove(filepath.Join(dir, "Cargo.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cargo", "config.toml"), []byte("[resolver]\nlockfile-path = \"alt/Cargo.lock\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runForwardEnv(t, dir, env, binPath, "cargo", "fetch", "--offline")
	if res.exitCode != 101 {
		t.Fatalf("exit %d, want cargo's 101\nstderr: %s", res.exitCode, res.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "alt", "Cargo.lock")); err != nil {
		t.Errorf("cargo left no moved lock (%v)", err)
	}
	if want := "ossprey: warning: Cargo.lock not checked after `cargo fetch --offline` (a resolver.lockfile-path may move it); cargo's changes are kept"; !strings.Contains(res.stderr, want) {
		t.Errorf("stderr lacks %q:\n%s", want, res.stderr)
	}
}

// cargo add in a directory with no Cargo.toml fails before it writes anything, so cargo's error is the only line, gating or passive.
func TestCargoAddWithNoWorkspaceSaysNothing(t *testing.T) {
	api := newFakeAPI(t, "")
	env := cargoEnv(t, api.URL)
	dir := t.TempDir()
	for _, passive := range []string{"", "1"} {
		res := runForwardEnv(t, dir, append(slices.Clone(env), "OSSPREY_PASSIVE="+passive), binPath, "cargo", "add", "itoa", "--offline")
		if res.exitCode != 101 || !strings.Contains(res.stderr, "could not find `Cargo.toml`") {
			t.Fatalf("passive %q: exit %d, want cargo's 101 and its error\nstderr: %s", passive, res.exitCode, res.stderr)
		}
		if strings.Contains(res.stderr, "ossprey:") {
			t.Errorf("passive %q: ossprey spoke after cargo's own error:\n%s", passive, res.stderr)
		}
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("%d API requests, want none", n)
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

// A path naming lockfile-path sets nothing, so cargo 1.99.1's lock is still checked and a block undoes the add.
func TestCargoAddInALockfilePathDirectoryIsChecked(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/itoa@1.0.15")
	env := cargoEnv(t, api.URL)
	dir, manifest := cargoCrate(t)
	parent := t.TempDir()
	if err := os.Rename(dir, filepath.Join(parent, "lockfile-path")); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(parent, "lockfile-path")

	res := runForwardEnv(t, parent, env, binPath, "cargo", "add", "--manifest-path", "lockfile-path/Cargo.toml", "itoa@=1.0.15")
	if res.exitCode != 1 {
		t.Fatalf("exit %d, want 1\nstderr: %s", res.exitCode, res.stderr)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Cargo.toml")); string(got) != manifest {
		t.Errorf("Cargo.toml = %q, want it restored", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.lock")); !os.IsNotExist(err) {
		t.Errorf("the Cargo.lock cargo created is still there (%v)", err)
	}
}

// cargo 1.99.1 locks a -Zscript manifest under its build directory, so the project lock beside the script is not checked in its place (OSS-2553).
func TestCargoScriptLockIsNotCheckedWarns(t *testing.T) {
	api := newFakeAPI(t, "pkg:cargo/itoa@1.0.15")
	env := append(cargoEnv(t, api.URL), "RUSTC_BOOTSTRAP=1")
	dir, _ := cargoCrate(t)
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte("version = 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := "---\n[package]\nedition = \"2024\"\n[dependencies]\nitoa = \"=1.0.15\"\n---\nfn main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "s.rs"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runForwardEnv(t, dir, env, binPath, "cargo", "-Zscript", "generate-lockfile", "--manifest-path", "s.rs")
	if res.exitCode != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", res.exitCode, res.stderr)
	}
	if want := "ossprey: warning: Cargo.lock not checked after `cargo -Zscript generate-lockfile --manifest-path s.rs` (a cargo script keeps it in the build directory); cargo's changes are kept"; !strings.Contains(res.stderr, want) {
		t.Errorf("stderr lacks %q:\n%s", want, res.stderr)
	}
	var locked bool
	for _, kv := range env {
		if home, ok := strings.CutPrefix(kv, "CARGO_HOME="); ok {
			_ = filepath.WalkDir(filepath.Join(home, "build"), func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.Name() == "Cargo.lock" {
					data, _ := os.ReadFile(p)
					locked = locked || strings.Contains(string(data), "name = \"itoa\"")
				}
				return nil
			})
		}
	}
	if !locked {
		t.Error("cargo wrote no lock for the script under its build directory")
	}
}
