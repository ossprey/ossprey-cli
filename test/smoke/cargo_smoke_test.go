//go:build smoke

// The cargo forwarder against the real cargo and a fake API: add runs first and is undone on a block, install is blocked before it builds.

package smoke

import (
	"os"
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
