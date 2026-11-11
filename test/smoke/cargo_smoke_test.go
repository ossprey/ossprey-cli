//go:build smoke

// The cargo forwarder against the real cargo and a fake API: install is blocked before it builds, and the commands that only lock are refused.

package smoke

import (
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

const smokeManifest = "[package]\nname = \"ossprey-smoke\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n"

// In gating mode add, update, generate-lockfile and fetch exit 2 before cargo runs or the API is asked, leaving the project as it was, and passive hands them to cargo.
func TestCargoLockingCommandsAreRefused(t *testing.T) {
	// The fake cargo is a shell script that records what reaches it, so only POSIX checks that cargo never ran.
	posix := runtime.GOOS != "windows"
	bin, path := t.TempDir(), os.Getenv("PATH")
	if posix {
		if err := os.WriteFile(filepath.Join(bin, "cargo"), []byte("#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/ran\"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		path = bin + string(os.PathListSeparator) + path
	}
	api := newFakeAPI(t, "")
	env := forwardEnv(t.TempDir(), api.URL, path)
	dir := t.TempDir()
	lock := "version = 4\n"
	for name, data := range map[string]string{"Cargo.toml": smokeManifest, "Cargo.lock": lock} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "itoa"}, {"add", "--dry-run", "itoa"}, {"update"}, {"generate-lockfile"}, {"fetch"}} {
		res := runForwardEnv(t, dir, env, binPath, append([]string{"cargo"}, args...)...)
		want := "error: did not run `cargo " + strings.Join(args, " ") + "`: ossprey does not check `cargo " + args[0] + "` yet"
		if res.exitCode != 2 || !strings.Contains(res.stderr, want) {
			t.Errorf("cargo %v: exit %d, want 2 and %q\nstderr: %s", args, res.exitCode, want, res.stderr)
		}
	}
	for name, want := range map[string]string{"Cargo.toml": smokeManifest, "Cargo.lock": lock} {
		if got, _ := os.ReadFile(filepath.Join(dir, name)); string(got) != want {
			t.Errorf("%s = %q, want it untouched", name, got)
		}
	}
	if n, _ := api.stats(); n != 0 {
		t.Errorf("%d API requests, want none", n)
	}
	if !posix {
		return
	}
	if ran, err := os.ReadFile(filepath.Join(bin, "ran")); err == nil {
		t.Errorf("cargo ran: %s", ran)
	}
	res := runForwardEnv(t, dir, append(env, "OSSPREY_PASSIVE=1"), binPath, "cargo", "update")
	if ran, _ := os.ReadFile(filepath.Join(bin, "ran")); res.exitCode != 0 || string(ran) != "update\n" || strings.Contains(res.stderr, "ossprey:") {
		t.Errorf("passive cargo update: exit %d, cargo ran %q, want 0 and update alone\nstderr: %s", res.exitCode, ran, res.stderr)
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
