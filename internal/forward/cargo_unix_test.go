//go:build !windows

package forward

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A Cargo.lock that is a FIFO or a link to a device is never read, so a passive run whose cargo failed at once neither blocks nor reads without end (OSS-2553).
func TestRunCargo_PassiveReadsOnlyARegularLock(t *testing.T) {
	for name, mk := range map[string]func(string) error{
		"a FIFO":                 func(p string) error { return syscall.Mkfifo(p, 0o644) },
		"a symlink to /dev/zero": func(p string) error { return os.Symlink("/dev/zero", p) },
	} {
		t.Run(name, func(t *testing.T) {
			_, ws := cargoProject(t)
			if err := mk(ws.Lock); err != nil {
				t.Skipf("cannot make the lock: %v", err)
			}
			// Releases a reader blocked on the FIFO, so a failure ends the test instead of hanging it.
			t.Cleanup(func() {
				if f, err := os.OpenFile(ws.Lock, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					f.Close()
				}
			})
			// cargo 1.99.1 fails `add nosuchcrate` before it opens the lock.
			exit101 := errors.New("exit status 101")
			swap(t, func(context.Context, string, []string) error { return exit101 }, cleanSBOM)
			type result struct {
				out string
				err error
			}
			done := make(chan result, 1)
			go func() {
				out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "nosuchcrate"}, Passive: true})
				done <- result{out, err}
			}()
			select {
			case r := <-done:
				want := "ossprey: warning: could not post scan (read " + ws.Lock + ": not a regular file); the install was not blocked (passive)\n"
				if !errors.Is(r.err, exit101) || r.out != want {
					t.Errorf("Run = %v, output %q; want cargo's error and %q", r.err, r.out, want)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("Run did not return")
			}
		})
	}
}

// cargo 1.99.1 reads a --config or level config that is a FIFO, which ossprey never opens, so it counts as one that may move the lock, while cargo install reads its config twice and installs from crates.io once a pipe runs dry (OSS-2553).
func TestCargoConfigThatIsAFIFOMayMoveTheLock(t *testing.T) {
	assertIrregularConfig(t, func(p string) error { return syscall.Mkfifo(p, 0o644) })
}

// cargo metadata is handed no --config naming a file, in any spelling: it would empty a one-shot pipe before the command reads it, and on macOS read a /dev/fd/N regular file to the end of the offset cargo shares (OSS-2553).
func TestWithoutConfigFiles(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Skipf("cannot make a FIFO: %v", err)
	}
	writeFile(t, filepath.Join(dir, "c.toml"), "net.retry = 2\n")
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "c.toml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := "/dev/fd/" + strconv.Itoa(int(f.Fd()))
	in := []string{"+nightly", "--config", "fifo", "--config=fifo", "--config", "c.toml", "--config=" + filepath.Join(dir, "c.toml"), "--config", fd, "--config=d", "--config", "k=v", "--config", filepath.Join(dir, "fifo"), "--config=/dev/null", "--config", "nosuch.toml", "-Z", "x", "--", "--config", "fifo"}
	want := []string{"+nightly", "--config=d", "--config", "k=v", "--config", "nosuch.toml", "-Z", "x", "--", "--config", "fifo"}
	if got := withoutConfigFiles(in, dir); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A `--config <(...)` pipe the forwarder inherits, before or after the verb, may move the lock, so the workspace is refused before cargo metadata could read it, and the pipe is left whole (OSS-2553).
func TestReadCargoWorkspaceLeavesAPipedConfigToCargo(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo not installed")
	}
	unsetEnv(t, "CARGO_RESOLVER_LOCKFILE_PATH")
	t.Setenv("CARGO_HOME", t.TempDir())
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Cargo.toml"), "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	if err := os.Mkdir(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "src", "lib.rs"), "")
	t.Chdir(dir)
	const config = "resolver.lockfile-path = \"moved/Cargo.lock\"\n"
	for _, spell := range []func(string) []string{
		func(p string) []string { return []string{"--config", p, "generate-lockfile"} },
		func(p string) []string { return []string{"--config=" + p, "generate-lockfile"} },
		func(p string) []string { return []string{"generate-lockfile", "--config", p} },
		func(p string) []string { return []string{"generate-lockfile", "--config=" + p} },
	} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		// Children inherit it, as they inherit the fd a shell opens for <(...).
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, r.Fd(), syscall.F_SETFD, 0); errno != 0 {
			t.Fatal(errno)
		}
		if _, err := w.WriteString(config); err != nil {
			t.Fatal(err)
		}
		w.Close()
		args := spell("/dev/fd/" + strconv.Itoa(int(r.Fd())))
		if _, err := readCargoWorkspace(context.Background(), args); !errors.Is(err, errLockfileMoved) {
			t.Errorf("cargo %v: err = %v, want errLockfileMoved", args, err)
		}
		left, _ := io.ReadAll(r)
		r.Close()
		if string(left) != config {
			t.Errorf("cargo %v: the pipe holds %q after cargo metadata, want %q left for cargo", args, left, config)
		}
	}
}

// cat cfg | cargo --config /dev/stdin install x goes to crates.io with cargo 1.99.1 whatever cfg sets, since cargo install reads the pipe again once it is empty, so the crate is checked and the pipe left unread (OSS-2553).
func TestCargoInstallFromAPipedConfigIsChecked(t *testing.T) {
	for _, cfg := range []string{"registry.default = \"corp\"\n", "net.retry = 3\n"} {
		t.Run(strings.TrimSpace(cfg), func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("CARGO_HOME", home)
			unsetEnv(t, "CARGO_REGISTRY_DEFAULT")
			t.Chdir(t.TempDir())
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err := w.WriteString(cfg); err != nil {
				t.Fatal(err)
			}
			w.Close()
			stdin := "/dev/fd/" + strconv.Itoa(int(r.Fd()))
			if _, err := os.Stat(stdin); err != nil {
				t.Skipf("no %s: %v", stdin, err)
			}
			if got := cargoDefaultRegistry([]string{"--config", stdin, "install", "x"}); got != "" {
				t.Errorf("a piped --config: %q, want the crates.io crate checked", got)
			}
			if err := os.Symlink(stdin, filepath.Join(home, "config.toml")); err != nil {
				t.Fatal(err)
			}
			if got := cargoDefaultRegistry([]string{"install", "x"}); got != "" {
				t.Errorf("CARGO_HOME's config linked to a pipe: %q, want the crates.io crate checked", got)
			}
			if left, err := io.ReadAll(r); err != nil || string(left) != cfg {
				t.Errorf("the pipe holds %q (%v), want %q left for cargo", left, err, cfg)
			}
		})
	}
}

// A name starting with `..` is inside the working directory, so it is shown relative to whichever spelling of it holds the path.
func TestDisplayPathReadsADotDotNameAsInside(t *testing.T) {
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot link: %v", err)
	}
	t.Chdir(link)
	for _, base := range []string{link, real} {
		if got, want := displayPath(filepath.Join(base, "..crate", "Cargo.toml")), filepath.Join("..crate", "Cargo.toml"); got != want {
			t.Errorf("under %s: %q, want %q", base, got, want)
		}
	}
}
