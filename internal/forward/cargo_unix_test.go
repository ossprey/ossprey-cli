//go:build !windows

package forward

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
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

// A mirror base another user could write to would let a planted link lead cargo add into the project, so it is refused (OSS-2553).
func TestCargoMirrorBaseMustBePrivate(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	if _, err := cargoMirrorBase(); err != nil {
		t.Fatalf("a new base: %v", err)
	}
	if err := os.Chmod(filepath.Join(cache, "ossprey"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := cargoMirrorBase(); err == nil || !strings.Contains(err.Error(), "is not a directory only you can write to") {
		t.Errorf("a base others may write to: %v", err)
	}
}

// A manifest that cannot be staged beside itself lands nothing, not the lock staged before it either, and leaves no staged file behind (OSS-2553).
func TestRunCargoAdd_StagingFailureLandsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a directory without write permission")
	}
	root, ws := cargoProject(t)
	writeFile(t, ws.Lock, "version = 4\n# before\n")
	swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock})
	swap(t, nil, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return cleanCrates(), nil })
	noLanding(t)
	member := filepath.Dir(ws.Manifests[1])
	if err := os.Chmod(member, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(member, 0o755) })
	before := projectState(t, root)
	lock, err := os.Stat(ws.Lock)
	if err != nil {
		t.Fatal(err)
	}
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
	if err == nil || !strings.HasPrefix(err.Error(), "could not write "+filepath.Join("a", "Cargo.toml")+" (") || !strings.HasSuffix(err.Error(), "permission denied); the project was not changed") || out != "" {
		t.Errorf("Run = %v, output %q; want the manifest's staging error alone", err, out)
	}
	if !reflect.DeepEqual(projectState(t, root), before) {
		t.Error("the project changed")
	}
	if now, err := os.Stat(ws.Lock); err != nil || !os.SameFile(lock, now) {
		t.Errorf("the lock was replaced (%v)", err)
	}
}

// A link planted at a Cargo.toml during the scan stops the landing before anything is staged through it, so nothing is written outside the project (OSS-2553).
func TestRunCargoAdd_StagesNothingThroughALinkPlantedDuringTheScan(t *testing.T) {
	needSymlinks(t)
	if os.Geteuid() == 0 {
		t.Skip("root writes to a directory without write permission")
	}
	root, ws := cargoProject(t)
	writeFile(t, ws.Lock, "version = 4\n# before\n")
	swapCargo(t, &fakeCargo{t: t, root: root, lock: evilLock})
	swap(t, nil, cleanSBOM)
	noLanding(t)
	member := ws.Manifests[1]
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "Cargo.toml")
	writeFile(t, outside, readFile(t, member))
	if err := os.Chmod(outsideDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(outsideDir, 0o755) })
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
		if err := os.Remove(member); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, member); err != nil {
			t.Fatal(err)
		}
		return cleanCrates(), nil
	})
	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
	if want := filepath.Join("a", "Cargo.toml") + " changed while ossprey checked it, so nothing was written; run the command again"; err == nil || err.Error() != want || out != "" {
		t.Errorf("Run = %v, output %q; want %q alone", err, out, want)
	}
	if entries, _ := os.ReadDir(outsideDir); len(entries) != 1 || readFile(t, outside) != memberManifest {
		t.Errorf("outside the project now holds %v, want its one file untouched", entries)
	}
}

const cargoChildHelperEnv = "OSSPREY_TEST_CARGO_CHILD"

// TestCargoChildHelperProcess is not a test: TestCargoChildInterrupted runs it in a process group of its own to signal a real cargo child.
func TestCargoChildHelperProcess(t *testing.T) {
	verb := os.Getenv(cargoChildHelperEnv)
	if verb == "" {
		return
	}
	ws := cargoWorkspace{Lock: filepath.Join(os.Getenv("HELPER_PROJECT"), "Cargo.lock")}
	var err error
	switch verb {
	case "fetch":
		err = fetchCheckedLock(context.Background(), "cargo fetch", []string{"fetch"}, ws, []byte("version = 4\n"))
	case "add":
		err = cargoAddInHelper(os.Getenv("HELPER_PROJECT"))
	default:
		_, err, _ = resolveCargoLock(context.Background(), []string{verb}, ws, cargoFile{path: ws.Lock})
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if st, ok := ee.Sys().(syscall.WaitStatus); ok && st.Signaled() {
			fmt.Println("cargo died by", st.Signal())
			os.Exit(0)
		}
	}
	fmt.Println("cargo returned", err)
	os.Exit(0)
}

// cargoAddInHelper runs cargo add -p a in a mirror of the workspace at project, which the helper's working directory is, answering cargo's version and metadata itself.
func cargoAddInHelper(project string) error {
	ws := cargoWorkspace{
		Lock:      filepath.Join(project, "Cargo.lock"),
		Manifests: []string{filepath.Join(project, "Cargo.toml"), filepath.Join(project, "a", "Cargo.toml")},
		ConfigDir: project,
	}
	cargoVersionFn = func(context.Context, string, []string) (string, error) { return cargo199, nil }
	cargoMetadataFn = func(_ context.Context, dir string, _ []string, _ string) (cargoWorkspace, error) {
		return mirroredWorkspace(dir, ws), nil
	}
	var before []cargoFile
	for _, p := range append([]string{ws.Lock}, ws.Manifests...) {
		f, err := readCargoState(p)
		if err != nil {
			return err
		}
		before = append(before, f)
	}
	_, runErr, err := resolveCargoAdd(context.Background(), []string{"add", "-p", "a", "evil"}, ws, before, cargo199)
	if runErr != nil {
		return runErr
	}
	return err
}

// Interrupted while a cargo child runs, ossprey outlives it, removes its scratch copy of the lock or its mirror and reports cargo's death by the signal, passing on one sent to ossprey alone (OSS-2553).
func TestCargoChildInterrupted(t *testing.T) {
	for _, tc := range []struct {
		verb string
		// group sends the signal to the process group, as a terminal's Ctrl-C does, else to ossprey alone.
		group bool
		sig   syscall.Signal
		died  string
	}{
		{"fetch", true, syscall.SIGINT, "cargo died by interrupt"},
		{"update", true, syscall.SIGINT, "cargo died by interrupt"},
		{"fetch", false, syscall.SIGTERM, "cargo died by terminated"},
		{"add", true, syscall.SIGINT, "cargo died by interrupt"},
	} {
		t.Run(fmt.Sprintf("%s %v", tc.verb, tc.sig), func(t *testing.T) {
			verb := tc.verb
			bin, tmp, cache := t.TempDir(), t.TempDir(), t.TempDir()
			started := filepath.Join(bin, "started")
			if err := os.WriteFile(filepath.Join(bin, "cargo"), []byte("#!/bin/sh\n: > '"+started+"'\nexec sleep 30\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			project, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if verb == "add" {
				needSymlinks(t)
				if err := os.Mkdir(filepath.Join(project, "a"), 0o755); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(project, "Cargo.toml"), "[workspace]\nmembers = [\"a\"]\n")
				writeFile(t, filepath.Join(project, "a", "Cargo.toml"), memberManifest)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCargoChildHelperProcess$")
			cmd.Dir = project
			// The mirror goes in the user cache, which is XDG_CACHE_HOME on Linux and under HOME on macOS.
			cmd.Env = append(os.Environ(), cargoChildHelperEnv+"="+verb, "HELPER_PROJECT="+project, "TMPDIR="+tmp,
				"XDG_CACHE_HOME="+cache, "HOME="+cache, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			// A cargo left running holds the output pipe, so a failure ends at the delay rather than with it.
			cmd.WaitDelay = 5 * time.Second
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
			for deadline := time.Now().Add(20 * time.Second); !exists(started); time.Sleep(10 * time.Millisecond) {
				if time.Now().After(deadline) {
					cmd.Process.Kill()
					t.Fatalf("cargo never started\n%s", out.String())
				}
			}
			pid := cmd.Process.Pid
			if tc.group {
				pid = -pid
			}
			if err := syscall.Kill(pid, tc.sig); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil || !strings.Contains(out.String(), tc.died) {
				t.Errorf("ossprey ended with %v, output %q; want it to outlive cargo and print %q", err, out.String(), tc.died)
			}
			if left, _ := os.ReadDir(tmp); len(left) != 0 {
				t.Errorf("left %v in TMPDIR, want the scratch removed", left)
			}
			var left []string
			filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.Name() == "Cargo.toml" {
					left = append(left, p)
				}
				return nil
			})
			if len(left) != 0 {
				t.Errorf("left %v in the user cache, want the mirror removed", left)
			}
		})
	}
}

// Under nohup a hangup reaches neither ossprey nor cargo, which inherits the ignored SIGHUP and finishes (OSS-2553).
func TestCargoChildKeepsAnIgnoredHangupIgnored(t *testing.T) {
	bin, tmp := t.TempDir(), t.TempDir()
	started := filepath.Join(bin, "started")
	if err := os.WriteFile(filepath.Join(bin, "cargo"), []byte("#!/bin/sh\n: > '"+started+"'\nsleep 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", `trap "" HUP; exec "$0" -test.run='^TestCargoChildHelperProcess$'`, os.Args[0])
	cmd.Env = append(os.Environ(), cargoChildHelperEnv+"=fetch", "HELPER_PROJECT="+t.TempDir(), "TMPDIR="+tmp,
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	for deadline := time.Now().Add(20 * time.Second); !exists(started); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("cargo never started\n%s", out.String())
		}
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil || !strings.Contains(out.String(), "cargo returned <nil>") {
		t.Errorf("ended with %v, output %q; want cargo to finish through the hangup", err, out.String())
	}
}
