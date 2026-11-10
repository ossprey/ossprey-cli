//go:build !windows

package forward

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
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

// A block undoes only the file cargo left at each path: through a link as cargo 1.99.1 writes, and never a file the path reaches only since (OSS-2553).
func TestRunCargoAdd_BlockTouchesOnlyTheFileCargoLeft(t *testing.T) {
	const oldLock = "version = 4\n# before\n"
	added := memberManifest + "\n[dependencies]\nevil = \"1\"\n"
	link := func(t *testing.T, target, p string) {
		t.Helper()
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	isLink := func(t *testing.T, p string) {
		t.Helper()
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s is no longer a link (%v)", p, err)
		}
	}
	for _, tc := range []struct {
		name                 string
		setup, cargo, during func(t *testing.T, root string)
		check                func(t *testing.T, root string)
		want                 string
	}{
		{
			name: "links cargo writes through",
			setup: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "shared.lock"), oldLock)
				link(t, "shared.lock", filepath.Join(root, "Cargo.lock"))
				writeFile(t, filepath.Join(root, "shared.toml"), memberManifest)
				link(t, filepath.Join("..", "shared.toml"), filepath.Join(root, "a", "Cargo.toml"))
			},
			cargo: func(t *testing.T, root string) {
				// cargo writes the lock in place through the link, and replaces the manifest link's target by a rename.
				writeFile(t, filepath.Join(root, "Cargo.lock"), evilLock)
				writeFile(t, filepath.Join(root, "shared.toml.tmp"), added)
				if err := os.Rename(filepath.Join(root, "shared.toml.tmp"), filepath.Join(root, "shared.toml")); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, root string) {
				if got := readFile(t, filepath.Join(root, "shared.lock")); got != oldLock {
					t.Errorf("lock target = %q, want its old bytes", got)
				}
				if got := readFile(t, filepath.Join(root, "shared.toml")); got != memberManifest {
					t.Errorf("manifest target = %q, want its old bytes", got)
				}
				isLink(t, filepath.Join(root, "Cargo.lock"))
				isLink(t, filepath.Join(root, "a", "Cargo.toml"))
			},
			want: "ossprey: undid `cargo add -p a evil`: restored " + filepath.Join("a", "Cargo.toml") + ", restored Cargo.lock\n",
		},
		{
			name: "a lock link retargeted while the check ran",
			setup: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "shared.lock"), oldLock)
				link(t, "shared.lock", filepath.Join(root, "Cargo.lock"))
			},
			cargo: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "Cargo.lock"), evilLock)
			},
			during: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "other.lock"), evilLock)
				link(t, "other.lock", filepath.Join(root, "Cargo.lock"))
			},
			check: func(t *testing.T, root string) {
				for _, f := range []string{"shared.lock", "other.lock"} {
					if got := readFile(t, filepath.Join(root, f)); got != evilLock {
						t.Errorf("%s = %q, want it left alone", f, got)
					}
				}
			},
			want: "ossprey: warning: did not undo `cargo add -p a evil` in Cargo.lock, changed again after cargo exited\n",
		},
		{
			name: "a member directory swapped for a link while the check ran",
			cargo: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "a", "Cargo.toml"), added)
				writeFile(t, filepath.Join(root, "Cargo.lock"), evilLock)
			},
			during: func(t *testing.T, root string) {
				if err := os.Rename(filepath.Join(root, "a"), filepath.Join(root, "a.old")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, "copy"), 0o755); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(root, "copy", "Cargo.toml"), added)
				link(t, "copy", filepath.Join(root, "a"))
			},
			check: func(t *testing.T, root string) {
				for _, d := range []string{"copy", "a.old"} {
					if got := readFile(t, filepath.Join(root, d, "Cargo.toml")); got != added {
						t.Errorf("%s/Cargo.toml = %q, want it left alone", d, got)
					}
				}
			},
			want: "ossprey: warning: did not undo `cargo add -p a evil` in " + filepath.Join("a", "Cargo.toml") + ", changed again after cargo exited\n",
		},
		{
			name: "a lock cargo created through a dangling link",
			setup: func(t *testing.T, root string) {
				link(t, "made.lock", filepath.Join(root, "Cargo.lock"))
			},
			cargo: func(t *testing.T, root string) {
				// cargo creates the link's target, as cargo 1.99.1 does.
				writeFile(t, filepath.Join(root, "Cargo.lock"), evilLock)
			},
			check: func(t *testing.T, root string) {
				if _, err := os.Stat(filepath.Join(root, "made.lock")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the lock cargo created is still there (%v)", err)
				}
				isLink(t, filepath.Join(root, "Cargo.lock"))
			},
			want: "ossprey: undid `cargo add -p a evil`: removed Cargo.lock\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := cargoProject(t)
			if tc.setup != nil {
				tc.setup(t, root)
			}
			swap(t, func(context.Context, string, []string) error {
				tc.cargo(t, root)
				return nil
			}, cleanSBOM)
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) {
				if tc.during != nil {
					tc.during(t, root)
				}
				return evilSBOM(), nil
			})

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("Run = %v, want ErrBlocked", err)
			}
			tc.check(t, root)
			if !strings.Contains(out, tc.want) {
				t.Errorf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
}

// The path is checked again just before the staged copy replaces cargo's file, so a link retargeted while the copy was written is left alone (OSS-2553).
func TestRunCargoAdd_RestoreChecksThePathAgainBeforeReplacing(t *testing.T) {
	const oldLock = "version = 4\n# before\n"
	root, ws := cargoProject(t)
	writeFile(t, filepath.Join(root, "shared.lock"), oldLock)
	if err := os.Symlink("shared.lock", ws.Lock); err != nil {
		t.Fatal(err)
	}
	swap(t, func(context.Context, string, []string) error {
		writeFile(t, ws.Lock, evilLock)
		return nil
	}, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return evilSBOM(), nil })
	swapWriteRestore(t, func(w io.Writer, data []byte) error {
		writeFile(t, filepath.Join(root, "other.lock"), evilLock)
		if err := os.Remove(ws.Lock); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("other.lock", ws.Lock); err != nil {
			t.Fatal(err)
		}
		_, err := w.Write(data)
		return err
	})

	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "-p", "a", "evil"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Run = %v, want ErrBlocked", err)
	}
	for _, f := range []string{"shared.lock", "other.lock"} {
		if got := readFile(t, filepath.Join(root, f)); got != evilLock {
			t.Errorf("%s = %q, want it left alone", f, got)
		}
	}
	if got := dirNames(t, root); !slices.Equal(got, []string{"Cargo.lock", "Cargo.toml", "a", "other.lock", "shared.lock"}) {
		t.Errorf("root holds %v, want no staged copy left", got)
	}
	if want := "ossprey: warning: did not undo `cargo add -p a evil` in Cargo.lock, changed again after cargo exited\n"; !strings.Contains(out, want) || strings.Contains(out, "undid") {
		t.Errorf("output:\n%s\nwant %q and no undo", out, want)
	}
}

// A restore keeps what writing in place keeps, as cargo 1.99.1 writes Cargo.lock: in place where no copy can be staged beside it or the lock has a second name, and with its owner and group (OSS-2553).
func TestRunCargoUpdate_RestoreKeepsWhatAWriteInPlaceKeeps(t *testing.T) {
	const oldLock = "version = 4\n# before\n"
	readOnly := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o755) })
	}
	stat := func(t *testing.T, p string) *syscall.Stat_t {
		t.Helper()
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(*syscall.Stat_t)
	}
	var other uint32
	if groups, err := os.Getgroups(); err == nil {
		for _, g := range groups {
			if g != os.Getegid() {
				other = uint32(g)
			}
		}
	}
	for _, tc := range []struct {
		name string
		skip string
		// setup returns the files that must end up holding the old lock, each still the same file.
		setup func(t *testing.T, root string) []string
		owner *[2]uint32
	}{
		{
			name: "a read-only project directory",
			skip: map[bool]string{true: "root writes into a read-only directory"}[os.Geteuid() == 0],
			setup: func(t *testing.T, root string) []string {
				readOnly(t, root)
				return []string{filepath.Join(root, "Cargo.lock")}
			},
		},
		{
			name: "a lock linked into a read-only directory",
			skip: map[bool]string{true: "root writes into a read-only directory"}[os.Geteuid() == 0],
			setup: func(t *testing.T, root string) []string {
				shared := filepath.Join(root, "shared")
				if err := os.Mkdir(shared, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filepath.Join(root, "Cargo.lock"), filepath.Join(shared, "real.lock")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join("shared", "real.lock"), filepath.Join(root, "Cargo.lock")); err != nil {
					t.Fatal(err)
				}
				readOnly(t, shared)
				return []string{filepath.Join(shared, "real.lock")}
			},
		},
		{
			name: "a lock with a second name",
			setup: func(t *testing.T, root string) []string {
				if err := os.Link(filepath.Join(root, "Cargo.lock"), filepath.Join(root, "Cargo.lock.orig")); err != nil {
					t.Fatal(err)
				}
				return []string{filepath.Join(root, "Cargo.lock"), filepath.Join(root, "Cargo.lock.orig")}
			},
		},
		{
			name: "a lock in a group of the user's other than their own",
			skip: map[bool]string{true: "the user is in no other group"}[other == 0],
			setup: func(t *testing.T, root string) []string {
				if err := os.Chown(filepath.Join(root, "Cargo.lock"), -1, int(other)); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			owner: &[2]uint32{uint32(os.Getuid()), other},
		},
		{
			name: "a lock root restores in a user's tree",
			skip: map[bool]string{false: "needs root"}[os.Geteuid() == 0],
			setup: func(t *testing.T, root string) []string {
				if err := os.Chown(filepath.Join(root, "Cargo.lock"), 65534, 65534); err != nil {
					t.Fatal(err)
				}
				return nil
			},
			owner: &[2]uint32{65534, 65534},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			root, ws := cargoProject(t)
			writeFile(t, ws.Lock, oldLock)
			same := tc.setup(t, root)
			before := map[string]uint64{}
			for _, p := range same {
				before[p] = stat(t, p).Ino
			}
			swap(t, func(context.Context, string, []string) error {
				writeFile(t, ws.Lock, evilLock)
				return nil
			}, cleanSBOM)
			swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return evilSBOM(), nil })

			out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
			if !errors.Is(err, ErrBlocked) {
				t.Fatalf("Run = %v, want ErrBlocked", err)
			}
			if want := "ossprey: undid `cargo update`: restored Cargo.lock\n"; !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
			if got := readFile(t, ws.Lock); got != oldLock {
				t.Errorf("lock = %q, want its old bytes", got)
			}
			for _, p := range same {
				if got := readFile(t, p); got != oldLock || stat(t, p).Ino != before[p] {
					t.Errorf("%s = %q, want the old bytes written into the same file", p, got)
				}
			}
			if st := stat(t, ws.Lock); tc.owner != nil && (st.Uid != tc.owner[0] || st.Gid != tc.owner[1]) {
				t.Errorf("lock owned by %d:%d, want %d:%d", st.Uid, st.Gid, tc.owner[0], tc.owner[1])
			}
			if got := dirNames(t, root); slices.ContainsFunc(got, func(n string) bool { return strings.Contains(n, ".ossprey-") }) {
				t.Errorf("root holds %v, want no staged copy left", got)
			}
		})
	}
}

// A staged copy is removed from the directory it was made in, even one moved while the copy was written (OSS-2553).
func TestRunCargoUpdate_RestoreRemovesItsCopyFromAMovedDirectory(t *testing.T) {
	root, ws := cargoProject(t)
	writeFile(t, ws.Lock, "version = 4\n# before\n")
	swap(t, func(context.Context, string, []string) error {
		writeFile(t, ws.Lock, evilLock)
		return nil
	}, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return evilSBOM(), nil })
	moved := root + ".moved"
	t.Cleanup(func() { os.RemoveAll(moved) })
	swapWriteRestore(t, func(w io.Writer, data []byte) error {
		if err := os.Rename(root, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, ws.Lock, "# another project\n")
		_, err := w.Write(data)
		return err
	})

	out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("Run = %v, want ErrBlocked", err)
	}
	if got := readFile(t, filepath.Join(moved, "Cargo.lock")); got != evilLock {
		t.Errorf("moved lock = %q, want it left alone", got)
	}
	if got := readFile(t, ws.Lock); got != "# another project\n" {
		t.Errorf("new lock = %q, want it left alone", got)
	}
	if got := dirNames(t, moved); !slices.Equal(got, []string{"Cargo.lock", "Cargo.toml", "a"}) {
		t.Errorf("moved directory holds %v, want no staged copy left", got)
	}
	if want := ", changed again after cargo exited\n"; !strings.Contains(out, want) || strings.Contains(out, "undid") {
		t.Errorf("output:\n%s\nwant %q and no undo", out, want)
	}
}
