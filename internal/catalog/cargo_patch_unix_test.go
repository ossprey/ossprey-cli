//go:build !windows

package catalog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

// A Cargo.lock that is a FIFO or a link to a device is never read, so the scan neither blocks nor reads without end, and the patch target goes out (OSS-2099).
func TestCatalogCargoPatchGateReadsOnlyARegularLock(t *testing.T) {
	t.Setenv("CARGO_HOME", t.TempDir())
	for name, mk := range map[string]func(string) error{
		"a FIFO":                 func(p string) error { return syscall.Mkfifo(p, 0o644) },
		"a symlink to /dev/zero": func(p string) error { return os.Symlink("/dev/zero", p) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"Cargo.toml": lockless7})
			if err := mk(filepath.Join(dir, "Cargo.lock")); err != nil {
				t.Skipf("cannot make the lock: %v", err)
			}
			done := make(chan []Package, 1)
			go func() {
				got, err := Catalog(context.Background(), dir, Options{NoExec: true, SkipVersionLookup: true})
				if err != nil {
					t.Errorf("Catalog: %v", err)
				}
				done <- got
			}()
			select {
			case got := <-done:
				want := []string{"serde@1.0.100 Cargo.toml", "serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml"}
				if gotC := cargoComponents(t, got, dir); !slices.Equal(gotC, want) {
					t.Errorf("crates = %v, want %v", gotC, want)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("Catalog did not return")
			}
		})
	}
}

// A FIFO is refused before it is opened, so a writer blocked opening it stays blocked rather than being released into a SIGPIPE (OSS-2553).
func TestReadRegularNeverOpensAFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "Cargo.lock")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("cannot make a FIFO: %v", err)
	}
	opened := make(chan struct{})
	go func() {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Close()
		}
		close(opened)
	}()
	// Releases the writer once the test is done with it.
	t.Cleanup(func() {
		if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			<-opened
			f.Close()
		}
	})
	// Gives the writer time to block in its open.
	time.Sleep(100 * time.Millisecond)
	if _, _, err := ReadRegular(p, maxCargoProofBytes); !errors.Is(err, ErrNotRegular) {
		t.Errorf("ReadRegular = %v, want %v", err, ErrNotRegular)
	}
	if _, ok := readRegularFile(p, maxCargoProofBytes); ok {
		t.Error("readRegularFile read a FIFO")
	}
	select {
	case <-opened:
		t.Error("the FIFO was opened, releasing its writer")
	case <-time.After(200 * time.Millisecond):
	}
}
