//go:build !windows

package catalog

import (
	"context"
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
