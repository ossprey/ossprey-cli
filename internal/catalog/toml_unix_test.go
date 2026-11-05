//go:build !windows

package catalog

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO named like a manifest would block the open forever, so it is refused without being opened.
func TestReadTOMLRefusesAFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Cargo.toml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readTOML(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || err.Error() != "read "+path+": not a regular file" {
			t.Errorf("readTOML() error = %v, want the regular-file refusal naming %s", err, path)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readTOML() blocked on a FIFO")
	}
}
