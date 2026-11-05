//go:build !windows

package catalog

import (
	"errors"
	"os"
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

// A manifest swapped for a FIFO between the stat and the open neither blocks the read nor is read.
func TestReadTOMLRefusesAFIFOSwappedInAfterTheStat(t *testing.T) {
	if err := syscall.Mkfifo(filepath.Join(t.TempDir(), "probe"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	for name, refused := range map[string]func(string) bool{
		"readTOML": func(p string) bool { _, err := readTOML(p); return errors.Is(err, errNotRegular) },
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "Cargo.toml")
			if err := os.WriteFile(path, []byte("[package]\nname = \"a\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			open := openTOML
			t.Cleanup(func() { openTOML = open })
			openTOML = func(p string) (*os.File, error) {
				if err := os.Remove(p); err != nil {
					return nil, err
				}
				if err := syscall.Mkfifo(p, 0o600); err != nil {
					return nil, err
				}
				return open(p)
			}
			done := make(chan bool, 1)
			go func() { done <- refused(path) }()
			select {
			case ok := <-done:
				if !ok {
					t.Error("the FIFO swapped in after the stat was not refused as not a regular file")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("blocked on a FIFO swapped in after the stat")
			}
		})
	}
}
