//go:build !windows

package catalog

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
		// The vendor filter's reads above the scan share the one reader, so they cannot drift from it.
		"readCargoFileAt": func(p string) bool { _, ok := readCargoFileAt(p, filepath.Dir(p)); return !ok },
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

// A uv config the user names may be a pipe, as `uvx --config-file <(...)` gives, and is read within the byte cap.
func TestUVToolRunConfigReadsANamedPipe(t *testing.T) {
	for name, c := range map[string]struct {
		body    string
		refused bool
	}{
		"a config":              {body: "index-url = \"https://top.example/simple\"\n\n[pip]\nindex-url = \"https://pip.example/simple\"\n"},
		"a config over the cap": {body: strings.Repeat("#", maxManifestBytes+1), refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "config.toml")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			t.Setenv("UV_CONFIG_FILE", "")
			go func() {
				if w, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
					w.WriteString(c.body)
					w.Close()
				}
			}()
			scratch := t.TempDir()
			type result struct {
				flags []string
				err   error
			}
			done := make(chan result, 1)
			go func() {
				flags, err := uvToolRunConfig([]string{"--config-file", fifo}, scratch)
				done <- result{flags, err}
			}()
			var got result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("uvToolRunConfig() blocked on a named pipe")
			}
			if c.refused {
				if got.err == nil || !strings.Contains(got.err.Error(), fifo) {
					t.Errorf("uvToolRunConfig() = %v, %v, want a refusal naming %s", got.flags, got.err, fifo)
				}
				return
			}
			stripped := filepath.Join(scratch, "uv.toml")
			if got.err != nil || !reflect.DeepEqual(got.flags, []string{"--config-file", stripped}) {
				t.Fatalf("uvToolRunConfig() = %v, %v, want the stripped copy named", got.flags, got.err)
			}
			if data, _ := os.ReadFile(stripped); !strings.Contains(string(data), "top.example") || strings.Contains(string(data), "pip") {
				t.Errorf("stripped copy:\n%s", data)
			}
		})
	}
}
