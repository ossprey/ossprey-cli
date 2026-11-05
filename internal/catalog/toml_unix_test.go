//go:build !windows

package catalog

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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

// A uv config named as a pipe, as `uvx --config-file <(...)` gives, is refused unopened everywhere the dry run looks, so the run still reads it whole.
func TestUVConfigPipeIsLeftForTheRun(t *testing.T) {
	body := "index-url = \"https://top.example/simple\"\n"
	_, noUV := lookTool("uv")
	for name, c := range map[string]struct {
		needsUV bool
		call    func(t *testing.T, fifo string) error
	}{
		"tool-run config": {call: func(t *testing.T, fifo string) error {
			_, err := uvToolRunConfig([]string{"--config-file", fifo}, t.TempDir())
			return err
		}},
		"UV_CONFIG_FILE": {call: func(t *testing.T, fifo string) error {
			t.Setenv("UV_CONFIG_FILE", fifo)
			_, err := uvToolRunConfig(nil, t.TempDir())
			return err
		}},
		"uv cache dir": {needsUV: true, call: func(t *testing.T, fifo string) error {
			_, err := UVCacheDir(context.Background(), []string{"--config-file", fifo})
			return err
		}},
		"uv tool dir": {needsUV: true, call: func(t *testing.T, fifo string) error {
			_, err := UVToolDir(context.Background(), []string{"--config-file", fifo})
			return err
		}},
		"tool-run resolve": {needsUV: true, call: func(t *testing.T, fifo string) error {
			_, err := ResolvePythonInstallWithUV(context.Background(), "", []string{"cowsay==6.1"}, []string{"--config-file", fifo})
			return err
		}},
		"named install resolve": {needsUV: true, call: func(t *testing.T, fifo string) error {
			_, err := ResolvePythonInstallWithUV(context.Background(), t.TempDir(), []string{"cowsay==6.1"}, []string{"--config-file", fifo})
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if c.needsUV && noUV != nil {
				t.Skip("uv not on PATH")
			}
			fifo := filepath.Join(t.TempDir(), "uv.toml")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			t.Setenv("UV_CONFIG_FILE", "")
			// The writer's open returns only once something opens the pipe to read it.
			opened, written := make(chan struct{}), make(chan error, 1)
			go func() {
				w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
				if err != nil {
					written <- err
					return
				}
				close(opened)
				_, err = w.WriteString(body)
				w.Close()
				written <- err
			}()
			done := make(chan error, 1)
			go func() { done <- c.call(t, fifo) }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "uv config "+fifo+" is a pipe") {
					t.Errorf("error = %v, want the pipe refusal naming %s", err, fifo)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("blocked on the pipe")
			}
			select {
			case <-opened:
				t.Error("the pipe was opened before the run")
			default:
			}
			r, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			select {
			case <-opened:
			case <-time.After(10 * time.Second):
				t.Fatal("the writer never reached the pipe")
			}
			if data, err := io.ReadAll(r); err != nil || string(data) != body {
				t.Errorf("the run would read %q, %v, want %q", data, err, body)
			}
			if err := <-written; err != nil {
				t.Error(err)
			}
		})
	}
}
