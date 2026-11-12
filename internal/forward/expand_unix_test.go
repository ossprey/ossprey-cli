//go:build !windows

package forward

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// `uvx --config-file <(...)` checks the named packages with one line saying the config is a pipe, and uvx still reads all of it.
func TestRun_UVConfigPipeIsLeftForTheRun(t *testing.T) {
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not on PATH")
	}
	fifo := filepath.Join(t.TempDir(), "uv.toml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	t.Setenv("UV_CONFIG_FILE", "")
	t.Setenv("UV_CACHE_DIR", t.TempDir())
	t.Setenv("UV_TOOL_DIR", t.TempDir())
	body := "index-url = \"https://top.example/simple\"\n"
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

	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	swapExpand(t, expandInstall)
	args := []string{"--config-file", fifo, "cowsay==6.1"}
	out, err := quietOutput(t, warn.NewContext(context.Background(), false), Options{Bin: "uvx", Args: args})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := fmt.Sprintf("ossprey: warning: could not resolve the dependencies of cowsay (uv config %s is a pipe, and reading it would consume it before uv does); checking the named packages only\n", fifo)
	if !strings.Contains(out, want) {
		t.Errorf("output = %q, want the line %q", out, want)
	}
	if !ex.called || !reflect.DeepEqual(ex.args, args) {
		t.Errorf("exec = %v (called=%v), want uvx %v", ex.args, ex.called, args)
	}
	select {
	case <-opened:
		t.Fatal("the pipe was opened before the run")
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
		t.Errorf("uvx would read %q, %v, want %q", data, err, body)
	}
	if err := <-written; err != nil {
		t.Error(err)
	}
}
