//go:build !windows

package forward

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// ossprey never opens a --config or CARGO_HOME config that is a FIFO, and cargo 1.99.1 install reads its config twice and installs from crates.io once a pipe runs dry, so the crate is checked (OSS-2553).
func TestCargoInstallChecksACrateWhoseConfigIsAFIFO(t *testing.T) {
	assertIrregularConfig(t, func(p string) error { return syscall.Mkfifo(p, 0o644) })
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
