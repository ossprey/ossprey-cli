//go:build !windows

package catalog

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestDepthProbesRefuseWhatIsNotARegularFile pins that the probes choosing a
// forwarder's depth never open a FIFO, which would block until something
// wrote to it, in front of the install. A refused manifest takes the full
// scan.
func TestDepthProbesRefuseWhatIsNotARegularFile(t *testing.T) {
	for _, name := range []string{"package.json", "pnpm-workspace.yaml", "pyproject.toml"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := syscall.Mkfifo(filepath.Join(dir, name), 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			if !IsWorkspaceRoot(dir) {
				t.Error("IsWorkspaceRoot = false for a FIFO manifest, want true")
			}
			if name != "pnpm-workspace.yaml" && !HasLocalDeps(dir) {
				t.Error("HasLocalDeps = false for a FIFO manifest, want true")
			}
		})
	}
	t.Run("oversized package.json", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), make([]byte, maxManifestBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if !IsWorkspaceRoot(dir) || !HasLocalDeps(dir) {
			t.Error("an oversized package.json must take the full scan")
		}
	})
}
