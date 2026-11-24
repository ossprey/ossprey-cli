package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the temp directory at its real path. macOS keeps it under
// /var, a link to /private/var, and Catalog hands syft the resolved root, so
// a fixture's absolute symlink (spelled through /var) points out of that root
// and syft indexes the link's whole target tree as a second root: it walks
// /private/var, and the test runs until the timeout. A test that needs a
// linked root makes one itself.
func TestMain(m *testing.M) {
	if real, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		os.Setenv("TMPDIR", real)
	}
	os.Exit(m.Run())
}
