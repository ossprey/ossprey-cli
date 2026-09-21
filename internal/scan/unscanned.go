package scan

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Manifests for ecosystems Ossprey does not catalogue. Their presence means the
// scan did not cover the whole tree, which is what stops the verdict being clean.
var unscannedManifests = []string{"Cargo.lock", "Cargo.toml"}

var unscannedSkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
	"target":       true,
	".venv":        true,
}

// HasUnscannedManifests reports whether the tree holds a manifest Ossprey cannot
// catalogue. It drives the verdict rather than a message: what was actually
// scanned is on the dashboard, so the CLI's job is to not claim a clean bill of
// health for a tree it only partly read.
func HasUnscannedManifests(ctx context.Context, root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Swallowing this silently would repeat the bug this function exists to
		// fix: an unreadable subtree could hide a manifest and the scan would
		// claim full coverage.
		if err != nil {
			warn.Add(ctx, unreadableEntry(relTo(root, path), err))
			return nil //nolint:nilerr // best-effort: keep walking the rest
		}
		if d.IsDir() {
			if unscannedSkipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		for _, n := range unscannedManifests {
			if d.Name() == n {
				found = true
				return fs.SkipAll
			}
		}
		return nil
	})
	return found
}

func relTo(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(rel)
}

// unreadableEntry reports a subtree the walk could not enter.
func unreadableEntry(path string, err error) warn.Entry {
	return warn.Entry{
		Class: "unscanned-walk",
		One:   fmt.Sprintf("could not check %s for manifests, so this scan's coverage is not certain", path),
		Many:  "could not check %d paths for manifests, so this scan's coverage is not certain",
		Item:  fmt.Sprintf("%s: %v", path, err),
	}
}
