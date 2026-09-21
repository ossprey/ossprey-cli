package scan

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Unscanned names an ecosystem whose manifests are present in the tree but
// whose dependencies were not catalogued.
type Unscanned struct {
	Ecosystem string   `json:"ecosystem"`
	Manifests []string `json:"manifests"`
}

// Manifests for ecosystems Ossprey does not catalogue. Cargo only: this exists
// to stop a Rust monorepo reading as clean, and the same gap for go and maven
// wants measuring on its own rather than riding along with the Rust work.
var unscannedManifests = map[string][]string{
	"cargo": {"Cargo.lock", "Cargo.toml"},
}

var unscannedSkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	"vendor":       true,
	"target":       true,
	".venv":        true,
}

// DetectUnscanned reports ecosystems whose manifests sit in the tree unread.
// Without it a Rust-and-JS monorepo scans its JS half and prints "No malware
// found", which reads as a clean bill of health for the whole repo. The README
// naming Python and JavaScript is a weaker safeguard than the scan saying so.
func DetectUnscanned(ctx context.Context, root string) []Unscanned {
	found := map[string]map[string]bool{}
	for eco := range unscannedManifests {
		found[eco] = map[string]bool{}
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Swallowing this silently would repeat the bug the whole function
		// exists to fix: an unreadable subtree could hide a manifest and the
		// scan would claim full coverage.
		if err != nil {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			warn.Add(ctx, unreadableEntry(filepath.ToSlash(rel), err))
			return nil //nolint:nilerr // best-effort: keep walking the rest
		}
		if d.IsDir() {
			if unscannedSkipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		for eco, names := range unscannedManifests {
			for _, n := range names {
				if d.Name() != n {
					continue
				}
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					rel = path
				}
				found[eco][filepath.ToSlash(rel)] = true
			}
		}
		return nil
	})

	var out []Unscanned
	for eco, files := range found {
		if len(files) == 0 {
			continue
		}
		list := make([]string, 0, len(files))
		for f := range files {
			list = append(list, f)
		}
		sort.Strings(list)
		out = append(out, Unscanned{Ecosystem: eco, Manifests: list})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ecosystem < out[j].Ecosystem })
	return out
}

// UnscannedNote is the one-line caveat printed beside a clean verdict.
func UnscannedNote(u []Unscanned) string {
	if len(u) == 0 {
		return ""
	}
	parts := make([]string, 0, len(u))
	for _, e := range u {
		parts = append(parts, e.Ecosystem)
	}
	return "Not scanned: " + strings.Join(parts, ", ") +
		" manifests were found. Ossprey catalogues Python and JavaScript, so those dependencies were not checked."
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
