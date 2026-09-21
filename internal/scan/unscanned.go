package scan

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Unscanned names an ecosystem whose manifests are present in the tree but
// whose dependencies were not catalogued.
type Unscanned struct {
	Ecosystem string   `json:"ecosystem"`
	Manifests []string `json:"manifests"`
}

// Manifests for ecosystems Ossprey knows as a purl type but does not catalogue.
// The API already records an UNSUPPORTED finding for these when a component
// reaches it, so staying quiet about a manifest we never opened is the
// inconsistency, not the warning.
var unscannedManifests = map[string][]string{
	"cargo":     {"Cargo.lock", "Cargo.toml"},
	"golang":    {"go.mod", "go.sum"},
	"maven":     {"pom.xml", "build.gradle", "build.gradle.kts"},
	"gem":       {"Gemfile", "Gemfile.lock", "gems.rb", "gems.locked"},
	"composer":  {"composer.json", "composer.lock"},
	"nuget":     {"packages.config"},
	"cocoapods": {"Podfile", "Podfile.lock"},
	"pub":       {"pubspec.yaml", "pubspec.lock"},
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
func DetectUnscanned(root string) []Unscanned {
	found := map[string]map[string]bool{}
	for eco := range unscannedManifests {
		found[eco] = map[string]bool{}
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree is not a scan failure
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
