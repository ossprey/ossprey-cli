package catalog

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/anchore/syft/syft/pkg"
)

// hasCargoLock reports whether a Cargo.lock sits beside the manifest at manifestPath.
func hasCargoLock(manifestPath string) bool {
	_, err := os.Stat(filepath.Join(filepath.Dir(manifestPath), "Cargo.lock"))
	return err == nil
}

// fullCommit is a whole git object id, the only rev Cargo.lock would record after '#'.
var fullCommit = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// cargoGitTargets lists the git crates [patch] and [replace] build in place of the crates they name; a path target is the project's own code.
func cargoGitTargets(m cargoManifest) []pkg.RustCargoLockEntry {
	var out []pkg.RustCargoLockEntry
	for _, table := range m.Patch {
		entries, _ := table.(map[string]any)
		for alias, spec := range entries {
			t, _ := spec.(map[string]any)
			source := cargoGitSource(t)
			if source == "" {
				continue
			}
			name := alias
			if real, ok := t["package"].(string); ok && real != "" {
				name = real
			}
			version, _ := t["version"].(string)
			out = append(out, pkg.RustCargoLockEntry{Name: name, Version: cargoExactVersion(version), Source: source})
		}
	}
	for id, spec := range m.Replace {
		t, _ := spec.(map[string]any)
		if source := cargoGitSource(t); source != "" {
			name, version := cargoSpecCrate(id)
			out = append(out, pkg.RustCargoLockEntry{Name: name, Version: version, Source: source})
		}
	}
	return out
}

// cargoGitSource spells a git dependency as Cargo.lock does, or returns "" for any other kind.
func cargoGitSource(spec map[string]any) string {
	git, _ := spec["git"].(string)
	if git == "" {
		return ""
	}
	if rev, _ := spec["rev"].(string); fullCommit.MatchString(strings.ToLower(rev)) {
		git += "#" + strings.ToLower(rev)
	}
	return "git+" + git
}

// cargoSpecCrate reads the crate name and full version a package ID spec such as "foo:1.0.0" or "<url>#foo@1.0.0" names, as Cargo parses it.
func cargoSpecCrate(spec string) (name, version string) {
	id := spec
	if strings.Contains(spec, "://") {
		u, frag, _ := strings.Cut(spec, "#")
		u, _, _ = strings.Cut(u, "?")
		// Without a name in the fragment Cargo takes the URL's last path segment.
		switch {
		case frag == "":
			id = path.Base(u)
		case !strings.ContainsAny(frag, ":@") && strings.IndexFunc(frag, unicode.IsLetter) != 0:
			id = path.Base(u) + "@" + frag
		default:
			id = frag
		}
	}
	name, version = id, ""
	if i := strings.IndexAny(id, ":@"); i >= 0 {
		name, version = id[:i], id[i+1:]
	}
	if !cargoRelease.MatchString(version) {
		version = ""
	}
	return name, version
}
