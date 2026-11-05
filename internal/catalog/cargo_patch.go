package catalog

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/syft/pkg"
)

// cargoLockGitSources maps each crate name to the git sources the Cargo.lock beside manifestPath records, as a package or an unused patch, or nil without a readable lock.
func cargoLockGitSources(manifestPath string) map[string][]string {
	lockPath := filepath.Join(filepath.Dir(manifestPath), "Cargo.lock")
	if info, err := os.Stat(lockPath); err != nil || info.Size() > maxCargoProofBytes {
		return nil
	}
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil
	}
	type entry struct {
		Name   string `toml:"name"`
		Source string `toml:"source"`
	}
	var lock struct {
		Package []entry `toml:"package"`
		Patch   struct {
			Unused []entry `toml:"unused"`
		} `toml:"patch"`
	}
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil
	}
	out := map[string][]string{}
	for _, e := range append(lock.Package, lock.Patch.Unused...) {
		if strings.HasPrefix(e.Source, "git+") {
			out[e.Name] = append(out[e.Name], e.Source)
		}
	}
	return out
}

// lockRecords reports whether a lock records the git target from its repository, at its commit when the manifest names one.
func lockRecords(locked map[string][]string, t pkg.RustCargoLockEntry) bool {
	repo, rev, _ := strings.Cut(t.Source, "#")
	repo, _, _ = strings.Cut(repo, "?")
	for _, s := range locked[t.Name] {
		lockRepo, commit, _ := strings.Cut(s, "#")
		lockRepo, _, _ = strings.Cut(lockRepo, "?")
		if lockRepo == repo && (rev == "" || commit == rev) {
			return true
		}
	}
	return false
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
	// Cargo ignores a fragment in the URL and builds rev, branch, tag or the default branch.
	git, _, _ = strings.Cut(git, "#")
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
	if !isCargoRelease(version) {
		version = ""
	}
	return name, version
}
