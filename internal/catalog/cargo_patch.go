package catalog

import (
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/anchore/syft/syft/pkg"
	"github.com/ossprey/ossprey-cli/internal/registry"
)

// cargoLockGit is what the Cargo.lock beside a manifest records of git crates: each name's packages, and whether its version form-encodes their query.
type cargoLockGit struct {
	sources map[string][]lockedGit
	encoded bool
}

// lockedGit is one git package a Cargo.lock records.
type lockedGit struct{ source, version string }

// cargoLockGitSources reads the git sources the Cargo.lock beside manifestPath records as packages, or none without a readable lock.
func cargoLockGitSources(manifestPath string) cargoLockGit {
	// A FIFO or device named Cargo.lock may never end, so only a regular file is read, and only up to the limit.
	data, ok := readRegularFile(filepath.Join(filepath.Dir(manifestPath), "Cargo.lock"), maxCargoProofBytes)
	if !ok || proofTOMLError(data) != nil {
		return cargoLockGit{}
	}
	type entry struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  string `toml:"source"`
	}
	var lock struct {
		Version int     `toml:"version"`
		Package []entry `toml:"package"`
	}
	if _, err := decodeTOML(data, &lock); err != nil {
		return cargoLockGit{}
	}
	// Cargo writes the query form-encoded from lock version 4 and as written before it.
	out := cargoLockGit{sources: map[string][]lockedGit{}, encoded: lock.Version >= 4}
	// A [[patch.unused]] entry is never sent, yet cargo builds it once a changed requirement reaches its version, so it records nothing.
	for _, e := range lock.Package {
		if strings.HasPrefix(e.Source, "git+") {
			out.sources[e.Name] = append(out.sources[e.Name], lockedGit{e.Source, e.Version})
		}
	}
	return out
}

// lockRecords reports whether the lock records the target as Cargo matches it: the same URL and the same branch, tag or rev once both are read back, at the rev's commit when that is a full one, at a version the target's requirement accepts.
func lockRecords(locked cargoLockGit, t cargoGitTarget) bool {
	if t.unsure {
		return false
	}
	want := t.repo
	if t.selector != "" {
		v := t.value
		if locked.encoded {
			v = url.QueryEscape(v)
		}
		want += "?" + t.selector + "=" + v
	}
	// The manifest's spec is read back from the text Cargo would write for it, as Cargo compares the two.
	repo, ref, _, ok := cargoGitRef(want)
	if !ok {
		return false
	}
	_, rev, _ := strings.Cut(t.Source, "#")
	for _, l := range locked.sources[t.Name] {
		lockRepo, lockRef, commit, ok := cargoGitRef(l.source)
		if ok && lockRepo == repo && lockRef == ref && (rev == "" || commit == rev) && meetsTargetReq(t.req, l.version) {
			return true
		}
	}
	return false
}

// meetsTargetReq reports whether a locked version meets the target's requirement, since cargo fetches the branch afresh for one it does not.
func meetsTargetReq(req, version string) bool {
	if req == "" {
		return true
	}
	match, ok := registry.CargoSatisfies(req, version)
	return match && ok
}

// cargoGitRef reads a git source as Cargo does: the URL before '?', the last branch (or legacy ref), tag or rev in its form-encoded query, and the commit after '#'.
func cargoGitRef(source string) (repo, ref, commit string, ok bool) {
	rest, commit, _ := strings.Cut(source, "#")
	repo, query, _ := strings.Cut(rest, "?")
	for pair := range strings.SplitSeq(query, "&") {
		k, v, _ := strings.Cut(pair, "=")
		k, errK := url.QueryUnescape(k)
		v, errV := url.QueryUnescape(v)
		// Cargo decodes a bad escape leniently, so a lock holding one is not taken to match.
		if errK != nil || errV != nil {
			return "", "", "", false
		}
		switch k {
		case "branch", "ref":
			ref = "branch=" + v
		case "tag", "rev":
			ref = k + "=" + v
		}
	}
	return repo, ref, commit, true
}

// fullCommit is a whole git object id, the only rev Cargo.lock would record after '#'.
var fullCommit = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// cargoGitTarget is a git crate [patch] or [replace] builds, with the branch, tag or rev that selects it.
type cargoGitTarget struct {
	pkg.RustCargoLockEntry
	repo, selector, value string
	// req is the version requirement the spec puts on the crate it builds, empty for none.
	req string
	// unsure is a spec whose lock entry Cargo may not match: a query in the URL, or two selectors or one that is not a string.
	unsure bool
}

// cargoGitTargets lists the git crates [patch] and [replace] build in place of the crates they name; a path target is the project's own code.
func cargoGitTargets(m cargoManifest) []cargoGitTarget {
	var out []cargoGitTarget
	for _, table := range m.Patch {
		entries, _ := table.(map[string]any)
		for alias, spec := range entries {
			t, _ := spec.(map[string]any)
			target, ok := cargoGitSpec(t)
			if !ok {
				continue
			}
			target.Name = alias
			if real, ok := t["package"].(string); ok && real != "" {
				target.Name = real
			}
			target.req, _ = t["version"].(string)
			target.Version = cargoExactVersion(target.req)
			out = append(out, target)
		}
	}
	for id, spec := range m.Replace {
		t, _ := spec.(map[string]any)
		if target, ok := cargoGitSpec(t); ok {
			target.Name, target.Version = cargoSpecCrate(id)
			// Cargo takes only a full version here and fetches afresh for another, so one it reads and we cannot never matches the lock.
			target.req = "=" + target.Version
			target.unsure = target.unsure || target.Version == ""
			out = append(out, target)
		}
	}
	return out
}

// cargoGitSpec reads a git dependency, its source spelled as Cargo.lock does before '?' and after '#', or returns false for any other kind.
func cargoGitSpec(spec map[string]any) (cargoGitTarget, bool) {
	git, _ := spec["git"].(string)
	// Cargo ignores a fragment in the URL and builds rev, branch, tag or the default branch.
	git, _, _ = strings.Cut(git, "#")
	if git == "" {
		return cargoGitTarget{}, false
	}
	t := cargoGitTarget{repo: "git+" + git, unsure: strings.Contains(git, "?")}
	for _, k := range []string{"branch", "tag", "rev"} {
		if v, set := spec[k]; set {
			s, ok := v.(string)
			t.unsure = t.unsure || !ok || t.selector != ""
			t.selector, t.value = k, s
		}
	}
	t.Source = t.repo
	if rev := strings.ToLower(t.value); t.selector == "rev" && fullCommit.MatchString(rev) {
		t.Source += "#" + rev
	}
	return t, true
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
	if !registry.IsCargoRelease(version) {
		version = ""
	}
	return name, version
}
