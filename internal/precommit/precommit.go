// Package precommit extracts the dependency delta introduced by the git
// index: the packages that a staged change to a dependency manifest or
// lockfile ADDS or VERSION-BUMPS relative to HEAD. It is a pure library —
// no API calls, no cobra — used by the `ossprey precommit` hook command.
//
// Mechanism: enumerate staged manifest/lockfile changes, materialize the
// STAGED blobs and the HEAD blobs into two temp trees (preserving relative
// paths), catalog both trees in no-exec/offline mode, and diff the package
// sets. Removals are ignored: a pre-commit malware gate only cares about
// what the commit introduces.
package precommit

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/catalog"
)

// Package is one dependency introduced (or version-changed) by the staged
// diff — enough for a caller to build a purl (pkg:<type>/<name>@<version>)
// and report "package X (from package-lock.json)".
type Package struct {
	// Type is the OSSBOM ecosystem: "npm" or "pypi".
	Type string
	// Name is the package name as cataloged.
	Name string
	// Version may be empty when the manifest only declares a range and no
	// lockfile pins it.
	Version string
	// Path is the repo-relative manifest/lockfile the package was parsed
	// from, slash-separated (e.g. "web/package-lock.json").
	Path string
}

// Delta is the set of packages present in the staged (index) manifest set
// but not in the HEAD set, keyed by (type, name, version).
type Delta struct {
	Packages []Package
}

// catalogFn is a test seam for the tree cataloging step.
var catalogFn = catalog.Catalog

// StagedDelta computes the dependency delta of the git index vs HEAD for the
// repository at repoDir. On an unborn branch (initial commit) everything
// staged counts as added. Cataloging is pure parsing: it never shells out to
// a package manager and never touches the network.
func StagedDelta(ctx context.Context, repoDir string) (Delta, error) {
	hasHead := gitHasHead(ctx, repoDir)

	paths, err := stagedManifestPaths(ctx, repoDir, hasHead)
	if err != nil {
		return Delta{}, err
	}
	if len(paths) == 0 {
		return Delta{}, nil
	}

	tmp, err := os.MkdirTemp("", "ossprey-precommit-")
	if err != nil {
		return Delta{}, fmt.Errorf("precommit: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	stagedRoot := filepath.Join(tmp, "staged")
	headRoot := filepath.Join(tmp, "head")
	for _, d := range []string{stagedRoot, headRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return Delta{}, fmt.Errorf("precommit: temp tree: %w", err)
		}
	}

	for _, p := range paths {
		// Staged (index) content — the exact bytes this commit would record,
		// which may differ from the worktree file.
		blob, err := gitShow(ctx, repoDir, ":"+p)
		if err != nil {
			return Delta{}, fmt.Errorf("precommit: read staged %s: %w", p, err)
		}
		if err := writeTreeFile(stagedRoot, p, blob); err != nil {
			return Delta{}, err
		}
		if !hasHead {
			continue
		}
		// HEAD content; absent from HEAD (newly added file) → no file at all
		// in the head tree, so every package it declares reads as added.
		if blob, err := gitShow(ctx, repoDir, "HEAD:"+p); err == nil {
			if err := writeTreeFile(headRoot, p, blob); err != nil {
				return Delta{}, err
			}
		}
	}

	// No-exec + no version lookup: a pre-commit hook must be fast, offline,
	// and must never run npm/uv against a synthetic tree.
	opts := catalog.Options{SkipVersionLookup: true, NoExec: true}
	stagedPkgs, err := catalogFn(ctx, stagedRoot, opts)
	if err != nil {
		return Delta{}, fmt.Errorf("precommit: catalog staged tree: %w", err)
	}
	headPkgs, err := catalogFn(ctx, headRoot, opts)
	if err != nil {
		return Delta{}, fmt.Errorf("precommit: catalog head tree: %w", err)
	}

	return diffPackages(stagedPkgs, headPkgs, stagedRoot, paths), nil
}

// diffPackages returns the staged packages absent from head, keyed by
// (type, name, version). Mirroring catalog's mergeVersionless convention, a
// versionless staged entry (an unpinned manifest range) is treated as
// already-present when HEAD carries the same (type, name) at any version —
// it is a lower-fidelity view of the same package, not a new one.
func diffPackages(staged, head []catalog.Package, stagedRoot string, repoPaths []string) Delta {
	// Longest-first so a nested manifest (web/package-lock.json) wins over a
	// root one (package-lock.json) when both are suffixes of a location.
	known := append([]string(nil), repoPaths...)
	sort.Slice(known, func(a, b int) bool { return len(known[a]) > len(known[b]) })

	exact := make(map[string]struct{}, len(head))
	names := make(map[string]struct{}, len(head))
	for _, p := range head {
		exact[pkgKey(p.Type, p.Name, p.Version)] = struct{}{}
		names[nameKey(p.Type, p.Name)] = struct{}{}
	}

	var out []Package
	seen := map[string]struct{}{}
	for _, p := range staged {
		if p.Local {
			continue // the repo's own path/workspace code, never a registry package
		}
		if _, ok := exact[pkgKey(p.Type, p.Name, p.Version)]; ok {
			continue
		}
		if p.Version == "" {
			if _, ok := names[nameKey(p.Type, p.Name)]; ok {
				continue
			}
		}
		key := pkgKey(p.Type, p.Name, p.Version)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, Package{
			Type:    p.Type,
			Name:    p.Name,
			Version: p.Version,
			Path:    repoRelLocation(p.Locations, stagedRoot, known),
		})
	}

	sort.Slice(out, func(a, b int) bool {
		if out[a].Type != out[b].Type {
			return out[a].Type < out[b].Type
		}
		if out[a].Name != out[b].Name {
			return out[a].Name < out[b].Name
		}
		return out[a].Version < out[b].Version
	})
	return Delta{Packages: out}
}

// pkgKey matches catalog's dedup identity: (type, normalized name, version).
func pkgKey(t, name, version string) string {
	return nameKey(t, name) + "@" + version
}

func nameKey(t, name string) string {
	return t + "@" + strings.ToLower(strings.TrimSpace(name))
}

// repoRelLocation maps a cataloged location back to its repo-relative path.
//
// The temp tree preserves repo-relative layout, so a file's path under the
// tree root IS its repo path. But the form the resolver reports varies:
// relative to the scan root on POSIX, absolute on Windows — and on Windows
// the resolver's absolute path can disagree with our os.MkdirTemp root in
// spelling alone: 8.3 short names (C:\Users\RUNNER~1 vs C:\Users\runneradmin
// on GitHub runners, where %TMP% is the short form), letter case, or symlink
// resolution. Reconstructing via filepath.Rel against the root broke on
// exactly that (OSS-1564 Windows CI: a ..-laden path instead of
// "package-lock.json").
//
// So don't reconstruct from the root at all: every cataloged file is one we
// materialized, so match the location's slash-normalized tail against the
// known repo paths (longest-first, case-insensitively — the tail's spelling
// is ours, only the root prefix is untrusted). The Rel fallback remains for
// the never-expected case of a location matching no known path.
func repoRelLocation(locs []string, root string, knownLongestFirst []string) string {
	for _, l := range locs {
		if l == "" {
			continue
		}
		nl := strings.TrimPrefix(strings.ReplaceAll(l, `\`, "/"), "./")
		for _, p := range knownLongestFirst {
			if strings.EqualFold(nl, p) {
				return p
			}
			if len(nl) > len(p) && nl[len(nl)-len(p)-1] == '/' &&
				strings.EqualFold(nl[len(nl)-len(p):], p) {
				return p
			}
		}
		if filepath.IsAbs(l) {
			if rel, err := filepath.Rel(root, l); err == nil {
				return filepath.ToSlash(rel)
			}
		}
		return filepath.ToSlash(strings.TrimPrefix(l, "/"))
	}
	return ""
}

// stagedManifestPaths lists the dependency manifests/lockfiles changed in the
// index: added, copied, modified, or renamed (deletions are ignored — a
// removed manifest introduces nothing). On an unborn branch there is no HEAD
// to diff against, so everything staged counts as added.
func stagedManifestPaths(ctx context.Context, repoDir string, hasHead bool) ([]string, error) {
	var raw []byte
	var err error
	if hasHead {
		raw, err = gitOutput(ctx, repoDir, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
	} else {
		raw, err = gitOutput(ctx, repoDir, "ls-files", "--cached", "-z")
	}
	if err != nil {
		return nil, fmt.Errorf("precommit: list staged files: %w", err)
	}

	var out []string
	for _, p := range strings.Split(string(raw), "\x00") {
		if p == "" {
			continue
		}
		if isVendoredPath(p) {
			continue
		}
		if isManifestPath(p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// isManifestPath reports whether the repo-relative path (slash-separated, as
// git emits it) is a dependency manifest/lockfile that internal/catalog can
// parse without shelling out. Mirrors catalog's coverage — syft's python
// cataloger (**/*requirements*.txt, poetry.lock, Pipfile.lock, setup.py,
// uv.lock, pdm.lock), syft's JS lock cataloger (package-lock.json, yarn.lock,
// pnpm-lock.yaml), and our pyproject/package.json direct-deps parsers. A bare
// Pipfile is deliberately absent: no cataloger parses it.
func isManifestPath(p string) bool {
	base := path.Base(p)
	switch base {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"pyproject.toml", "poetry.lock", "Pipfile.lock", "uv.lock",
		"pdm.lock", "setup.py":
		return true
	}
	// Matches syft's "**/*requirements*.txt" glob.
	return strings.HasSuffix(base, ".txt") && strings.Contains(strings.ToLower(base), "requirements")
}

// isVendoredPath mirrors catalog.isVendoredPath: anything inside a vendored
// dependency tree is skipped.
func isVendoredPath(p string) bool {
	return strings.Contains(filepath.ToSlash(p), "node_modules/")
}

// writeTreeFile writes blob at root/<repoRelPath>, creating parent dirs.
func writeTreeFile(root, repoRelPath string, blob []byte) error {
	dst := filepath.Join(root, filepath.FromSlash(repoRelPath))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("precommit: temp tree: %w", err)
	}
	if err := os.WriteFile(dst, blob, 0o644); err != nil {
		return fmt.Errorf("precommit: write %s: %w", repoRelPath, err)
	}
	return nil
}

// gitHasHead reports whether HEAD resolves to a commit (false on the unborn
// branch of an initial commit).
func gitHasHead(ctx context.Context, repoDir string) bool {
	_, err := gitOutput(ctx, repoDir, "rev-parse", "--verify", "-q", "HEAD")
	return err == nil
}

// gitShow returns the blob content for a git revision:path spec (":p" for the
// index, "HEAD:p" for the last commit).
func gitShow(ctx context.Context, repoDir, spec string) ([]byte, error) {
	return gitOutput(ctx, repoDir, "show", spec)
}

// gitOutput runs git -C repoDir with args and returns stdout. Git is
// guaranteed present in a pre-commit hook context.
func gitOutput(ctx context.Context, repoDir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoDir}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
