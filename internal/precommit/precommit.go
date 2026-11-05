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
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/trust"
)

// Package is one dependency introduced (or version-changed) by the staged
// diff — enough for a caller to build a purl (pkg:<type>/<name>@<version>)
// and report "package X (from package-lock.json)".
type Package struct {
	// Type is the OSSBOM ecosystem: "npm", "pypi" or "cargo".
	Type string
	// Name is the package name as cataloged.
	Name string
	// Version may be empty when the manifest only declares a range and no
	// lockfile pins it.
	Version string
	// Path is the repo-relative manifest/lockfile the package was parsed
	// from, slash-separated (e.g. "web/package-lock.json").
	Path string
	// Qualifiers mark a git or private-registry crate, which is not the crates.io crate of that name.
	Qualifiers map[string]string
}

// Delta is the set of packages present in the staged (index) manifest set
// but not in the HEAD set, keyed by (type, name, version).
type Delta struct {
	Packages []Package
	// Trusted counts staged packages that would have been new but come from a
	// trusted source (internal/trust), so they are neither in Packages nor sent.
	Trusted int
}

// catalogFn is a test seam for the tree cataloging step.
var catalogFn = catalog.Catalog

// StagedDelta computes the dependency delta of the git index vs HEAD for the
// repository at repoDir. On an unborn branch (initial commit) everything
// staged counts as added. Cataloging is pure parsing: it never shells out to
// a package manager and never touches the network.
//
// Packages the policy trusts are left out of the delta and counted instead.
func StagedDelta(ctx context.Context, repoDir string, policy trust.Policy) (Delta, error) {
	hasHead := gitHasHead(ctx, repoDir)

	paths, err := stagedManifestPaths(ctx, repoDir, hasHead)
	if err != nil {
		return Delta{}, err
	}
	paths = withoutVendoredLocks(ctx, repoDir, paths)
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

	// A member's `workspace = true` pins live in a workspace root the commit may not touch.
	for _, a := range cargoAncestors(paths) {
		if err := writeWorkspaceRoot(ctx, repoDir, ":"+a, stagedRoot, a); err != nil {
			return Delta{}, err
		}
		if hasHead {
			if err := writeWorkspaceRoot(ctx, repoDir, "HEAD:"+a, headRoot, a); err != nil {
				return Delta{}, err
			}
		}
	}

	// No-exec + no version lookup: a pre-commit hook must be fast, offline,
	// and must never run npm/uv against a synthetic tree.
	opts := catalog.Options{SkipVersionLookup: true, NoExec: true, Trust: policy}
	stagedPkgs, err := catalogFn(ctx, stagedRoot, opts)
	if err != nil {
		return Delta{}, fmt.Errorf("precommit: catalog staged tree: %w", err)
	}
	headPkgs, err := catalogFn(ctx, headRoot, opts)
	if err != nil {
		return Delta{}, fmt.Errorf("precommit: catalog head tree: %w", err)
	}

	// A pin changed only in a root's [workspace.dependencies] reaches no manifest in the trees, so the root reports it.
	for _, p := range paths {
		if path.Base(p) == "Cargo.toml" {
			stagedPkgs = append(stagedPkgs, workspacePinChanges(stagedRoot, headRoot, p)...)
		}
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
		exact[pkgKey(p)] = struct{}{}
		names[nameKey(p)] = struct{}{}
	}

	var out []Package
	trusted := 0
	seen := map[string]struct{}{}
	for _, p := range staged {
		if p.Local {
			continue // the repo's own path/workspace code, never a registry package
		}
		key := pkgKey(p)
		if _, ok := exact[key]; ok {
			continue
		}
		if p.Version == "" {
			if _, ok := names[nameKey(p)]; ok {
				continue
			}
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if p.Trusted {
			trusted++
			continue
		}
		out = append(out, Package{
			Type:       p.Type,
			Name:       p.Name,
			Version:    p.Version,
			Path:       repoRelLocation(p.Locations, stagedRoot, known),
			Qualifiers: p.Qualifiers,
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
	return Delta{Packages: out, Trusted: trusted}
}

// pkgKey matches catalog's dedup identity: (type, normalized name, version) plus any source qualifiers.
func pkgKey(p catalog.Package) string {
	return nameKey(p) + "@" + p.Version
}

// nameKey keeps a source-marked crate apart from the crates.io crate of that name, as catalog does.
func nameKey(p catalog.Package) string {
	key := p.Type + "@" + strings.ToLower(strings.TrimSpace(p.Name))
	for _, k := range slices.Sorted(maps.Keys(p.Qualifiers)) {
		key += "?" + k + "=" + p.Qualifiers[k]
	}
	return key
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
		// Unlike diff, ls-files lists only cwd's subtree, cwd-relative; ":/"
		// and --full-name make it the whole index, root-relative, as the
		// ":<path>" reads below expect when repoDir is a subdirectory.
		raw, err = gitOutput(ctx, repoDir, "ls-files", "--cached", "-z", "--full-name", "--", ":/")
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
// pnpm-lock.yaml), syft's Cargo.lock cataloger, and our pyproject/package.json/
// Cargo.toml direct-deps parsers. A bare Pipfile is deliberately absent: no
// cataloger parses it.
func isManifestPath(p string) bool {
	base := path.Base(p)
	switch base {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"pyproject.toml", "poetry.lock", "Pipfile.lock", "uv.lock",
		"pdm.lock", "setup.py", "Cargo.toml", "Cargo.lock":
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

// maxVendorProofs bounds the staged Cargo.lock files tested as vendored copies; the rest are looked up as usual.
const maxVendorProofs = 2048

// maxProofLocks bounds the ancestor directories read as proof, for Cargo.lock and cargo config each.
const maxProofLocks = 64

// cargoConfig is a directory's staged cargo config, nil for none, with ok false when cargo's reading of it is unclear.
type cargoConfig struct {
	doc map[string]any
	ok  bool
}

// withoutVendoredLocks drops the Cargo.lock `cargo vendor` copied with a crate, which no build of the project reads.
func withoutVendoredLocks(ctx context.Context, repoDir string, paths []string) []string {
	var files proofFiles
	locks := map[string]*catalog.CargoLock{}
	lockAt := func(dir string) *catalog.CargoLock {
		if l, ok := locks[dir]; ok || len(locks) >= maxProofLocks {
			return l
		}
		var l *catalog.CargoLock
		// As in the scan's filter, only a lock beside its Cargo.toml in an unmarked directory is a project's.
		_, marked := files[path.Join(dir, ".cargo-checksum.json")]
		if blob, ok := files.read(ctx, repoDir, path.Join(dir, "Cargo.lock"), catalog.CargoProofLimit); ok && files[path.Join(dir, "Cargo.toml")].oid != "" && !marked {
			if parsed, err := catalog.ParseCargoLock(blob); err == nil {
				l = &parsed
			}
		}
		locks[dir] = l
		return l
	}
	configs := map[string]cargoConfig{}
	configAt := func(dir string) (map[string]any, bool) {
		c, ok := configs[dir]
		if !ok && len(configs) < maxProofLocks {
			c = stagedCargoConfig(ctx, repoDir, files, dir)
			configs[dir] = c
		}
		return c.doc, c.ok
	}
	tested := 0
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if dir := path.Dir(p); path.Base(p) == "Cargo.lock" && dir != "." && tested < maxVendorProofs {
			if files == nil {
				files = listProofFiles(ctx, repoDir)
			}
			tested++
			if vendoredCopy(ctx, repoDir, files, dir, lockAt, configAt) {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

// proofBlob is an index entry's blob and size, with no blob for an entry that is not one regular file of known size.
type proofBlob struct {
	oid  string
	size int64
}

// proofFiles maps each index path a vendor proof may read to its blob.
type proofFiles map[string]proofBlob

// listProofFiles lists every Cargo.lock, Cargo.toml, marker and cargo config in the index, then their blob sizes, in two calls.
func listProofFiles(ctx context.Context, repoDir string) proofFiles {
	files := proofFiles{}
	out, err := gitOutput(ctx, repoDir, "ls-files", "-s", "-z", "--full-name", "--",
		":(top,glob)**/Cargo.lock", ":(top,glob)**/Cargo.toml", ":(top,glob)**/.cargo-checksum.json",
		":(top,glob)**/.cargo/config", ":(top,glob)**/.cargo/config.toml")
	if err != nil {
		return files
	}
	var oids []string
	for _, entry := range strings.Split(string(out), "\x00") {
		meta, p, ok := strings.Cut(entry, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			continue
		}
		// A symlink's blob is its target text, which cargo never reads as the file, and a conflicted path has several.
		_, seen := files[p]
		if (f[0] == "100644" || f[0] == "100755") && f[2] == "0" && !seen {
			files[p] = proofBlob{oid: f[1]}
			oids = append(oids, f[1])
		} else {
			files[p] = proofBlob{}
		}
	}
	sizes, err := blobSizes(ctx, repoDir, oids)
	if err != nil {
		return proofFiles{}
	}
	for p, b := range files {
		if size, ok := sizes[b.oid]; ok {
			files[p] = proofBlob{oid: b.oid, size: size}
		} else {
			files[p] = proofBlob{}
		}
	}
	return files
}

// blobSizes asks git for each blob's size in one call, reading none of them.
func blobSizes(ctx context.Context, repoDir string, oids []string) (map[string]int64, error) {
	sizes := map[string]int64{}
	if len(oids) == 0 {
		return sizes, nil
	}
	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "cat-file", "--batch-check")
	cmd.Stdin = strings.NewReader(strings.Join(oids, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		// Each line is "<oid> blob <size>", or "<oid> missing".
		if f := strings.Fields(line); len(f) == 3 && f[1] == "blob" {
			if n, err := strconv.ParseInt(f[2], 10, 64); err == nil {
				sizes[f[0]] = n
			}
		}
	}
	return sizes, nil
}

// read returns the regular file at p, false when it is absent, of another mode, over limit bytes or unreadable.
func (f proofFiles) read(ctx context.Context, repoDir, p string, limit int64) ([]byte, bool) {
	// The object's own size refuses an oversized file before any of it is read.
	if b := f[p]; b.oid != "" && b.size <= limit {
		return readBlob(ctx, repoDir, b.oid, limit)
	}
	return nil, false
}

// readBlob reads the blob oid, false when git fails or the blob passes limit bytes, where it stops git.
func readBlob(ctx context.Context, repoDir, oid string, limit int64) ([]byte, bool) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", repoDir, "cat-file", "blob", oid)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false
	}
	if err := cmd.Start(); err != nil {
		return nil, false
	}
	blob, err := io.ReadAll(io.LimitReader(stdout, limit+1))
	if err != nil || int64(len(blob)) > limit {
		cancel()
		_ = cmd.Wait()
		return nil, false
	}
	return blob, cmd.Wait() == nil
}

// stagedCargoConfig reads dir's .cargo/config or .cargo/config.toml from the index, unclear when both exist or one is not a regular file that parses.
func stagedCargoConfig(ctx context.Context, repoDir string, files proofFiles, dir string) cargoConfig {
	var c cargoConfig
	for _, name := range []string{"config", "config.toml"} {
		p := path.Join(dir, ".cargo", name)
		if _, listed := files[p]; !listed {
			continue
		}
		blob, ok := files.read(ctx, repoDir, p, catalog.CargoManifestLimit)
		if !ok {
			return cargoConfig{}
		}
		doc, err := catalog.ParseCargoConfig(blob)
		if err != nil || c.doc != nil {
			return cargoConfig{}
		}
		c.doc = doc
	}
	c.ok = true
	return c
}

// vendoredCopy reports whether a strict ancestor's staged Cargo.lock locks dir's crate at its marker's .crate checksum and its cargo config vendors crates.io into dir's parent.
func vendoredCopy(ctx context.Context, repoDir string, files proofFiles, dir string, lockAt func(string) *catalog.CargoLock, configAt func(string) (map[string]any, bool)) bool {
	marker, ok := files.read(ctx, repoDir, path.Join(dir, ".cargo-checksum.json"), catalog.CargoProofLimit)
	if !ok {
		return false
	}
	sum := catalog.CargoVendorChecksum(marker)
	if sum == "" {
		return false
	}
	manifest, ok := files.read(ctx, repoDir, path.Join(dir, "Cargo.toml"), catalog.CargoManifestLimit)
	if !ok {
		return false
	}
	name, version := catalog.CargoPackageID(manifest)
	if name == "" || version == "" {
		return false
	}
	for a := dir; a != "."; {
		a = path.Dir(a)
		if l := lockAt(a); l != nil && l.Vendors(name, version, sum) && catalog.CargoVendorSource(a, configAt) == path.Dir(dir) {
			return true
		}
	}
	return false
}

// cargoAncestors lists the unstaged Cargo.toml paths above each staged one, up to the repo root.
func cargoAncestors(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[p] = true
	}
	var out []string
	for _, p := range paths {
		if path.Base(p) != "Cargo.toml" {
			continue
		}
		for dir := path.Dir(p); dir != "."; {
			dir = path.Dir(dir)
			a := path.Join(dir, "Cargo.toml")
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// writeWorkspaceRoot writes the Cargo.toml at spec into root when it exists and declares [workspace].
func writeWorkspaceRoot(ctx context.Context, repoDir, spec, root, repoRelPath string) error {
	blob, err := gitShow(ctx, repoDir, spec)
	if err != nil || !catalog.DeclaresCargoWorkspace(blob) {
		return nil
	}
	return writeTreeFile(root, repoRelPath, blob)
}

// workspacePinChanges returns the exact crates.io pins in the staged [workspace.dependencies] of the Cargo.toml at p that its HEAD copy lacks.
func workspacePinChanges(stagedRoot, headRoot, p string) []catalog.Package {
	staged, err := os.ReadFile(filepath.Join(stagedRoot, filepath.FromSlash(p)))
	if err != nil {
		return nil
	}
	head, _ := os.ReadFile(filepath.Join(headRoot, filepath.FromSlash(p)))
	old := map[string]bool{}
	for _, q := range catalog.CargoWorkspacePins(head) {
		old[pkgKey(q)] = true
	}
	var out []catalog.Package
	for _, q := range catalog.CargoWorkspacePins(staged) {
		if !old[pkgKey(q)] {
			q.Locations = []string{p}
			out = append(out, q)
		}
	}
	return out
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
