package catalog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// CargoTomlCataloger extracts direct dependencies declared in Cargo.toml. Used
// when no Cargo.lock is present -- syft reads the lockfile only, so a library
// crate that gitignores it catalogues to nothing.
type CargoTomlCataloger struct {
	root string
}

func NewCargoTomlCataloger(root string) *CargoTomlCataloger {
	return &CargoTomlCataloger{root: root}
}

func (c *CargoTomlCataloger) Name() string { return "ossprey-cargotoml-cataloger" }

func (c *CargoTomlCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// The scan root bounds the walk to a member's workspace root.
	parse := func(path string, loc file.Location) ([]pkg.Package, error) {
		return parseCargoTomlFile(ctx, path, loc, c.root)
	}
	out, err := catalogByGlob(ctx, resolver, c.root, "**/Cargo.toml", "cargotoml", parse)
	return out, nil, err
}

// A dependency is either a bare version string or a table. toml decodes both
// into any, so the shape is inspected rather than declared.
type cargoManifest struct {
	Package struct {
		Name      string `toml:"name"`
		Workspace string `toml:"workspace"`
	} `toml:"package"`
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
	// Cargo still accepts the deprecated underscore spellings.
	DevDependenciesUS   map[string]any `toml:"dev_dependencies"`
	BuildDependenciesUS map[string]any `toml:"build_dependencies"`
	// Platform-gated deps, e.g. [target.'cfg(windows)'.dependencies]. Still
	// shipped to whoever builds for that platform, so still worth scanning.
	Target map[string]struct {
		Dependencies        map[string]any `toml:"dependencies"`
		DevDependencies     map[string]any `toml:"dev-dependencies"`
		BuildDependencies   map[string]any `toml:"build-dependencies"`
		DevDependenciesUS   map[string]any `toml:"dev_dependencies"`
		BuildDependenciesUS map[string]any `toml:"build_dependencies"`
	} `toml:"target"`
	Workspace struct {
		Dependencies map[string]any `toml:"dependencies"`
		Members      []string       `toml:"members"`
		Exclude      []string       `toml:"exclude"`
	} `toml:"workspace"`
	// Cargo builds these in place of the crates they name, but only from the workspace root.
	Patch   map[string]any `toml:"patch"`
	Replace map[string]any `toml:"replace"`
}

func parseCargoTomlFile(ctx context.Context, path string, loc file.Location, scanRoot string) ([]pkg.Package, error) {
	data, err := readManifest(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var m cargoManifest
	md, err := toml.Decode(string(data), &m)
	if err != nil {
		return nil, err
	}

	pool, rootDir, rootOK := workspacePool(m, md.IsDefined("workspace"), path, scanRoot)
	// A root that cannot be read governs nothing here, so no lock is known to pin this manifest.
	if rootOK {
		loc = withCargoRoot(loc, path, rootDir)
	}
	// An excluded crate is its own root and a package.workspace member is not, as the resolved root says.
	member := rootDir != filepath.Dir(filepath.Clean(path))
	var out []pkg.Package
	// catalogByGlob dedups what this returns, across every manifest.
	emit := func(name, version string, metadata any) {
		out = append(out, pkg.Package{Name: name, Version: version, Type: pkg.RustPkg, Locations: file.NewLocationSet(loc), Metadata: metadata})
	}
	reqs := map[string][]string{} // a range's crate -> every requirement this manifest declares for it
	add := func(alias string, spec any) {
		name, version, ok, why := cargoDep(alias, spec, pool)
		if why != "" {
			warn.Add(ctx, cargoDropEntry("cargotoml", why, alias))
		}
		if !ok || name == "" || name == m.Package.Name {
			return
		}
		if version == "" {
			reqs[name] = append(reqs[name], cargoRequirement(alias, spec, pool))
			return
		}
		emit(name, version, nil)
	}
	tables := []map[string]any{m.Dependencies, m.DevDependencies, m.BuildDependencies, m.DevDependenciesUS, m.BuildDependenciesUS}
	for _, t := range m.Target {
		tables = append(tables, t.Dependencies, t.DevDependencies, t.BuildDependencies, t.DevDependenciesUS, t.BuildDependenciesUS)
	}
	// [workspace.dependencies] is an inheritance pool, not a dependency list: it
	// is consulted for `dep = { workspace = true }` but never emitted wholesale.
	for _, table := range tables {
		for n, spec := range table {
			add(n, spec)
		}
	}
	// mergeVersionless folds a range only into a locked release that meets it.
	for _, name := range slices.Sorted(maps.Keys(reqs)) {
		l := withAnnotation(loc, cargoReqAnnotation, strings.Join(reqs[name], "\n"))
		out = append(out, pkg.Package{Name: name, Type: pkg.RustPkg, Locations: file.NewLocationSet(l)})
	}
	// Cargo reads [patch] and [replace] only at the workspace root, and a lock there already records their git sources.
	if !member && !hasCargoLock(path) {
		for _, t := range cargoGitTargets(m) {
			if _, _, ok, why := vouched(t.Name, ""); !ok {
				warn.Add(ctx, cargoDropEntry("cargotoml", why, t.Name))
				continue
			}
			// Carried as a Cargo.lock git entry, so cargoSourceMarks marks it the same way.
			emit(t.Name, t.Version, t)
		}
	}
	return out, nil
}

// maxManifestBytes is a sanity bound, not a fix for deeply nested TOML, which
// allocates quadratically in every toml cataloguer here (OSS-2098).
const maxManifestBytes = 1 << 20

// readManifest reads a Cargo.toml, refusing one too large to be genuine.
func readManifest(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxManifestBytes {
		return nil, fmt.Errorf("Cargo.toml is %d bytes, over the %d limit", info.Size(), maxManifestBytes)
	}
	return os.ReadFile(path)
}

// workspacePool returns the [workspace.dependencies] table of the root cargo finds for this manifest (isRoot: it declares [workspace]), that root's directory, and false when the root cannot be read inside the scan root.
func workspacePool(m cargoManifest, isRoot bool, manifestPath, scanRoot string) (pool map[string]any, rootDir string, ok bool) {
	manifestPath = filepath.Clean(manifestPath)
	own := filepath.Dir(manifestPath)
	if isRoot {
		return m.Workspace.Dependencies, own, true
	}
	root := filepath.Clean(scanRoot)
	if m.Package.Workspace != "" {
		return pointedPool(manifestPath, m.Package.Workspace, root)
	}
	// Cargo run from the member errors past an ancestor it cannot read, but run from a root that lists the member it never reads that ancestor.
	broken := false
	dir := own
	for {
		parent := filepath.Dir(dir)
		if parent == dir || !withinRoot(parent, root) {
			if broken {
				return nil, "", false
			}
			return nil, own, true
		}
		dir = parent
		ancestorPath := filepath.Join(dir, "Cargo.toml")
		// Cargo climbs past a missing ancestor manifest.
		if _, err := os.Stat(ancestorPath); err != nil {
			continue
		}
		// A manifest linked out of the scan root counts as unreadable, since its pool would come from elsewhere.
		if !withinRoot(ancestorPath, root) {
			broken = true
			continue
		}
		ancestor, ancestorIsRoot, err := readCargoManifest(ancestorPath)
		switch {
		case err != nil:
			broken = true
		case broken:
			if ancestorIsRoot && listsMember(ancestor, dir, manifestPath) && !excludes(ancestor, dir, manifestPath) {
				return ancestor.Workspace.Dependencies, dir, true
			}
		case ancestorIsRoot && !excludes(ancestor, dir, manifestPath):
			return ancestor.Workspace.Dependencies, dir, true
		case !ancestorIsRoot && ancestor.Package.Workspace != "":
			return pointedPool(ancestorPath, ancestor.Package.Workspace, root)
		}
	}
}

// withinRoot reports whether dir is root or sits inside it, resolving symlinks
// first so a linked directory cannot walk the read outside the scan root.
func withinRoot(dir, root string) bool {
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(realRoot, realDir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// pointedPool returns the pool and directory of the root a package.workspace path names, and false when it cannot be read inside the scan root.
func pointedPool(manifestPath, pointer, root string) (map[string]any, string, bool) {
	if !filepath.IsAbs(pointer) {
		pointer = filepath.Join(filepath.Dir(manifestPath), pointer)
	}
	dir := filepath.Clean(pointer)
	target := filepath.Join(dir, "Cargo.toml")
	if !withinRoot(target, root) {
		return nil, dir, false
	}
	m, isRoot, err := readCargoManifest(target)
	if err != nil || !isRoot {
		return nil, dir, false
	}
	return m.Workspace.Dependencies, dir, true
}

// errNotAManifest is a Cargo.toml with no [package], [project] or [workspace], which cargo rejects as a workspace manifest.
var errNotAManifest = errors.New("Cargo.toml declares no package or workspace")

// readCargoManifest reads and decodes a Cargo.toml, and reports whether it declares [workspace].
func readCargoManifest(path string) (m cargoManifest, isRoot bool, err error) {
	data, err := readManifest(path)
	if err != nil {
		return m, false, err
	}
	md, err := toml.Decode(string(data), &m)
	if err == nil && !md.IsDefined("package") && !md.IsDefined("project") && !md.IsDefined("workspace") {
		err = errNotAManifest
	}
	return m, md.IsDefined("workspace"), err
}

// listsMember reports whether a members entry of the workspace rooted at dir, matched component by component as cargo's glob expands it, names the member's directory.
func listsMember(ws cargoManifest, dir, manifestPath string) bool {
	rel, err := filepath.Rel(dir, filepath.Dir(manifestPath))
	if err != nil {
		return false
	}
	want := strings.Split(filepath.ToSlash(rel), "/")
	for _, e := range ws.Workspace.Members {
		if filepath.IsAbs(e) {
			if e, err = filepath.Rel(dir, e); err != nil {
				continue
			}
		}
		if matchComponents(strings.Split(filepath.ToSlash(filepath.Clean(e)), "/"), want) {
			return true
		}
	}
	return false
}

// matchComponents reports whether each path component matches its glob, with as many components on each side.
func matchComponents(pattern, path []string) bool {
	if len(pattern) != len(path) {
		return false
	}
	for i := range pattern {
		if ok, err := filepath.Match(pattern[i], path[i]); err != nil || !ok {
			return false
		}
	}
	return true
}

// excludes reports whether the workspace rooted at dir leaves a member out, as cargo's is_excluded does: an exclude entry covers it and no members entry does.
func excludes(ws cargoManifest, dir, manifestPath string) bool {
	return covers(dir, ws.Workspace.Exclude, manifestPath) && !covers(dir, ws.Workspace.Members, manifestPath)
}

// covers reports whether manifestPath sits at or below dir joined with any entry, by whole components as Rust's Path::starts_with compares.
func covers(dir string, entries []string, manifestPath string) bool {
	for _, e := range entries {
		// Rust keeps a ".." component, which no manifest path holds, where Join would resolve it.
		if slices.Contains(strings.Split(filepath.ToSlash(e), "/"), "..") {
			continue
		}
		if !filepath.IsAbs(e) {
			e = filepath.Join(dir, e)
		}
		if rel, err := filepath.Rel(e, manifestPath); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// cargoRootAnnotation carries a manifest's workspace root to mergeVersionless.
const cargoRootAnnotation = "ossprey-cargo-workspace-root"

// cargoReqAnnotation carries a range's requirements in one manifest to mergeVersionless, one per line.
const cargoReqAnnotation = "ossprey-cargo-requirement"

// withAnnotation sets key on a copy of loc's annotations, which every package from one manifest shares.
func withAnnotation(loc file.Location, key, value string) file.Location {
	loc.Annotations = maps.Clone(loc.Annotations)
	return loc.WithAnnotation(key, value)
}

// withCargoRoot annotates loc with its workspace root, spelled as the resolver spells loc so it compares with a Cargo.lock's location.
func withCargoRoot(loc file.Location, manifestPath, rootDir string) file.Location {
	rel, err := filepath.Rel(filepath.Dir(filepath.Clean(manifestPath)), rootDir)
	if err != nil {
		return loc
	}
	return loc.WithAnnotation(cargoRootAnnotation, filepath.Join(filepath.Dir(loc.RealPath), rel))
}

// cargoDep resolves one dependency entry to the crate name and version to
// submit, and whether to submit it at all.
//
// The key is an alias: `renamed = { package = "real-crate" }` is legal, and
// emitting the alias would look up a crate that does not exist. path and git
// deps are not on crates.io, and `registry = "..."` names a private one, so
// all three would only ever produce NOT_FOUND.
func cargoDep(alias string, spec any, pool map[string]any) (name, version string, ok bool, why string) {
	switch v := spec.(type) {
	case string:
		return vouched(alias, cargoExactVersion(v))
	case map[string]any:
		for _, off := range []string{"path", "git", "registry", "registry-index"} {
			// "crates-io" is Cargo's reserved name for the default registry, so
			// naming it explicitly still means the public one.
			if r, found := v[off]; found && !(off == "registry" && r == "crates-io") && !(off == "registry-index" && indexIsCratesIo(r)) {
				return "", "", false, ""
			}
		}
		name = alias
		if real, isStr := v["package"].(string); isStr && real != "" {
			name = real
		}
		// `dep = { workspace = true }` inherits the pool entry, which carries the
		// real pin and any rename, so resolve against it rather than guessing.
		if inherit, isBool := v["workspace"].(bool); isBool && inherit {
			inherited, found := pool[alias]
			if !found {
				// The pool is out of scan scope, so this key could name a path
				// member, a private registry or a rename alias. Emitting it would
				// resolve a name we cannot vouch for against crates.io.
				return "", "", false, "its workspace root could not be read inside the scan"
			}
			return cargoDep(alias, inherited, nil)
		}
		s, _ := v["version"].(string)
		return vouched(name, cargoExactVersion(s))
	}
	return "", "", false, ""
}

// cargoRequirement returns the version requirement of a crates.io dependency entry cargoDep accepted, following workspace inheritance.
func cargoRequirement(alias string, spec any, pool map[string]any) string {
	switch v := spec.(type) {
	case string:
		return v
	case map[string]any:
		if inherit, _ := v["workspace"].(bool); inherit {
			return cargoRequirement(alias, pool[alias], nil)
		}
		s, _ := v["version"].(string)
		return s
	}
	return ""
}

// indexIsCratesIo reports whether a registry-index value names crates.io, read as the Cargo.lock source cargo records for it: sparse+ as given, any other under registry+.
func indexIsCratesIo(index any) bool {
	s, _ := index.(string)
	s = crateURLCleaner.Replace(trimC0(s))
	if kind, rest, ok := strings.Cut(s, "+"); ok && strings.EqualFold(kind, "sparse") {
		s = "sparse+" + rest
	} else {
		s = "registry+" + s
	}
	// A host cargo's IDNA may map to crates.io or elsewhere is not definitely crates.io, so its crate is another registry's.
	is, _ := isCratesIo(s)
	return is
}

// cargoName is the crates.io name shape, which the Ossprey API enforces too: one
// component failing it rejects the whole SBOM, taking every other ecosystem with it.
var cargoName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// validCargoComponent reports whether a crate name and version can survive the
// API's validator. One that cannot rejects the whole SBOM, so every cargo
// source is held to this, not just the manifest cataloguer.
func validCargoComponent(name, version string) bool {
	return cargoName.MatchString(name) && len(version) <= maxCargoVersion
}

// cargoDropReason names which half of validCargoComponent failed, so a real
// crate carrying an over-long version is not reported as an impossible name.
func cargoDropReason(name string) string {
	if cargoName.MatchString(name) {
		return "its version is over the API's length limit"
	}
	return "it cannot be a crates.io crate name"
}

// vouched drops a dependency whose key cannot name a crate on crates.io.
func vouched(name, version string) (string, string, bool, string) {
	if !cargoName.MatchString(name) {
		return "", "", false, "it cannot be a crates.io crate name"
	}
	return name, version, true, ""
}

func cargoDropEntry(file, why, alias string) warn.Entry {
	return warn.Entry{
		Class: "cargo:undeclarable:" + file + ":" + why,
		One:   fmt.Sprintf("%s: skipped %q because %s", file, alias, why),
		Many:  file + ": skipped %d dependencies because " + why,
		Item:  alias,
	}
}

// maxCargoVersion mirrors the API's version cap; a longer one rejects the SBOM.
const maxCargoVersion = 256

// cargoRelease matches a concrete crates.io release, which is always full three-component semver with no leading zero or empty identifier, so "=1.0" is a range rather than a pin.
var cargoRelease = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// cargoExactVersion returns the version only when the spec pins one exactly.
// Cargo's bare "1.0" means caret, i.e. a range, so it resolves to nothing and
// the component goes out versionless. Guessing the lower bound would ship a
// component on a version the crate never uses.
func cargoExactVersion(spec string) string {
	s := strings.TrimSpace(spec)
	if !strings.HasPrefix(s, "=") {
		return ""
	}
	s = strings.TrimSpace(s[1:])
	if len(s) > maxCargoVersion || !isCargoRelease(s) {
		return ""
	}
	return s
}

// isCargoRelease reports whether s is a release cargo's semver parser accepts, whose core numbers fit in a u64.
func isCargoRelease(s string) bool {
	if !cargoRelease.MatchString(s) {
		return false
	}
	core, _, _ := strings.Cut(strings.SplitN(s, "+", 2)[0], "-")
	for _, n := range strings.Split(core, ".") {
		if _, err := strconv.ParseUint(n, 10, 64); err != nil {
			return false
		}
	}
	return true
}
