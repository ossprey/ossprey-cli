package catalog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// CargoTomlCataloger extracts direct dependencies declared in Cargo.toml. Used
// when no Cargo.lock is present -- syft reads the lockfile only, so a library
// crate that gitignores it catalogues to nothing.
type CargoTomlCataloger struct {
	root string
	// coverage records a crate with no covering Cargo.lock as unresolved. Off
	// for NoExec runs (the pre-commit hook's temp trees hold no lock).
	coverage bool
}

func NewCargoTomlCataloger(root string) *CargoTomlCataloger {
	return &CargoTomlCataloger{root: root}
}

func (c *CargoTomlCataloger) Name() string { return "ossprey-cargotoml-cataloger" }

func (c *CargoTomlCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// The scan root bounds the walk to a member's workspace root.
	cache := &manifestCache{}
	parse := func(path string, loc file.Location) ([]pkg.Package, error) {
		pkgs, err := parseCargoTomlFile(ctx, path, loc, c.root, cache)
		// Without a Cargo.lock, here or at its workspace root, only the
		// direct dependencies are known: Rust has no resolver tier. Git, path
		// and private-registry dependencies are not emitted, but their trees
		// are just as unknown, so the declared tables decide. A manifest that
		// cannot be read or parsed declares nothing we know of, so only a lock
		// can cover it.
		if c.coverage && (err != nil || len(pkgs) > 0 || cargoDeclaresDependencies(path)) && !cargoLockCovers(path, c.root) {
			markUnresolved(ctx, c.root, path)
			dir := filepath.Dir(path)
			warn.Add(ctx, warn.Entry{
				Class: "cargotoml:no-lock",
				One:   fmt.Sprintf("cargotoml: %s has no readable Cargo.lock; direct dependencies only", dir),
				Many:  "cargotoml: %d crates have no readable Cargo.lock; direct dependencies only (OSSPREY_VERBOSE=1 lists them)",
				Item:  dir,
			})
		}
		return pkgs, err
	}
	out, err := catalogByGlob(ctx, resolver, c.root, "**/Cargo.toml", "cargotoml", parse)
	return out, nil, err
}

// A dependency is either a bare version string or a table. toml decodes both
// into any, so the shape is inspected rather than declared.
type cargoManifest struct {
	Package cargoPackage `toml:"package"`
	// Cargo reads the legacy [project] table as [package] before the 2024 edition.
	Project           cargoPackage   `toml:"project"`
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

type cargoPackage struct {
	Name      string `toml:"name"`
	Workspace string `toml:"workspace"`
}

// decodeCargoManifest decodes a Cargo.toml, reading a [project] table as [package] when there is no [package].
func decodeCargoManifest(data []byte) (cargoManifest, toml.MetaData, error) {
	var m cargoManifest
	md, err := toml.Decode(string(data), &m)
	if err == nil && !md.IsDefined("package") {
		m.Package = m.Project
	}
	return m, md, err
}

func parseCargoTomlFile(ctx context.Context, path string, loc file.Location, scanRoot string, cache *manifestCache) ([]pkg.Package, error) {
	data, err := readManifest(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	m, md, err := decodeCargoManifest(data)
	if err != nil {
		return nil, err
	}

	pool, rootDir, rootOK := workspacePool(m, md.IsDefined("workspace"), path, scanRoot, cache)
	// A root that cannot be read governs nothing here, so no lock is known to pin this manifest.
	root := ""
	if rootOK {
		root = cargoRootSpelling(loc, path, rootDir)
	}
	// An excluded crate is its own root and a package.workspace member is not; one whose root cannot be found counts as a root, so its git targets still go out.
	member := rootOK && rootDir != filepath.Dir(filepath.Clean(path))
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
	// [workspace.dependencies] is an inheritance pool, not a dependency list: it
	// is consulted for `dep = { workspace = true }` but never emitted wholesale.
	for _, table := range m.dependencyTables() {
		for n, spec := range table {
			add(n, spec)
		}
	}
	// foldCargoRanges folds a range only into a locked release that meets it.
	for _, name := range slices.Sorted(maps.Keys(reqs)) {
		emit(name, "", cargoRange{Manifest: loc.RealPath, Root: root, Reqs: reqs[name]})
	}
	// Cargo reads [patch] and [replace] only at the workspace root.
	if targets := cargoGitTargets(m); !member && len(targets) > 0 {
		locked := cargoLockGitSources(path)
		for _, t := range targets {
			// A lock that predates the target does not hide it, since a build without --locked rewrites the lock to fetch it.
			if lockRecords(locked, t) {
				continue
			}
			if _, _, ok, why := vouched(t.Name, ""); !ok {
				warn.Add(ctx, cargoDropEntry("cargotoml", why, t.Name))
				continue
			}
			// Carried as a Cargo.lock git entry, so cargoSourceMarks marks it the same way.
			emit(t.Name, t.Version, t.RustCargoLockEntry)
		}
	}
	return out, nil
}

// dependencyTables is every table of the crate's own dependencies, platform
// gated ones included; never [workspace.dependencies].
func (m cargoManifest) dependencyTables() []map[string]any {
	tables := []map[string]any{m.Dependencies, m.DevDependencies, m.BuildDependencies, m.DevDependenciesUS, m.BuildDependenciesUS}
	for _, t := range m.Target {
		tables = append(tables, t.Dependencies, t.DevDependencies, t.BuildDependencies, t.DevDependenciesUS, t.BuildDependenciesUS)
	}
	return tables
}

// cargoDeclaresDependencies reports a Cargo.toml declaring any dependency of
// its own, whatever its source: a path dependency counts too, since the crate
// it names may sit outside the scan and its tree is then read nowhere.
func cargoDeclaresDependencies(path string) bool {
	data, err := readManifest(path)
	if err != nil {
		return false
	}
	var m cargoManifest
	if _, err := toml.Decode(string(data), &m); err != nil {
		return false
	}
	for _, table := range m.dependencyTables() {
		if len(table) > 0 {
			return true
		}
	}
	return false
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

// manifestCache decodes each Cargo.toml a root search reads once per catalogue, since every member of a workspace climbs to the same root.
type manifestCache struct{ m sync.Map }

type cachedManifest struct {
	once   sync.Once
	m      cargoManifest
	isRoot bool
	err    error
}

func (c *manifestCache) read(path string) (cargoManifest, bool, error) {
	v, _ := c.m.LoadOrStore(path, &cachedManifest{})
	e := v.(*cachedManifest)
	e.once.Do(func() { e.m, e.isRoot, e.err = readCargoManifest(path) })
	return e.m, e.isRoot, e.err
}

// workspacePool returns the [workspace.dependencies] table of the root cargo finds for this manifest (isRoot: it declares [workspace]), that root's directory, and false when the root cannot be read inside the scan root.
func workspacePool(m cargoManifest, isRoot bool, manifestPath, scanRoot string, cache *manifestCache) (pool map[string]any, rootDir string, ok bool) {
	manifestPath = filepath.Clean(manifestPath)
	own := filepath.Dir(manifestPath)
	if isRoot {
		return m.Workspace.Dependencies, own, true
	}
	root := filepath.Clean(scanRoot)
	if m.Package.Workspace != "" {
		return pointedPool(manifestPath, m.Package.Workspace, root, cache)
	}
	dir := own
	for {
		parent := filepath.Dir(dir)
		if parent == dir || !withinRoot(parent, root) {
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
			return nil, "", false
		}
		ancestor, ancestorIsRoot, err := cache.read(ancestorPath)
		switch {
		// Cargo run from the member errors at an ancestor it cannot read, so no higher root counts.
		case err != nil:
			return nil, "", false
		case ancestorIsRoot && !excludes(ancestor, dir, manifestPath):
			return ancestor.Workspace.Dependencies, dir, true
		case !ancestorIsRoot && ancestor.Package.Workspace != "":
			return pointedPool(ancestorPath, ancestor.Package.Workspace, root, cache)
		}
	}
}

// DeclaresCargoWorkspace reports whether a Cargo.toml roots a workspace, as workspacePool reads one.
func DeclaresCargoWorkspace(data []byte) bool {
	if len(data) > maxManifestBytes {
		return false
	}
	var m cargoManifest
	md, err := toml.Decode(string(data), &m)
	return err == nil && md.IsDefined("workspace")
}

// CargoWorkspacePins returns the crates.io crates a Cargo.toml's [workspace.dependencies] pins exactly, read as an inheriting member reads each entry.
func CargoWorkspacePins(data []byte) []Package {
	if len(data) > maxManifestBytes {
		return nil
	}
	var m cargoManifest
	if _, err := toml.Decode(string(data), &m); err != nil {
		return nil
	}
	var out []Package
	for alias, spec := range m.Workspace.Dependencies {
		if name, version, ok, _ := cargoDep(alias, spec, nil); ok && version != "" {
			out = append(out, Package{Type: "cargo", Name: name, Version: version})
		}
	}
	return out
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
func pointedPool(manifestPath, pointer, root string, cache *manifestCache) (map[string]any, string, bool) {
	if !filepath.IsAbs(pointer) {
		pointer = filepath.Join(filepath.Dir(manifestPath), pointer)
	}
	// The root's Cargo.lock is found by real path, so a symlink alias of the root is spelled as the manifest spells it.
	dir := respell(filepath.Dir(manifestPath), filepath.Clean(pointer))
	target := filepath.Join(dir, "Cargo.toml")
	if !withinRoot(target, root) {
		return nil, dir, false
	}
	m, isRoot, err := cache.read(target)
	if err != nil || !isRoot {
		return nil, dir, false
	}
	return m.Workspace.Dependencies, dir, true
}

// errNotAManifest is a Cargo.toml with no [package], [project] or [workspace], which cargo rejects as a workspace manifest.
var errNotAManifest = errors.New("Cargo.toml declares no package or workspace")

// respell returns p as reached from base by real paths, so a symlink alias or a Windows short name of a directory takes the spelling base uses.
func respell(base, p string) string {
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return p
	}
	realP, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(realBase, realP)
	if err != nil {
		return p
	}
	return filepath.Join(base, rel)
}

// readCargoManifest reads and decodes a Cargo.toml, and reports whether it declares [workspace].
func readCargoManifest(path string) (m cargoManifest, isRoot bool, err error) {
	data, err := readManifest(path)
	if err != nil {
		return m, false, err
	}
	m, md, err := decodeCargoManifest(data)
	if err == nil && !md.IsDefined("package") && !md.IsDefined("project") && !md.IsDefined("workspace") {
		err = errNotAManifest
	}
	return m, md.IsDefined("workspace"), err
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
		// An absolute entry may spell the scan root otherwise than the manifest path does.
		if filepath.IsAbs(e) {
			e = respell(dir, e)
		} else {
			e = filepath.Join(dir, e)
		}
		if rel, err := filepath.Rel(e, manifestPath); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// cargoRange is a versionless crate one manifest declares, which foldCargoRanges folds only into a release its root's Cargo.lock locks.
type cargoRange struct {
	Manifest string   // the manifest's RealPath
	Root     string   // its workspace root spelled as the resolver spells Manifest, "" when none can be read
	Reqs     []string // every requirement the manifest declares for the crate
}

// cargoRootSpelling is a manifest's workspace root spelled as the resolver spells loc, so it compares with a Cargo.lock's location.
func cargoRootSpelling(loc file.Location, manifestPath, rootDir string) string {
	rel, err := filepath.Rel(filepath.Dir(filepath.Clean(manifestPath)), rootDir)
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(loc.RealPath), rel)
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

// validCargoComponent reports whether a crate name and version can survive the
// API's validator. One that cannot rejects the whole SBOM, so every cargo
// source is held to this, not just the manifest cataloguer.
func validCargoComponent(name, version string) bool {
	return registry.IsCargoName(name) && len(version) <= registry.MaxCargoVersion
}

// cargoDropReason names which half of validCargoComponent failed, so a real
// crate carrying an over-long version is not reported as an impossible name.
func cargoDropReason(name string) string {
	if registry.IsCargoName(name) {
		return "its version is over the API's length limit"
	}
	return "it cannot be a crates.io crate name"
}

// vouched drops a dependency whose key cannot name a crate on crates.io.
func vouched(name, version string) (string, string, bool, string) {
	if !registry.IsCargoName(name) {
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
	if len(s) > registry.MaxCargoVersion || !registry.IsCargoRelease(s) {
		return ""
	}
	return s
}

// cargoLockCovers reports whether a Cargo.lock syft reads holds the tree of
// the crate at manifestPath: the one at the workspace root cargo finds for it
// (workspacePool: the root package.workspace names, else the nearest
// ancestor [workspace] that does not exclude it), which for a crate outside
// any workspace is its own directory. cargo locks a member at that root and
// ignores a Cargo.lock beside the member (verified with cargo 1.99). A
// manifest that cannot be read is covered only by a lock beside it, and a
// lock that does not parse covers nothing.
func cargoLockCovers(manifestPath, scanRoot string) bool {
	manifestPath = filepath.Clean(manifestPath)
	cache := &manifestCache{}
	m, isRoot, err := cache.read(manifestPath)
	if err != nil {
		return cargoLockReadable(filepath.Dir(manifestPath))
	}
	_, rootDir, ok := workspacePool(m, isRoot, manifestPath, scanRoot, cache)
	return ok && cargoLockReadable(rootDir)
}

func cargoLockReadable(dir string) bool {
	data, err := readBoundedFile(filepath.Join(dir, "Cargo.lock"), maxLockfileBytes)
	if err != nil {
		return false
	}
	return tomlLockHasPackages(data, true) // a lock always holds the crate itself
}
