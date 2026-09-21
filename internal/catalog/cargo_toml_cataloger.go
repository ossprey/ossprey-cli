package catalog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
		Name string `toml:"name"`
	} `toml:"package"`
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
	// Platform-gated deps, e.g. [target.'cfg(windows)'.dependencies]. Still
	// shipped to whoever builds for that platform, so still worth scanning.
	Target map[string]struct {
		Dependencies      map[string]any `toml:"dependencies"`
		DevDependencies   map[string]any `toml:"dev-dependencies"`
		BuildDependencies map[string]any `toml:"build-dependencies"`
	} `toml:"target"`
	Workspace struct {
		Dependencies map[string]any `toml:"dependencies"`
	} `toml:"workspace"`
}

func parseCargoTomlFile(ctx context.Context, path string, loc file.Location, scanRoot string) ([]pkg.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var m cargoManifest
	if err := toml.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	pool := workspacePool(m, path, scanRoot)
	seen := make(map[string]struct{})
	var out []pkg.Package
	add := func(alias string, spec any) {
		name, version, ok, why := cargoDep(alias, spec, pool)
		if why != "" {
			warn.Add(ctx, cargoDropEntry(why, alias))
		}
		if !ok || name == "" || name == m.Package.Name {
			return
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, pkg.Package{
			Name:      name,
			Version:   version,
			Type:      pkg.RustPkg,
			Locations: file.NewLocationSet(loc),
		})
	}
	tables := []map[string]any{m.Dependencies, m.DevDependencies, m.BuildDependencies}
	for _, t := range m.Target {
		tables = append(tables, t.Dependencies, t.DevDependencies, t.BuildDependencies)
	}
	// [workspace.dependencies] is an inheritance pool, not a dependency list: it
	// is consulted for `dep = { workspace = true }` but never emitted wholesale.
	for _, table := range tables {
		for n, spec := range table {
			add(n, spec)
		}
	}
	return out, nil
}

// workspacePool returns the [workspace.dependencies] table governing this
// manifest: its own when it declares one, else the nearest ancestor manifest
// that does, since a workspace member conventionally holds only the opt-in.
// Bounded by the scan root, so it never reads outside what was asked for.
func workspacePool(m cargoManifest, manifestPath, scanRoot string) map[string]any {
	if len(m.Workspace.Dependencies) > 0 {
		return m.Workspace.Dependencies
	}
	root := filepath.Clean(scanRoot)
	dir := filepath.Dir(filepath.Clean(manifestPath))
	for {
		parent := filepath.Dir(dir)
		if parent == dir || !withinRoot(parent, root) {
			return nil
		}
		dir = parent
		data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
		if err != nil {
			continue
		}
		var ancestor cargoManifest
		if toml.Unmarshal(data, &ancestor) == nil && len(ancestor.Workspace.Dependencies) > 0 {
			return ancestor.Workspace.Dependencies
		}
	}
}

// withinRoot reports whether dir is root or sits inside it.
func withinRoot(dir, root string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
			if _, found := v[off]; found {
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
				return "", "", false, "its workspace root is outside the scan"
			}
			return cargoDep(alias, inherited, nil)
		}
		s, _ := v["version"].(string)
		return vouched(name, cargoExactVersion(s))
	}
	return "", "", false, ""
}

// cargoName is the crates.io name shape, which the Ossprey API enforces too: one
// component failing it rejects the whole SBOM, taking every other ecosystem with it.
var cargoName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// vouched drops a dependency whose key cannot name a crate on crates.io.
func vouched(name, version string) (string, string, bool, string) {
	if !cargoName.MatchString(name) {
		return "", "", false, "it cannot be a crates.io crate name"
	}
	return name, version, true, ""
}

func cargoDropEntry(why, alias string) warn.Entry {
	return warn.Entry{
		Class: "cargo:undeclarable:" + why,
		One:   fmt.Sprintf("cargotoml: skipped %q because %s", alias, why),
		Many:  "cargotoml: skipped %d dependencies because " + why,
		Item:  alias,
	}
}

// cargoRelease matches a concrete crates.io release, which is always full
// three-component semver, so "=1.0" is a range rather than a pin.
var cargoRelease = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.\-+]*)?$`)

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
	if !cargoRelease.MatchString(s) {
		return ""
	}
	return s
}
