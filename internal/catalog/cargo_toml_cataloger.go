package catalog

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
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
	out, err := catalogByGlob(ctx, resolver, c.root, "**/Cargo.toml", "cargotoml", parseCargoTomlFile)
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

func parseCargoTomlFile(path string, loc file.Location) ([]pkg.Package, error) {
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

	seen := make(map[string]struct{})
	var out []pkg.Package
	add := func(alias string, spec any) {
		name, version, ok := cargoDep(alias, spec, m.Workspace.Dependencies)
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

// cargoDep resolves one dependency entry to the crate name and version to
// submit, and whether to submit it at all.
//
// The key is an alias: `renamed = { package = "real-crate" }` is legal, and
// emitting the alias would look up a crate that does not exist. path and git
// deps are not on crates.io, and `registry = "..."` names a private one, so
// all three would only ever produce NOT_FOUND.
func cargoDep(alias string, spec any, pool map[string]any) (name, version string, ok bool) {
	switch v := spec.(type) {
	case string:
		return alias, cargoExactVersion(v), true
	case map[string]any:
		for _, off := range []string{"path", "git", "registry", "registry-index"} {
			if _, found := v[off]; found {
				return "", "", false
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
				return name, "", true
			}
			return cargoDep(alias, inherited, nil)
		}
		s, _ := v["version"].(string)
		return name, cargoExactVersion(s), true
	}
	return "", "", false
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
