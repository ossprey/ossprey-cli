package catalog

import (
	"context"
	"errors"
	"io/fs"
	"os"
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
	Workspace         struct {
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
	add := func(name string, spec any) {
		if name == "" || name == m.Package.Name {
			return
		}
		version, registry := cargoDepVersion(spec)
		if !registry {
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
	for _, table := range []map[string]any{
		m.Dependencies, m.DevDependencies, m.BuildDependencies, m.Workspace.Dependencies,
	} {
		for n, spec := range table {
			add(n, spec)
		}
	}
	return out, nil
}

// cargoDepVersion returns the pinned version (empty unless the spec names one
// exactly) and whether the dependency comes from a registry at all. A `path`
// or `git` dependency is not on crates.io, so submitting it would only produce
// a NOT_FOUND finding.
func cargoDepVersion(spec any) (version string, registry bool) {
	switch v := spec.(type) {
	case string:
		return cargoExactVersion(v), true
	case map[string]any:
		if _, ok := v["path"]; ok {
			return "", false
		}
		if _, ok := v["git"]; ok {
			return "", false
		}
		s, _ := v["version"].(string)
		return cargoExactVersion(s), true
	}
	return "", false
}

// cargoExactVersion returns the version only when the spec pins one exactly.
// Cargo's bare "1.0" means caret, i.e. a range, so it resolves to nothing and
// the component goes out versionless for resolveVersionless to settle. Guessing
// the lower bound would ship a component on a version the crate never uses.
func cargoExactVersion(spec string) string {
	s := strings.TrimSpace(spec)
	if !strings.HasPrefix(s, "=") {
		return ""
	}
	return pinVersion(strings.TrimSpace(s[1:]))
}
