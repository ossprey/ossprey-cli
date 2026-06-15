package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// PackageJSONCataloger extracts direct dependencies declared in package.json
// (dependencies, devDependencies, peerDependencies). Used when no lockfile
// is present — syft's package.json parser emits only the root project itself,
// not its dependencies.
type PackageJSONCataloger struct {
	root string
}

func NewPackageJSONCataloger(root string) *PackageJSONCataloger {
	return &PackageJSONCataloger{root: root}
}

func (c *PackageJSONCataloger) Name() string { return "ossprey-packagejson-cataloger" }

func (c *PackageJSONCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	out, err := catalogByGlob(resolver, c.root, "**/package.json", "packagejson", parsePackageJSONFile)
	return out, nil, err
}

type packageJSON struct {
	Name             string            `json:"name"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

func parsePackageJSONFile(path string, loc file.Location) ([]pkg.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var pj packageJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var out []pkg.Package
	add := func(name, raw string) {
		if name == "" || name == pj.Name {
			return
		}
		version := pinVersion(stripVersionOp(raw))
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, pkg.Package{
			Name:      name,
			Version:   version,
			Type:      pkg.NpmPkg,
			Locations: file.NewLocationSet(loc),
		})
	}
	for n, v := range pj.Dependencies {
		add(n, v)
	}
	for n, v := range pj.DevDependencies {
		add(n, v)
	}
	for n, v := range pj.PeerDependencies {
		add(n, v)
	}
	return out, nil
}
