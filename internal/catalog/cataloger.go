package catalog

import (
	"fmt"
	"path/filepath"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// fileParser converts one matched manifest into syft packages.
type fileParser func(absPath string, loc file.Location) ([]pkg.Package, error)

// catalogByGlob runs parse against every file matching glob under the
// resolver's root, dedup'd by (name, version). Shared by every ossprey-*
// cataloger — they differ only by glob + parse.
func catalogByGlob(resolver file.Resolver, root, glob, label string, parse fileParser) ([]pkg.Package, error) {
	locs, err := resolver.FilesByGlob(glob)
	if err != nil {
		return nil, fmt.Errorf("%s cataloger: glob: %w", label, err)
	}
	seen := make(map[string]struct{})
	var out []pkg.Package
	for _, loc := range locs {
		pkgs, err := parse(filepath.Join(root, loc.RealPath), loc)
		if err != nil || len(pkgs) == 0 {
			continue
		}
		for _, p := range pkgs {
			key := p.Name + "@" + p.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}
