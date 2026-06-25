package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"golang.org/x/sync/errgroup"
)

func catalogConcurrency() int {
	if n, err := strconv.Atoi(os.Getenv("OSSPREY_SCAN_CONCURRENCY")); err == nil && n > 0 {
		return n
	}
	return 8
}

// fileParser converts one matched manifest into syft packages.
type fileParser func(absPath string, loc file.Location) ([]pkg.Package, error)

// isVendoredPath reports whether p sits inside a vendored dependency tree.
func isVendoredPath(p string) bool {
	return strings.Contains(p, "node_modules/")
}

// catalogByGlob runs parse against every file matching glob under the
// resolver's root, dedup'd by (name, version). Shared by every ossprey-*
// cataloger — they differ only by glob + parse.
func catalogByGlob(resolver file.Resolver, root, glob, label string, parse fileParser) ([]pkg.Package, error) {
	locs, err := resolver.FilesByGlob(glob)
	if err != nil {
		return nil, fmt.Errorf("%s cataloger: glob: %w", label, err)
	}

	type result struct {
		idx  int
		pkgs []pkg.Package
	}
	var (
		mu      sync.Mutex
		results []result
	)
	g := new(errgroup.Group)
	g.SetLimit(catalogConcurrency())
	for i, loc := range locs {
		if isVendoredPath(loc.RealPath) {
			continue
		}
		i, loc := i, loc
		g.Go(func() error {
			pkgs, err := parse(filepath.Join(root, loc.RealPath), loc)
			if err != nil || len(pkgs) == 0 {
				return nil // per-file errors are non-fatal, as before
			}
			mu.Lock()
			results = append(results, result{idx: i, pkgs: pkgs})
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait() // workers never return non-nil; Wait is just the barrier

	sort.Slice(results, func(a, b int) bool { return results[a].idx < results[b].idx })
	seen := make(map[string]struct{})
	var out []pkg.Package
	for _, r := range results {
		for _, p := range r.pkgs {
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
