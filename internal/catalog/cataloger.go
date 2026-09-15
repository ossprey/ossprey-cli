package catalog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"golang.org/x/sync/errgroup"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

func catalogConcurrency() int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("OSSPREY_SCAN_CONCURRENCY"))); err == nil && n > 0 {
		return n
	}
	return 8
}

// resolverTimeout caps one uv/npm invocation so a single hung manifest cannot eat the whole scan budget.
func resolverTimeout() time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv("OSSPREY_RESOLVE_TIMEOUT"))); err == nil && d > 0 {
		return d
	}
	return 2 * time.Minute
}

// fileParser converts one matched manifest into syft packages.
type fileParser func(absPath string, loc file.Location) ([]pkg.Package, error)

// isVendoredPath reports whether p sits inside a vendored dependency tree.
func isVendoredPath(p string) bool {
	return strings.Contains(filepath.ToSlash(p), "node_modules/")
}

// hostPath maps a resolver location's RealPath to an absolute host path. Syft's
// directory resolver reports paths relative to the scan root on POSIX but
// absolute (drive-lettered) on Windows, where joining unconditionally doubles
// the root and breaks every manifest read.
func hostPath(root, realPath string) string {
	if filepath.IsAbs(realPath) {
		return realPath
	}
	return filepath.Join(root, realPath)
}

// catalogByGlob runs parse against every file matching glob under the
// resolver's root, dedup'd by (name, version). Shared by every ossprey-*
// cataloger — they differ only by glob + parse.
func catalogByGlob(ctx context.Context, resolver file.Resolver, root, glob, label string, parse fileParser) ([]pkg.Package, error) {
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
		if ctx.Err() != nil {
			break // past the deadline a queued resolve would only start in order to die
		}
		if isVendoredPath(loc.RealPath) {
			continue
		}
		i, loc := i, loc
		g.Go(func() error {
			pkgs, err := parse(hostPath(root, loc.RealPath), loc)
			if err != nil {
				// Non-fatal, but surface it: a swallowed uv/npm failure (e.g.
				// the host Python is too old to resolve the pins) otherwise
				// looks identical to "nothing found". Warn to stderr — the SBOM
				// goes to stdout, so this never corrupts --local output.
				// Past the deadline every remaining manifest fails the same way, and scan.Run reports that once.
				if ctx.Err() == nil {
					warn.Add(ctx, catalogerEntry(label, err))
				}
				return nil
			}
			if len(pkgs) == 0 {
				return nil
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

// catalogerEntry turns one manifest's failure into a warning. A subprocess
// failure contributes its one actionable line to the headline and keeps the
// rest for a verbose run; anything else is already a single sentence.
func catalogerEntry(label string, err error) warn.Entry {
	e := warn.Entry{
		Class: "cataloger:" + label,
		Many:  label + ": could not resolve %d manifests",
	}
	var te *toolError
	if errors.As(err, &te) {
		e.One = fmt.Sprintf("%s: could not resolve %s (%s)", label, te.dir, te.summary)
		e.Item = fmt.Sprintf("%s (%s)", te.dir, te.summary)
		e.Detail = te.detail
		e.DetailLabel = label
		return e
	}
	e.One = fmt.Sprintf("%s: %v", label, err)
	e.Item = err.Error()
	return e
}

// parseEntry reports entries a cataloger could not read. Syft's catalogers
// return everything they did parse alongside an error naming the rest; that
// error used to be discarded, so a malformed requirement went missing from the
// SBOM in silence — the one genuinely quiet failure in the catalog path.
func parseEntry(name string, err error) warn.Entry {
	detail := newToolError(name, "", err.Error()).detail
	return warn.Entry{
		Class:       "parse:" + name,
		One:         fmt.Sprintf("%s: some entries could not be parsed (%s)", name, summarize(detail)),
		Many:        name + ": entries could not be parsed in %d passes",
		Item:        summarize(detail),
		Detail:      detail,
		DetailLabel: name,
	}
}
