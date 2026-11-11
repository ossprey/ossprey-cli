package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

// maxLockfileBytes bounds a lockfile read to decide coverage; a larger one
// covers nothing.
const maxLockfileBytes = 64 << 20

// readBoundedFile reads a regular file of at most limit bytes, saying why not. A FIFO or a
// device (a lockfile linked to /dev/zero) could otherwise never end.
func readBoundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return data, nil
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
	seen := make(map[string]int)
	copied := make(map[int]bool)
	var out []pkg.Package
	for _, r := range results {
		for _, p := range r.pkgs {
			key := p.Name + "@" + p.Version
			// A crate Cargo builds from git is not the crates.io crate of its name.
			if e, ok := p.Metadata.(pkg.RustCargoLockEntry); ok {
				key += "#" + e.Source
			}
			// A range carries its own manifest's requirements and root, so each manifest's stays apart.
			if r, ok := p.Metadata.(cargoRange); ok {
				key += "\x00" + r.Manifest
			}
			if i, ok := seen[key]; ok {
				// foldCargoRanges folds a crate per manifest, so a crate keeps every file's location, in a set copied once since a parser may share one.
				if p.Type == pkg.RustPkg {
					if !copied[i] {
						out[i].Locations = file.NewLocationSet(out[i].Locations.ToUnorderedSlice()...)
						copied[i] = true
					}
					out[i].Locations.Add(p.Locations.ToUnorderedSlice()...)
				}
				continue
			}
			seen[key] = len(out)
			out = append(out, p)
		}
	}
	return out, nil
}

// resolveByGlob is catalogByGlob for the catalogers that resolve a manifest's
// transitive tree. A manifest it did not resolve — the resolver failed, or the
// scan deadline passed before its turn — is recorded as unresolved: the scan
// still covers its direct dependencies through the fallback catalogers, but
// the report has to say the tree is partial rather than let it read as whole.
// covered, when not nil, exempts a manifest whose tree a lockfile beside it
// already supplies (syft reads it), so the failure costs nothing.
func resolveByGlob(ctx context.Context, resolver file.Resolver, root, glob, label string, covered func(absPath string) bool, parse fileParser) ([]pkg.Package, error) {
	var (
		mu   sync.Mutex
		done = map[string]bool{}
	)
	out, err := catalogByGlob(ctx, resolver, root, glob, label, func(absPath string, loc file.Location) ([]pkg.Package, error) {
		pkgs, err := parse(absPath, loc)
		if err == nil {
			mu.Lock()
			done[absPath] = true
			mu.Unlock()
		}
		return pkgs, err
	})
	if err != nil {
		return out, err
	}
	locs, _ := resolver.FilesByGlob(glob)
	for _, loc := range locs {
		if isVendoredPath(loc.RealPath) {
			continue
		}
		if p := hostPath(root, loc.RealPath); !done[p] && (covered == nil || !covered(p)) {
			markUnresolved(ctx, root, p)
		}
	}
	return out, nil
}

// markUnresolved records a manifest as unresolved under its path relative to
// the scan root, slash-separated so a report reads the same on every OS.
func markUnresolved(ctx context.Context, root, absPath string) {
	rel, ok := relToRoot(root, absPath)
	if !ok {
		rel = absPath
	}
	warn.MarkUnresolved(ctx, filepath.ToSlash(rel))
}

// relToRoot makes p relative to the scan root. The two can name the same
// directory differently: syft reports Windows paths symlink- and
// short-name-resolved (C:\Users\runneradmin where the root said
// C:\Users\RUNNER~1), and Windows compares names without case. So both the
// root as given and as resolved are tried, case-folded on Windows.
func relToRoot(root, p string) (string, bool) {
	fold := runtime.GOOS == "windows"
	roots := []string{root}
	if r, err := filepath.EvalSymlinks(root); err == nil && r != root {
		roots = append(roots, r)
	}
	paths := []string{p}
	if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
		paths = append(paths, r)
	}
	for _, r := range roots {
		for _, q := range paths {
			if rel, ok := relWithin(r, q, fold); ok {
				return rel, true
			}
		}
	}
	return "", false
}

// relWithin is filepath.Rel for a path inside root, comparing names without
// case when fold is set.
func relWithin(root, p string, fold bool) (string, bool) {
	root, p = filepath.Clean(root), filepath.Clean(p)
	if r, err := filepath.Rel(root, p); err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return r, true
	}
	if !fold || len(p) <= len(root) || !strings.EqualFold(p[:len(root)], root) {
		return "", false
	}
	rest := p[len(root):]
	if !os.IsPathSeparator(rest[0]) && !os.IsPathSeparator(root[len(root)-1]) {
		return "", false
	}
	return strings.TrimLeft(rest, `/\`), true
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
