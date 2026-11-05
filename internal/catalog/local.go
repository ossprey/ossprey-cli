package catalog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/file"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// localPyProject captures only the tables that declare where a dependency comes
// from: uv's [tool.uv.sources] and poetry's [tool.poetry.dependencies]. A
// dependency wired to a local path or workspace member is the repo's own code,
// not a public-registry package.
type localPyProject struct {
	Tool struct {
		Uv struct {
			Sources map[string]any `toml:"sources"`
		} `toml:"uv"`
		Poetry struct {
			Dependencies map[string]any `toml:"dependencies"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// pep503Separators matches the runs of "-", "_" and "." that PEP 503 treats as
// equivalent, so "My_Pkg", "my.pkg" and "my-pkg" canonicalise to one name. The
// manifest keys and the cataloguer output can disagree on case and separator.
var pep503Separators = regexp.MustCompile(`[-_.]+`)

func canonicalPackageName(s string) string {
	return pep503Separators.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
}

// findLocalPackageNames walks every pyproject.toml under root and returns the
// canonicalised names of packages declared as local (uv path/workspace sources
// or poetry path dependencies). Vendored trees are skipped, matching the
// cataloguers. Best-effort: unreadable or malformed manifests are skipped so a
// stray file never fails the scan.
func findLocalPackageNames(ctx context.Context, resolver file.Resolver, root string) map[string]struct{} {
	names := map[string]struct{}{}
	locs, err := resolver.FilesByGlob("**/pyproject.toml")
	if err != nil {
		return names
	}
	seen := map[string]bool{}
	for _, loc := range locs {
		if isVendoredPath(loc.RealPath) || seen[loc.RealPath] {
			continue
		}
		seen[loc.RealPath] = true
		path := hostPath(root, loc.RealPath)
		data, err := readTOML(path)
		if err == nil {
			if err = collectLocalNames(data, names); err != nil {
				err = &fs.PathError{Op: "parse", Path: path, Err: err}
			}
		}
		// The packages it declares local are then looked up publicly, so say which file went unread.
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			warn.Add(ctx, localSourcesEntry(relToRoot(root, err)))
		}
	}
	return names
}

// localSourcesEntry reports a pyproject.toml whose local sources could not be read.
func localSourcesEntry(err error) warn.Entry {
	return warn.Entry{
		Class: "pyproject:local-sources",
		One:   fmt.Sprintf("pyproject: local sources not read (%v); any path or workspace package it declares is looked up on PyPI", err),
		Many:  "pyproject: local sources not read in %d files; any path or workspace package they declare is looked up on PyPI",
		Item:  err.Error(),
	}
}

// collectLocalNames parses one pyproject.toml and adds the canonical name of
// every locally-sourced package to out.
func collectLocalNames(data []byte, out map[string]struct{}) error {
	var pp localPyProject
	if _, err := decodeTOML(data, &pp); err != nil {
		return err
	}
	for name, src := range pp.Tool.Uv.Sources {
		if isLocalUVSource(src) {
			out[canonicalPackageName(name)] = struct{}{}
		}
	}
	for name, spec := range pp.Tool.Poetry.Dependencies {
		if strings.EqualFold(name, "python") {
			continue
		}
		if isLocalPoetryDep(spec) {
			out[canonicalPackageName(name)] = struct{}{}
		}
	}
	return nil
}

// isLocalUVSource reports whether a [tool.uv.sources] entry points at local
// code: a `path = "..."` (editable path dep) or `workspace = true` (workspace
// member). git/url sources are remote and left alone. uv also allows an array
// of source tables (one per environment marker); any local entry makes the
// dependency local.
func isLocalUVSource(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return sourceTableIsLocal(t)
	case []map[string]any:
		for _, e := range t {
			if sourceTableIsLocal(e) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if m, ok := e.(map[string]any); ok && sourceTableIsLocal(m) {
				return true
			}
		}
	}
	return false
}

func sourceTableIsLocal(m map[string]any) bool {
	if _, ok := m["path"]; ok {
		return true
	}
	if w, ok := m["workspace"].(bool); ok && w {
		return true
	}
	return false
}

// isLocalPoetryDep reports whether a [tool.poetry.dependencies] entry is a local
// path dependency (`{ path = "..." }`). Bare version strings and git/url tables
// are remote.
func isLocalPoetryDep(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, ok = m["path"]
	return ok
}
