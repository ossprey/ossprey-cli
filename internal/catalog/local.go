package catalog

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/file"
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
// stray file never fails the scan; the pyproject cataloguer names each one,
// with what skipping it here costs (withLocalSourcesCost).
func findLocalPackageNames(resolver file.Resolver, root string) map[string]struct{} {
	names := map[string]struct{}{}
	locs, err := resolver.FilesByGlob("**/pyproject.toml")
	if err != nil {
		return names
	}
	for _, loc := range locs {
		if isVendoredPath(loc.RealPath) {
			continue
		}
		data, err := readTOML(hostPath(root, loc.RealPath))
		if err != nil {
			continue
		}
		collectLocalNames(data, names)
	}
	return names
}

// withLocalSourcesCost adds to a pyproject.toml's read or parse error that its local packages go to PyPI, when its readable part declares any.
func withLocalSourcesCost(path string, err error) error {
	pe, ok := err.(*fs.PathError)
	if !ok || !declaresLocalSources(tomlPrefix(path)) {
		return err
	}
	return &fs.PathError{Op: pe.Op, Path: pe.Path, Err: fmt.Errorf("%w; any path or workspace package it declares is looked up on PyPI", pe.Err)}
}

// localSourceEntry matches a path or workspace source, the entries collectLocalNames marks local.
var localSourceEntry = regexp.MustCompile(`(^|[{,.\s])(path\s*=|workspace\s*=\s*true)`)

// declaresLocalSources reads TOML the parser refused line by line for [tool.uv.workspace], or a path or workspace entry under [tool.uv.sources] or [tool.poetry.dependencies].
func declaresLocalSources(data []byte) bool {
	bare := strings.NewReplacer(`"`, "", "'", "", " ", "", "\t", "")
	table := ""
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		key := table
		if strings.HasPrefix(line, "[") {
			table = bare.Replace(strings.Trim(line, "[]"))
			key = table
		} else if k, _, ok := strings.Cut(line, "="); ok {
			key = strings.TrimPrefix(table+"."+bare.Replace(k), ".")
		}
		under := func(t string) bool { return key == t || strings.HasPrefix(key, t+".") }
		if under("tool.uv.workspace") || (under("tool.uv.sources") || under("tool.poetry.dependencies")) && localSourceEntry.MatchString(line) {
			return true
		}
	}
	return false
}

// collectLocalNames parses one pyproject.toml and adds the canonical name of
// every locally-sourced package to out.
func collectLocalNames(data []byte, out map[string]struct{}) {
	var pp localPyProject
	if _, err := decodeTOML(data, &pp); err != nil {
		return
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
