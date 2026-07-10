package catalog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
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
// cataloguers. Best-effort: unreadable or malformed manifests are ignored so a
// stray file never fails the scan.
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
		data, err := os.ReadFile(filepath.Join(root, loc.RealPath))
		if err != nil {
			continue
		}
		collectLocalNames(data, names)
	}
	return names
}

// collectLocalNames parses one pyproject.toml and adds the canonical name of
// every locally-sourced package to out.
func collectLocalNames(data []byte, out map[string]struct{}) {
	var pp localPyProject
	if err := toml.Unmarshal(data, &pp); err != nil {
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
