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

// PyProjectCataloger extracts direct dependencies declared in pyproject.toml
// ([project].dependencies, [project].optional-dependencies, [tool.poetry]).
// Last-resort fallback when uv is unavailable. Will NOT find transitives.
type PyProjectCataloger struct {
	root string
}

func NewPyProjectCataloger(root string) *PyProjectCataloger { return &PyProjectCataloger{root: root} }

func (c *PyProjectCataloger) Name() string { return "ossprey-pyproject-cataloger" }

func (c *PyProjectCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	out, err := catalogByGlob(resolver, c.root, "**/pyproject.toml", "pyproject", parsePyProjectFile)
	return out, nil, err
}

type pyproject struct {
	Project struct {
		Name                 string              `toml:"name"`
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

var pep508 = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==\s*([0-9A-Za-z._+!\-]+))?`)

func parsePyProjectFile(path string, loc file.Location) ([]pkg.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var pp pyproject
	if err := toml.Unmarshal(data, &pp); err != nil {
		return nil, err
	}

	rootName := normalizeName(pp.Project.Name)
	seen := make(map[string]struct{})
	var out []pkg.Package
	add := func(name, version string) {
		name = normalizeName(name)
		if name == "" || name == rootName {
			return
		}
		version = pinVersion(version)
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, pkg.Package{
			Name:      name,
			Version:   version,
			Type:      pkg.PythonPkg,
			Locations: file.NewLocationSet(loc),
		})
	}
	for _, dep := range pp.Project.Dependencies {
		if n, v := parsePEP508(dep); n != "" {
			add(n, v)
		}
	}
	for _, group := range pp.Project.OptionalDependencies {
		for _, dep := range group {
			if n, v := parsePEP508(dep); n != "" {
				add(n, v)
			}
		}
	}
	for n, spec := range pp.Tool.Poetry.Dependencies {
		if strings.EqualFold(n, "python") {
			continue
		}
		add(n, poetryVersion(spec))
	}
	for n, spec := range pp.Tool.Poetry.DevDependencies {
		add(n, poetryVersion(spec))
	}
	return out, nil
}

func parsePEP508(spec string) (string, string) {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.HasPrefix(spec, "#") {
		return "", ""
	}
	m := pep508.FindStringSubmatch(spec)
	if m == nil {
		return "", ""
	}
	return m[1], m[2]
}

func poetryVersion(v any) string {
	switch t := v.(type) {
	case string:
		return stripVersionOp(t)
	case map[string]any:
		if s, ok := t["version"].(string); ok {
			return stripVersionOp(s)
		}
	}
	return ""
}

func stripVersionOp(s string) string {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{"^", "~", ">=", "<=", ">", "<", "==", "!="} {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimSpace(s[len(prefix):])
		}
	}
	return s
}

// pinVersion keeps a version only when it looks like a concrete release
// (contains a dot, e.g. "8.1.7" or "4.2"). A bare major like "8" — what a
// range/caret constraint such as "^8", ">=8" or poetry "8" collapses to once
// the operator is stripped — is NOT a real registry release. Pinning it
// produces purls like pkg:pypi/click@8 that 404 on the registry and surface as
// spurious NOT_FOUND. Treat those as unpinned ("") so registry resolution and
// the versionless merge fold them into the real package instead.
func pinVersion(v string) string {
	if !strings.Contains(v, ".") {
		return ""
	}
	return v
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// hasPEP621Project returns true when path contains a parseable pyproject.toml
// with a non-empty [project] table (name OR dependencies). Used by other
// catalogers to skip work UVCataloger already covered.
func hasPEP621Project(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var pp pyproject
	if err := toml.Unmarshal(data, &pp); err != nil {
		return false
	}
	return pp.Project.Name != "" || len(pp.Project.Dependencies) > 0
}
