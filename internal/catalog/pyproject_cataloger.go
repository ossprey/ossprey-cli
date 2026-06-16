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

var pep508 = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(.*)$`)

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
	// Drop PEP 508 environment markers ("; python_version >= ...") before
	// exactVersion runs — the marker carries its own comparators that would
	// otherwise be mistaken for the dependency's version.
	if i := strings.IndexByte(spec, ';'); i >= 0 {
		spec = spec[:i]
	}
	m := pep508.FindStringSubmatch(spec)
	if m == nil {
		return "", ""
	}
	return m[1], exactVersion(m[2])
}

func poetryVersion(v any) string {
	switch t := v.(type) {
	case string:
		return exactVersion(t)
	case map[string]any:
		if s, ok := t["version"].(string); ok {
			return exactVersion(s)
		}
	}
	return ""
}

// exactVersion returns the version ONLY when spec pins a single exact release —
// a bare concrete version ("4.17.21", poetry's default) or an equality
// constraint ("==1.2.3", npm "=1.2.3", PEP 440 "===1.0"). Every range, caret,
// tilde, compatible-release, wildcard or tag ("^1.2.3", "~1.2", ">=3 <4", "1.x",
// "*", "latest") returns "" so the entry stays versionless.
//
// A versionless entry folds (via mergeVersionless) into whatever a real
// resolver — uv, the npm lockfile cataloger, or syft — pins it to, or is
// resolved to latest by the backend. Guessing a version here (e.g. a range's
// lower bound) instead yields a concrete value that disagrees with the resolved
// one; the merge only collapses versionless↔versioned, so the guess survives as
// a duplicate component on a version the project never installs.
func exactVersion(spec string) string {
	s := strings.TrimSpace(spec)
	for _, op := range []string{"===", "==", "="} {
		if strings.HasPrefix(s, op) {
			s = strings.TrimSpace(s[len(op):])
			break
		}
	}
	return pinVersion(s) // "" unless s is itself a single concrete release
}

// concreteRelease matches a single pinned release: digits with at least one
// dot ("8.1.7", "4.2"), plus an optional prerelease/build suffix
// ("1.0.0-beta.1", "1.0+build"). It deliberately rejects bare majors ("8"),
// wildcards ("1.x", "*") and multi-constraint ranges ("3.4.1 <4.0.0",
// "1.0,<2.0") — none of which are real registry releases.
var concreteRelease = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+([.\-+][0-9A-Za-z.\-+]+)?$`)

// pinVersion keeps a version only when it is a single concrete release. A bare
// major like "8" is NOT a real registry release (it's what "^8"/">=8" collapse
// to once the operator is stripped) and pinning it produces purls like
// pkg:pypi/click@8 that 404. Anything that isn't a clean release returns ""
// (versionless) so registry resolution and the versionless merge fold it into
// the real package instead.
func pinVersion(v string) string {
	if !concreteRelease.MatchString(strings.TrimSpace(v)) {
		return ""
	}
	return strings.TrimSpace(v)
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
