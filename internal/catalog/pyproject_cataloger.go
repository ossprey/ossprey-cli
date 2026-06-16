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
	// floorVersion runs — the marker carries its own comparators that would
	// otherwise be mistaken for the dependency's version bound.
	if i := strings.IndexByte(spec, ';'); i >= 0 {
		spec = spec[:i]
	}
	m := pep508.FindStringSubmatch(spec)
	if m == nil {
		return "", ""
	}
	return m[1], floorVersion(m[2])
}

func poetryVersion(v any) string {
	switch t := v.(type) {
	case string:
		return floorVersion(t)
	case map[string]any:
		if s, ok := t["version"].(string); ok {
			return floorVersion(s)
		}
	}
	return ""
}

// constraintRe pulls (optional operator, version) pairs out of a constraint
// string, so it can walk space- or comma-separated multi-bound ranges like
// ">=3.4.1 <4.0.0" or ">=1.0,<2.0".
var constraintRe = regexp.MustCompile(`(===|>=|<=|==|!=|~=|\^|~|>|<)?\s*([0-9][0-9A-Za-z.+!*\-]*)`)

// floorVersion returns the lower bound of a version constraint as a concrete
// release, or "" when there is no concrete floor. npm/poetry/PEP 440 ranges can
// carry several comparators; only a lower bound (>=, >, ^, ~, ~=, ==, ===, or a
// bare leading version) names a release the project actually runs, so we scan
// that. Upper bounds (<, <=) and exclusions (!=) are skipped — pinning them
// would scan a version the manifest specifically forbids (the bootstrap
// ">=3.4.1 <4.0.0" → bootstrap@5.x drift). The chosen bound still passes
// through pinVersion, so a bare-major lower bound like ">=8" stays versionless
// rather than producing the bogus pkg:.../...@8.
func floorVersion(spec string) string {
	for _, m := range constraintRe.FindAllStringSubmatch(spec, -1) {
		switch m[1] {
		case "<", "<=", "!=":
			continue
		}
		if v := pinVersion(m[2]); v != "" {
			return v
		}
	}
	return ""
}

// concreteRelease matches a single pinned release: digits with at least one
// dot ("8.1.7", "4.2"), plus an optional prerelease/build suffix
// ("1.0.0-beta.1", "1.0+build"). It deliberately rejects bare majors ("8"),
// wildcards ("1.x", "*") and multi-constraint ranges ("3.4.1 <4.0.0",
// "1.0,<2.0") — none of which are real registry releases.
var concreteRelease = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+([.\-+][0-9A-Za-z.\-+]+)?$`)

// pinVersion keeps a version only when it is a single concrete release. A bare
// major like "8" — what a range/caret constraint such as "^8", ">=8" or poetry
// "8" collapses to once the operator is stripped — is NOT a real registry
// release. Worse, stripVersionOp only removes ONE leading operator, so a
// multi-bound npm/poetry range like ">=3.4.1 <4.0.0" leaks through as
// "3.4.1 <4.0.0". Both produce purls (pkg:pypi/click@8,
// pkg:npm/bootstrap@3.4.1 <4.0.0) that 404/405 on the registry and surface as
// spurious NOT_FOUND / 405 errors. Treat anything that isn't a clean release as
// unpinned ("") so registry resolution and the versionless merge fold them into
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
