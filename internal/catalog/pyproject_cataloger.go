package catalog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
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

func (c *PyProjectCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	out, err := catalogByGlob(ctx, resolver, c.root, "**/pyproject.toml", "pyproject", parsePyProjectFile)
	return out, nil, err
}

type pyproject struct {
	Project struct {
		Name                 string              `toml:"name"`
		RequiresPython       string              `toml:"requires-python"`
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		Dynamic              []string            `toml:"dynamic"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

var pep508 = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(.*)$`)

// readPyProject parses one pyproject.toml. A file that has vanished since the
// resolver globbed it yields (nil, nil) rather than an error.
func readPyProject(path string) (*pyproject, error) {
	data, err := readPyProjectData(path)
	if err != nil || data == nil {
		return nil, err
	}
	var pp pyproject
	if err := toml.Unmarshal(data, &pp); err != nil {
		return nil, err
	}
	return &pp, nil
}

// readPyProjectData reads a pyproject.toml as a regular file of at most
// maxManifestBytes that passes the structural TOML guard: it is repository
// content, and one linked to /dev/zero or nested without end must fail the
// manifest rather than the scan. A missing file is (nil, nil).
func readPyProjectData(path string) ([]byte, error) {
	data, err := readBoundedFile(path, maxManifestBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if err := proofTOMLError(data); err != nil {
		return nil, fmt.Errorf("%s %w", path, err)
	}
	return data, nil
}

func parsePyProjectFile(path string, loc file.Location) ([]pkg.Package, error) {
	pp, err := readPyProject(path)
	if err != nil || pp == nil {
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
// resolver — uv, the npm lockfile cataloger, or syft — pins it to; anything
// still versionless afterward defaults to the latest published release (see
// resolveVersionless). Guessing a version here (e.g. a range's lower bound)
// instead yields a concrete value that disagrees with the resolved one; the
// merge only collapses versionless↔versioned, so the guess survives as a
// duplicate component on a version the project never installs.
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
var concreteRelease = regexp.MustCompile(`^[0-9]+(\.[0-9]+)+([A-Za-z][0-9A-Za-z.\-+]*|[.\-+][0-9A-Za-z.\-+]+)?$`)

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
	pp, err := readPyProject(path)
	if err != nil || pp == nil {
		return false
	}
	return pp.Project.Name != "" || len(pp.Project.Dependencies) > 0
}

// pyprojectNeedsBuild reports, as an error, a pyproject.toml whose dependencies
// can only be learned by building the project: no [project] table, poetry
// dependencies, and no poetry.lock beside it to read them from instead.
// Building runs the project's backend, which a scan never does, so the manifest
// is reported unresolved. nil when there is nothing that needs it.
func pyprojectNeedsBuild(path string) error {
	pp, err := readPyProject(path)
	if err != nil {
		// Unreadable: nothing could resolve it, unless a lock covers it.
		if pyprojectLockCovered(path) {
			return nil
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	if pp == nil || hasPEP621Project(path) {
		return nil
	}
	deps := 0
	count := func(table map[string]any) {
		for name := range table {
			if name != "python" {
				deps++
			}
		}
	}
	count(pp.Tool.Poetry.Dependencies)
	count(pp.Tool.Poetry.DevDependencies) // poetry installs these too
	for _, g := range pp.Tool.Poetry.Group {
		count(g.Dependencies)
	}
	if deps == 0 {
		return nil
	}
	dir := filepath.Dir(path)
	if pyprojectLockCovered(path) {
		return nil
	}
	return fmt.Errorf("%s: poetry dependencies with no poetry.lock; resolving them would build the project, so direct dependencies only", dir)
}

// dynamicDependencies reports whether a [project] table leaves its
// dependencies to the build backend, which only a build would reveal.
func dynamicDependencies(pp *pyproject) bool {
	for _, d := range pp.Project.Dynamic {
		if d == "dependencies" || d == "optional-dependencies" {
			return true
		}
	}
	return false
}

// pythonLockfiles are the lockfiles beside a pyproject.toml that syft reads
// for the project's whole tree.
var pythonLockfiles = []string{"uv.lock", "poetry.lock", "pdm.lock"}

// tomlLockHasPackages reports a TOML lockfile (uv, poetry, pdm, Cargo; lock
// is its file name) that parses and locks at least one [[package]] with a
// name, and a version except in uv.lock (which omits it for a project with a
// dynamic version), fetched from outside the tree (lockedFromOutside). A stub
// such as `version = 1`, an empty [[package]] table, or a lock holding only
// the project itself and its local or workspace packages parses but supplies
// no tree for a registry or git dependency, so it must not stand in for one.
// Coverage is asked about only for a manifest that declares dependencies.
func tomlLockHasPackages(data []byte, lock string) bool {
	var doc struct {
		Package []map[string]any `toml:"package"`
	}
	// The structural guard runs first: a byte bound does not stop deeply
	// nested keys from exhausting the decoder.
	if proofTOMLError(data) != nil {
		return false
	}
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return false
	}
	for _, p := range doc.Package {
		name, _ := p["name"].(string)
		version, _ := p["version"].(string)
		if name == "" || (version == "" && lock != "uv.lock") {
			continue
		}
		if lockedFromOutside(lock, p) {
			return true
		}
	}
	return false
}

// lockedFromOutside reports a lock entry fetched from a registry, a git
// repository or a URL, rather than the project's own code: Cargo records no
// source for the root crate or a path crate; uv records editable, virtual,
// path or directory for local ones; poetry a directory or file source; pdm a
// path.
func lockedFromOutside(lock string, p map[string]any) bool {
	switch lock {
	case "Cargo.lock":
		source, _ := p["source"].(string)
		return source != ""
	case "uv.lock":
		source, _ := p["source"].(map[string]any)
		for _, k := range []string{"registry", "git", "url"} {
			if _, ok := source[k]; ok {
				return true
			}
		}
		return false
	case "poetry.lock":
		source, ok := p["source"].(map[string]any)
		if !ok {
			return true // a PyPI package records no source
		}
		kind, _ := source["type"].(string)
		return kind != "directory" && kind != "file"
	case "pdm.lock":
		_, local := p["path"]
		return !local
	}
	return true
}

// pythonCovered is pyprojectLockCovered, and for a uv workspace member also
// the root uv.lock (uvWorkspaceLockCovers), bounded by the scan root.
func pythonCovered(root string) func(string) bool {
	return func(path string) bool {
		return pyprojectLockCovered(path) || uvWorkspaceLockCovers(path, root)
	}
}

// uvWorkspaceLockCovers reports a pyproject that is a member of the nearest
// uv workspace above it inside the scan, whose root uv.lock locks every
// member's tree, so syft reads it from there. The nearest ancestor declaring
// [tool.uv.workspace] decides: one whose members globs do not list the
// project, whose exclude does, or that has no readable uv.lock covers
// nothing. An exclude glob with ** is not matched here, so it covers nothing.
func uvWorkspaceLockCovers(manifest, root string) bool {
	member := filepath.Dir(filepath.Clean(manifest))
	if member == filepath.Dir(member) {
		return false
	}
	for d := filepath.Dir(member); withinRoot(d, root); d = filepath.Dir(d) {
		l, err := readUVLists(filepath.Join(d, "pyproject.toml"))
		if err != nil {
			return false
		}
		if ws := l.Tool.UV.Workspace; ws != nil {
			rel, err := filepath.Rel(d, member)
			if err != nil {
				return false
			}
			rel = filepath.ToSlash(rel)
			match := func(globs []string) bool {
				for _, g := range globs {
					if ok, _ := path.Match(strings.TrimSuffix(filepath.ToSlash(g), "/"), rel); ok {
						return true
					}
				}
				return false
			}
			for _, g := range ws.Exclude {
				if strings.Contains(g, "**") {
					return false
				}
			}
			if !match(ws.Members) || match(ws.Exclude) {
				return false
			}
			data, err := readBoundedFile(filepath.Join(d, "uv.lock"), maxLockfileBytes)
			return err == nil && tomlLockHasPackages(data, "uv.lock")
		}
		if d == filepath.Dir(d) {
			break
		}
	}
	return false
}

// pyprojectLockCovered reports whether a lockfile beside the pyproject.toml
// at path parses, so syft has the transitive tree whether or not a resolver
// could produce one. A lock that does not parse covers nothing.
func pyprojectLockCovered(path string) bool {
	dir := filepath.Dir(path)
	for _, name := range pythonLockfiles {
		data, err := readBoundedFile(filepath.Join(dir, name), maxLockfileBytes)
		if err != nil {
			continue
		}
		if tomlLockHasPackages(data, name) {
			return true
		}
	}
	return false
}
