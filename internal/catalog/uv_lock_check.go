package catalog

import (
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
	"github.com/anchore/syft/syft/pkg"
)

// uvProject is what a pyproject.toml declares that uv export reads.
type uvProject struct {
	Project struct {
		Name           string   `toml:"name"`
		RequiresPython string   `toml:"requires-python"`
		Dynamic        []string `toml:"dynamic"`
		Dependencies   []string `toml:"dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		UV struct {
			DevDependencies []string       `toml:"dev-dependencies"`
			Sources         map[string]any `toml:"sources"`
		} `toml:"uv"`
	} `toml:"tool"`
}

// uvLockReq is one requirement uv recorded the lock as made from.
type uvLockReq struct {
	Name      string `toml:"name"`
	Specifier string `toml:"specifier"`
	URL       string `toml:"url"`
	Git       string `toml:"git"`
	Path      string `toml:"path"`
	Directory string `toml:"directory"`
	Editable  string `toml:"editable"`
	Index     string `toml:"index"`
}

type uvLock struct {
	RequiresPython string `toml:"requires-python"`
	Manifest       struct {
		DependencyGroups map[string][]uvLockReq `toml:"dependency-groups"`
	} `toml:"manifest"`
	Package []struct {
		Source struct {
			Editable string `toml:"editable"`
			Virtual  string `toml:"virtual"`
		} `toml:"source"`
		Metadata struct {
			RequiresDist []uvLockReq            `toml:"requires-dist"`
			RequiresDev  map[string][]uvLockReq `toml:"requires-dev"`
		} `toml:"metadata"`
	} `toml:"package"`
}

// uvDrift is what a pyproject.toml declares that its uv.lock was not made from, read without running anything.
type uvDrift struct {
	project bool     // [project].dependencies
	groups  []string // dependency groups, as the pyproject names them
	dynamic bool     // the build backend computes the dependencies, so only running it could tell
	floor   string   // the lowest Python the project supports, for the refresh
}

func (d uvDrift) stale() bool { return d.project || len(d.groups) > 0 }

// checkUVLock compares dir's pyproject.toml with the requirements its uv.lock records for the root project.
func checkUVLock(dir string) uvDrift {
	var p uvProject
	data, err := readTOML(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return uvDrift{}
	}
	if _, err := decodeTOML(data, &p); err != nil {
		return uvDrift{}
	}
	d := uvDrift{dynamic: slices.Contains(p.Project.Dynamic, "dependencies"), floor: pythonConstraintFloor(p.Project.RequiresPython)}
	hasProject := p.Project.Name != "" || len(p.Project.Dependencies) > 0 || len(p.Project.Dynamic) > 0
	groups := pyprojectGroups(&p)
	everything := func() uvDrift {
		d.project = hasProject && !d.dynamic
		d.groups = slices.Sorted(maps.Keys(groups))
		return d
	}

	var lock uvLock
	lockData, ok := readRegularFile(filepath.Join(dir, "uv.lock"), maxLockBytes)
	if !ok || tomlDepthOver(lockData, maxLockDepth) {
		return everything()
	}
	if _, err := toml.Decode(string(lockData), &lock); err != nil {
		return everything()
	}
	if d.floor == "" {
		d.floor = pythonConstraintFloor(lock.RequiresPython)
	}
	locked := lock.Manifest.DependencyGroups
	var dist map[string]bool
	for _, l := range lock.Package {
		if l.Source.Editable == "." || l.Source.Virtual == "." {
			dist, locked = lockKeys(l.Metadata.RequiresDist), l.Metadata.RequiresDev
			break
		}
	}
	if hasProject && dist == nil {
		return everything()
	}

	sourced := map[string]bool{}
	for n := range p.Tool.UV.Sources {
		sourced[canonicalPackageName(n)] = true
	}
	missing := func(reqs []string, have map[string]bool) bool {
		for _, r := range reqs {
			if k, ok := pep508Key(r, sourced); !ok || !have[k] {
				return true
			}
		}
		return false
	}
	byGroup := map[string]map[string]bool{}
	for g, reqs := range locked {
		byGroup[canonicalPackageName(g)] = lockKeys(reqs)
	}
	d.project = !d.dynamic && missing(p.Project.Dependencies, dist)
	for g, reqs := range groups {
		if missing(reqs, byGroup[canonicalPackageName(g)]) {
			d.groups = append(d.groups, g)
		}
	}
	slices.Sort(d.groups)
	return d
}

// pyprojectGroups is each dependency group's own requirements, with tool.uv.dev-dependencies under "dev" as uv merges them; an include-group entry is left to the group it names.
func pyprojectGroups(p *uvProject) map[string][]string {
	groups := map[string][]string{}
	dev := "dev"
	for g, entries := range p.DependencyGroups {
		if canonicalPackageName(g) == "dev" {
			dev = g
		}
		reqs := []string{}
		for _, e := range entries {
			if s, ok := e.(string); ok {
				reqs = append(reqs, s)
			}
		}
		groups[g] = reqs
	}
	if len(p.Tool.UV.DevDependencies) > 0 {
		groups[dev] = append(groups[dev], p.Tool.UV.DevDependencies...)
	}
	return groups
}

func lockKeys(reqs []uvLockReq) map[string]bool {
	keys := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		switch {
		case r.URL != "":
			keys[directKey(r.Name, "url "+r.URL)] = true
		case r.Git != "" || r.Path != "" || r.Directory != "" || r.Editable != "" || r.Index != "":
			keys[directKey(r.Name, "source")] = true
		default:
			keys[requirementKey(r.Name, r.Specifier)] = true
		}
	}
	return keys
}

var pep508Head = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)

// pep508Key is a requirement's lock key: an archive URL keys on the URL, and any other direct reference or tool.uv.sources entry on its kind alone, as uv respells those.
func pep508Key(req string, sourced map[string]bool) (string, bool) {
	req, _, _ = strings.Cut(req, ";")
	m := pep508Head.FindStringSubmatch(req)
	if m == nil {
		return "", false
	}
	name, spec := m[1], m[2]
	if ref, ok := strings.CutPrefix(spec, "@"); ok {
		ref = strings.TrimSpace(ref)
		if l := strings.ToLower(ref); strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") {
			return directKey(name, "url "+ref), true
		}
		return directKey(name, "source"), true
	}
	if sourced[canonicalPackageName(name)] {
		return directKey(name, "source"), true
	}
	return requirementKey(name, spec), true
}

func directKey(name, source string) string {
	return canonicalPackageName(name) + " @ " + source
}

// requirementKey canonicalises name and specifier, so a reordered, respaced or parenthesised specifier still matches uv's form.
func requirementKey(name, spec string) string {
	spec = strings.ToLower(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '(' || r == ')' {
			return -1
		}
		return r
	}, spec))
	clauses := strings.Split(spec, ",")
	slices.Sort(clauses)
	return canonicalPackageName(name) + " " + strings.Join(clauses, ",")
}

// uvRefreshArgs resolves, never building, the project's dependencies (group "") or one dependency group, for every Python from floor up.
func uvRefreshArgs(dir, floor, group string) []string {
	pyproject := filepath.Join(dir, "pyproject.toml")
	// Without a floor uv resolves from the host's Python up, dropping a requirement marked for older ones; it targets the floor without fetching it.
	args := []string{"pip", "compile", "--universal", "--no-progress", "--no-build", "--no-python-downloads"}
	if floor != "" {
		args = append(args, "--python-version", floor)
	}
	if group != "" {
		return append(args, "--group", pyproject+":"+group)
	}
	return append(args, pyproject)
}

// mergePackages appends to a the packages of b it lacks.
func mergePackages(a, b []pkg.Package) []pkg.Package {
	seen := make(map[string]bool, len(a))
	for _, p := range a {
		seen[p.Name+"@"+p.Version] = true
	}
	for _, p := range b {
		if !seen[p.Name+"@"+p.Version] {
			seen[p.Name+"@"+p.Version] = true
			a = append(a, p)
		}
	}
	return a
}
