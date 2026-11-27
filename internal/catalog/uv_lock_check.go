package catalog

import (
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
		Name         string   `toml:"name"`
		Dynamic      []string `toml:"dynamic"`
		Dependencies []string `toml:"dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		UV struct {
			DevDependencies []string `toml:"dev-dependencies"`
		} `toml:"uv"`
	} `toml:"tool"`
}

// uvLockReq is one requirement uv recorded the lock as made from.
type uvLockReq struct {
	Name      string `toml:"name"`
	Specifier string `toml:"specifier"`
}

type uvLock struct {
	Manifest struct {
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

// checkUVLock reports whether dir's pyproject.toml declares a requirement its uv.lock was not made from (stale), and whether the build backend computes the dependencies, so only running it could tell (dynamic).
func checkUVLock(dir string) (p *uvProject, stale, dynamic bool) {
	p = &uvProject{}
	data, err := readTOML(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return nil, true, false
	}
	if _, err := decodeTOML(data, p); err != nil {
		return nil, true, false
	}
	dynamic = slices.Contains(p.Project.Dynamic, "dependencies")

	var lock uvLock
	lockData, ok := readRegularFile(filepath.Join(dir, "uv.lock"), maxLockBytes)
	if !ok || tomlDepthOver(lockData, maxLockDepth) {
		return p, true, dynamic
	}
	if _, err := toml.Decode(string(lockData), &lock); err != nil {
		return p, true, dynamic
	}
	groups := lock.Manifest.DependencyGroups
	var dist map[string]bool
	for _, l := range lock.Package {
		if l.Source.Editable == "." || l.Source.Virtual == "." {
			dist, groups = lockKeys(l.Metadata.RequiresDist), l.Metadata.RequiresDev
			break
		}
	}
	hasProject := p.Project.Name != "" || len(p.Project.Dependencies) > 0 || len(p.Project.Dynamic) > 0
	if hasProject && dist == nil {
		return p, true, dynamic
	}

	missing := func(reqs []string, have map[string]bool) bool {
		for _, r := range reqs {
			if k, ok := pep508Key(r); !ok || !have[k] {
				return true
			}
		}
		return false
	}
	byGroup := map[string]map[string]bool{}
	for g, reqs := range groups {
		byGroup[canonicalPackageName(g)] = lockKeys(reqs)
	}
	if !dynamic && missing(p.Project.Dependencies, dist) {
		return p, true, dynamic
	}
	if missing(p.Tool.UV.DevDependencies, byGroup["dev"]) {
		return p, true, dynamic
	}
	for g, entries := range p.DependencyGroups {
		var reqs []string
		for _, e := range entries {
			if s, ok := e.(string); ok {
				reqs = append(reqs, s)
			}
		}
		if missing(reqs, byGroup[canonicalPackageName(g)]) {
			return p, true, dynamic
		}
	}
	return p, false, dynamic
}

func lockKeys(reqs []uvLockReq) map[string]bool {
	keys := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		keys[requirementKey(r.Name, r.Specifier)] = true
	}
	return keys
}

var pep508Head = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$`)

// pep508Key is a requirement's lock key; a direct URL keys on its name alone, as uv records it with no specifier.
func pep508Key(req string) (string, bool) {
	req, _, _ = strings.Cut(req, ";")
	m := pep508Head.FindStringSubmatch(req)
	if m == nil {
		return "", false
	}
	spec := m[2]
	if strings.HasPrefix(spec, "@") {
		spec = ""
	}
	return requirementKey(m[1], spec), true
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

// uvRefreshArgs resolves what dir's pyproject.toml declares now, never building, or nil when it declares nothing uv can read without a build.
func uvRefreshArgs(dir string, p *uvProject, dynamic bool) []string {
	pyproject := filepath.Join(dir, "pyproject.toml")
	args := []string{"pip", "compile", "--universal", "--no-progress", "--no-build"}
	var groups []string
	if p != nil {
		for g := range p.DependencyGroups {
			groups = append(groups, g)
		}
		if len(p.Tool.UV.DevDependencies) > 0 && !slices.Contains(groups, "dev") {
			groups = append(groups, "dev")
		}
	}
	slices.Sort(groups)
	for _, g := range groups {
		args = append(args, "--group", pyproject+":"+g)
	}
	if p != nil && !dynamic && (p.Project.Name != "" || len(p.Project.Dependencies) > 0) {
		return append(args, pyproject)
	}
	if len(groups) == 0 {
		return nil
	}
	return args
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
