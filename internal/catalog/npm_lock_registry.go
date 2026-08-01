package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// npmLockClassifier decides, for entries syft parsed out of committed
// package-lock.json files, which ones name a package npm would fetch from the
// registry on install. Syft's NpmPackageLockEntry metadata only carries the
// "resolved" URL, and an absent "resolved" does NOT mean the entry is
// unpublished: npm omits it for cache-installed deps and hand-edited (or
// attacker-injected) lockfile entries, yet `npm install`/`npm ci` still fetch
// name@version from the registry. So for entries without a "resolved" URL we
// re-read the lockfile itself, where the packages-map key tells root project,
// workspace/path members and link: deps apart from real registry deps.
//
// Lockfiles are parsed at most once per Catalog run (cache keyed by path).
// Not safe for concurrent use — Catalog consumes cataloger output serially.
type npmLockClassifier struct {
	root  string
	cache map[string]map[string]struct{} // lockfile abs path -> registry name@version set
}

func newNpmLockClassifier(root string) *npmLockClassifier {
	return &npmLockClassifier{root: root, cache: map[string]map[string]struct{}{}}
}

// isRegistryDep reports whether the syft lock package p appears in its
// package-lock.json as a registry dependency (rather than the root project or
// a local workspace/link entry).
func (c *npmLockClassifier) isRegistryDep(p pkg.Package) bool {
	key := p.Name + "@" + p.Version
	for _, l := range p.Locations.ToSlice() {
		if filepath.Base(l.RealPath) != "package-lock.json" {
			continue
		}
		if _, ok := c.registryEntries(hostPath(c.root, l.RealPath))[key]; ok {
			return true
		}
	}
	return false
}

// committedNpmLock is the subset of package-lock.json needed to classify
// entries. "packages" is the lockfileVersion 2/3 shape; v1 lockfiles only
// carry "dependencies".
type committedNpmLock struct {
	Packages map[string]struct {
		Name     string `json:"name"` // set on the root ("") entry and on aliased deps
		Version  string `json:"version"`
		Resolved string `json:"resolved"`
		Link     bool   `json:"link"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

// registryEntries parses the lockfile at lockPath (once; cached, including
// failures) and returns the name@version set of its registry dependencies.
func (c *npmLockClassifier) registryEntries(lockPath string) map[string]struct{} {
	if set, ok := c.cache[lockPath]; ok {
		return set
	}
	set := map[string]struct{}{}
	c.cache[lockPath] = set

	data, err := os.ReadFile(lockPath)
	if err != nil {
		return set
	}
	var lf committedNpmLock
	if err := json.Unmarshal(data, &lf); err != nil {
		return set
	}

	if lf.Packages != nil { // lockfileVersion 2/3
		for key, e := range lf.Packages {
			// "" is the root project; a key outside node_modules is a
			// workspace/path member's own manifest — neither is on the registry.
			if key == "" || !strings.Contains(key, "node_modules/") {
				continue
			}
			if e.Link || e.Version == "" || isLocalNpmResolved(e.Resolved) {
				continue
			}
			name := e.Name // aliased dep: syft emits the real package name
			if name == "" {
				name = npmNameFromLockKey(key)
			}
			set[name+"@"+e.Version] = struct{}{}
		}
		return set
	}

	// lockfileVersion 1: every top-level "dependencies" entry is a dep (the
	// root project never appears); local/git deps carry a URL-ish version.
	for name, e := range lf.Dependencies {
		if e.Version == "" || strings.ContainsAny(e.Version, ":/") {
			continue
		}
		set[name+"@"+e.Version] = struct{}{}
	}
	return set
}

// isLocalNpmResolved reports whether a lockfile "resolved" value points at
// local code instead of a registry tarball.
func isLocalNpmResolved(resolved string) bool {
	return strings.HasPrefix(resolved, "file:") || strings.HasPrefix(resolved, "link:")
}
