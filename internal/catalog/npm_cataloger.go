package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/goccy/go-yaml"
)

// NpmResolveCataloger resolves npm dependencies to concrete versions by running
// `npm install --package-lock-only` against a package.json that ships no
// committed lockfile, then reading the generated package-lock.json. It is the
// npm analogue of UVCataloger: it fills the resolution gap so package.json
// ranges ("^1.2.3", ">=3 <4", "latest") become the real installed versions
// instead of staying versionless. When a lockfile already exists, syft's own
// lock cataloger handles it and this cataloger stands down.
type NpmResolveCataloger struct {
	root string
}

func NewNpmResolveCataloger(root string) *NpmResolveCataloger {
	return &NpmResolveCataloger{root: root}
}

func (c *NpmResolveCataloger) Name() string { return "ossprey-npm-cataloger" }

func (c *NpmResolveCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	npm, err := lookTool("npm")
	if err != nil {
		// No real npm on PATH: the package.json fallback keeps the direct
		// dependencies, and the manifests that needed resolving say so.
		_, err := resolveByGlob(ctx, resolver, c.root, "**/package.json", "npm", nil, func(absPath string, loc file.Location) ([]pkg.Package, error) {
			if c.standsDown(absPath) {
				return nil, nil
			}
			if !declaresNpmDependencies(absPath) {
				return nil, nil
			}
			return nil, fmt.Errorf("%s: no npm on PATH to resolve it, so direct dependencies only", filepath.Dir(absPath))
		})
		return nil, nil, err
	}
	// One shared cache for the whole scan. One that cannot be made fails each
	// manifest, so each is recorded unresolved.
	cache, cacheErr := os.MkdirTemp("", "ossprey-npm-cache-")
	if cacheErr == nil {
		defer os.RemoveAll(cache)
	}

	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		if c.standsDown(absPath) {
			return nil, nil
		}
		if cacheErr != nil {
			if !declaresNpmDependencies(absPath) {
				return nil, nil
			}
			return nil, fmt.Errorf("npm cache: %w", cacheErr)
		}
		return runNpmResolve(ctx, npm, cache, absPath, loc)
	}
	out, err := resolveByGlob(ctx, resolver, c.root, "**/package.json", "npm", nil, parse)
	return out, nil, err
}

// standsDown reports a package.json whose tree a lockfile already carries:
// its own (syft reads it), or an ancestor's that declares it a workspace member.
func (c *NpmResolveCataloger) standsDown(packageJSON string) bool {
	dir := filepath.Dir(packageJSON)
	return hasNpmLockfile(dir) || isWorkspaceMember(dir, c.root)
}

// hasNpmLockfile reports whether dir already ships a lockfile syft can read.
// Present is not enough: a truncated or corrupt lock stood the resolve down
// while syft could read nothing from it, so the project's tree was missing
// from the scan and nothing recorded it.
func hasNpmLockfile(dir string) bool {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		if npmLockReadable(filepath.Join(dir, name)) {
			return true
		}
	}
	return false
}

// hasNpmLockTree reports whether dir ships a lockfile with a locked tree, the
// test for covering workspace members: a root-only lock beside a root
// declaring nothing covers that root alone, never members it locked nothing for.
func hasNpmLockTree(dir string) bool {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		if st := npmLockState(filepath.Join(dir, name)); st.parses && st.locks {
			return true
		}
	}
	return false
}

// declaresNpmDependencies reports a package.json with any direct dependency,
// optionalDependencies included (npm installs them by default); one that
// cannot be read counts as declaring some. The package.json fallback does not
// emit optional ones, so they are read here rather than in its parser.
func declaresNpmDependencies(path string) bool {
	direct, err := parsePackageJSONFile(path, file.Location{})
	if err != nil || len(direct) > 0 {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return !errors.Is(err, os.ErrNotExist)
	}
	var pj struct {
		Optional map[string]string `json:"optionalDependencies"`
	}
	if json.Unmarshal(data, &pj) != nil {
		return true
	}
	for _, spec := range pj.Optional {
		if !isLocalNpmVersion(spec) {
			return true
		}
	}
	return false
}

// npmLockReadCache memoises npmLockState by path, size and modification
// time: a monorepo root lock is consulted once per workspace member.
var npmLockReadCache sync.Map

type npmLock struct{ parses, locks bool }

// npmLockState reads the lockfile at path: whether it exists and, for npm's
// JSON locks, parses, and whether it locks any package. yarn.lock and
// pnpm-lock.yaml count as both when present: an empty one is how a project
// with no dependencies ships, and syft has its own parsers for their several
// formats.
func npmLockState(path string) npmLock {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return npmLock{}
	}
	key := fmt.Sprintf("%s\x00%d\x00%d", path, info.Size(), info.ModTime().UnixNano())
	if v, ok := npmLockReadCache.Load(key); ok {
		return v.(npmLock)
	}
	var st npmLock
	if data, err := readBoundedFile(path, maxLockfileBytes); err == nil {
		switch filepath.Base(path) {
		case "package-lock.json", "npm-shrinkwrap.json":
			_, err := parseNpmLock(data, file.Location{})
			st = npmLock{parses: err == nil, locks: err == nil && npmLockLocksSomething(data)}
		default:
			st = yarnPnpmLockState(filepath.Base(path), data)
		}
	}
	npmLockReadCache.Store(key, st)
	return st
}

// yarnPnpmLockState judges a yarn.lock or pnpm-lock.yaml by its structure,
// since syft has its own parsers for their several formats and presence alone
// says nothing: an empty one parses and locks nothing (how a project with no
// dependencies ships); a pnpm lock must be YAML with a lockfileVersion; a
// yarn berry lock (one with __metadata) must be YAML, and a classic one must
// have an entry header, an unindented line ending in a colon.
func yarnPnpmLockState(name string, data []byte) npmLock {
	if len(bytes.TrimSpace(data)) == 0 {
		return npmLock{parses: true}
	}
	if name == "pnpm-lock.yaml" {
		var doc map[string]any
		if yaml.Unmarshal(data, &doc) != nil {
			return npmLock{}
		}
		_, ok := doc["lockfileVersion"]
		// Only package records are a tree: importers alone name the
		// project's requirements, not what they resolved to (v9 keeps the
		// records in packages and snapshots, earlier versions in packages).
		packages, _ := doc["packages"].(map[string]any)
		snapshots, _ := doc["snapshots"].(map[string]any)
		return npmLock{parses: ok, locks: ok && (len(packages) > 0 || len(snapshots) > 0)}
	}
	headers, berry := 0, false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		if strings.HasPrefix(line, "__metadata:") {
			berry = true
		}
		if strings.HasSuffix(line, ":") {
			headers++
		}
	}
	if berry {
		var doc map[string]any
		ok := yaml.Unmarshal(data, &doc) == nil
		return npmLock{parses: ok, locks: ok && len(doc) > 1}
	}
	return npmLock{parses: headers > 0, locks: headers > 0}
}

// npmLockReadable reports whether the lockfile at path covers the package.json
// beside it: it parses, and locks something unless that manifest declares nothing.
func npmLockReadable(path string) bool {
	st := npmLockState(path)
	return st.parses && (st.locks || !declaresNpmDependencies(filepath.Join(filepath.Dir(path), "package.json")))
}

// runNpmResolve copies package.json into a throwaway dir, generates a lockfile
// with `npm install --package-lock-only` (resolution only — no node_modules,
// no install scripts), and parses the resolved versions. The temp dir keeps the
// user's working tree clean; --ignore-scripts guarantees we never execute code
// from the (potentially malicious) dependency tree we are about to scan. cache
// is the scan-wide shared npm cache.
func runNpmResolve(ctx context.Context, npm, cache, packageJSON string, loc file.Location) ([]pkg.Package, error) {
	tmp, err := os.MkdirTemp("", "ossprey-npm-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	data, err := os.ReadFile(packageJSON)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), data, 0o644); err != nil {
		return nil, err
	}

	budget := resolverTimeout()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := exec.CommandContext(ctx, npm, "install",
		"--package-lock-only",
		"--ignore-scripts",
		"--no-audit",
		"--no-fund",
		"--no-update-notifier",
	)
	cmd.Dir = tmp
	cmd.Env = toolEnv("npm_config_cache=" + cache)
	cmd.WaitDelay = 5 * time.Second // the kill lands on npm, but CombinedOutput still waits on pipes a grandchild may hold
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("npm install --package-lock-only: timed out after %s (raise OSSPREY_RESOLVE_TIMEOUT)", budget)
		}
		// ErrWaitDelay replaces a successful exit, so npm finished and only a
		// grandchild's pipe lingered; the lock it wrote is complete.
		if !errors.Is(runErr, exec.ErrWaitDelay) {
			return nil, newToolError("npm", filepath.Dir(packageJSON), string(out))
		}
	}

	lock, err := os.ReadFile(filepath.Join(tmp, "package-lock.json"))
	if err != nil {
		if runErr != nil {
			return nil, newToolError("npm", filepath.Dir(packageJSON), string(out))
		}
		return nil, fmt.Errorf("npm produced no package-lock.json: %w", err)
	}
	return parseNpmLock(lock, loc)
}

type npmLockfile struct {
	Packages map[string]struct {
		// Name is set for an alias (`renamed@npm:left-pad`): the real
		// package, where the key names the directory it is installed as.
		Name     string `json:"name"`
		Version  string `json:"version"`
		Resolved string `json:"resolved"`
		// Link marks a symlink to a local package (a workspace member or a
		// file: dependency), whose Resolved is the path linked to.
		Link bool `json:"link"`
		// npm's dependency kinds: recorded in the lock whatever the omit
		// policy, and left out of an install that omits them. DevOptional
		// is reached both through a dev edge and an optional one, so only
		// omitting both leaves it out.
		Dev         bool `json:"dev"`
		Optional    bool `json:"optional"`
		DevOptional bool `json:"devOptional"`
		Peer        bool `json:"peer"`
	} `json:"packages"`
}

// parseNpmLock extracts resolved (name, version) pairs from an npm
// lockfileVersion 2/3 document. The root project, links and the local
// packages they point at (file:, workspaces) are left out, since they are
// not fetched from a registry. An installed entry without a "resolved"
// field is kept with no registry recorded: npm omits the field under
// omit-lockfile-registry-resolved, and a package it installed from a
// registry it did not name is one to check, not to drop.
func parseNpmLock(data []byte, loc file.Location) ([]pkg.Package, error) {
	return parseNpmLockAt(data, loc, "")
}

// parseNpmLockAt is parseNpmLock for a lock beside the tree it describes,
// at root: an entry whose directory is not on disk is left out, since the
// lock records what was resolved, omitted dependencies included, and only
// what was installed can run. A root without node_modules at all is read
// as the lock says, which can only check more.
func parseNpmLockAt(data []byte, loc file.Location, root string) ([]pkg.Package, error) {
	var lf npmLockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	installed := func(string) bool { return true }
	if root != "" {
		if _, err := os.Stat(filepath.Join(root, "node_modules")); err == nil {
			installed = func(key string) bool {
				_, err := os.Stat(filepath.Join(root, filepath.FromSlash(key)))
				return err == nil
			}
		}
	}
	seen := make(map[string]int)
	var pkgs []pkg.Package
	for key, entry := range lf.Packages {
		if key == "" || entry.Version == "" || entry.Link || !installed(key) {
			continue // root project, a link to a local package, or not on disk
		}
		if entry.Resolved == "" && !strings.Contains(key, "node_modules/") {
			continue // a local package in the tree (a workspace member), not installed from a registry
		}
		name := entry.Name // an alias names the real package here
		if name == "" {
			name = npmNameFromLockKey(key)
		}
		if name == "" {
			continue
		}
		dk := name + "@" + entry.Version
		copyKinds := DependencyKinds{Dev: entry.Dev, Optional: entry.Optional, DevOptional: entry.DevOptional, Peer: entry.Peer}
		kind := registrySource{URL: entry.Resolved, Dev: entry.Dev, Optional: entry.Optional, DevOptional: entry.DevOptional, Peer: entry.Peer,
			Copies: []DependencyKinds{copyKinds}}
		if i, ok := seen[dk]; ok {
			// The same release can sit at several paths (nested copies),
			// each with its own kind. An install leaves the release out
			// only if it leaves every copy out, so a kind survives the
			// merge only when every copy carries it; map order must not
			// decide which copy is read first. Nor may it decide the
			// registry: copies fetched from different places record none,
			// since no registry means checked and one copy fetched
			// publicly is enough to need that.
			have := pkgs[i].Metadata.(registrySource)
			if have.URL != kind.URL {
				have.URL = ""
			}
			have.Dev = have.Dev && kind.Dev
			have.Optional = have.Optional && kind.Optional
			have.DevOptional = have.DevOptional && kind.DevOptional
			have.Peer = have.Peer && kind.Peer
			// The AND alone loses which copy is left out under which policy
			// (a dev-only copy beside an optional-only one is left out
			// entirely under --omit=dev --omit=optional), so each copy's
			// kinds are kept as well.
			have.Copies = append(have.Copies, copyKinds)
			pkgs[i].Metadata = have
			continue
		}
		seen[dk] = len(pkgs)
		pkgs = append(pkgs, pkg.Package{
			Name:      name,
			Version:   entry.Version,
			Type:      pkg.NpmPkg,
			Locations: file.NewLocationSet(loc),
			Metadata:  kind,
		})
	}
	return pkgs, nil
}

// npmNameFromLockKey turns a package-lock "packages" key into a package name:
// "node_modules/lodash" -> "lodash",
// "node_modules/@types/bun" -> "@types/bun",
// "node_modules/a/node_modules/b" -> "b" (nested dep).
func npmNameFromLockKey(key string) string {
	const marker = "node_modules/"
	if i := strings.LastIndex(key, marker); i >= 0 {
		return key[i+len(marker):]
	}
	return key
}
