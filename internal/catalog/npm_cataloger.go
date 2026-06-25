package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
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
	npm, err := exec.LookPath("npm")
	if err != nil {
		return nil, nil, nil // no npm on PATH — silently skip
	}
	// One shared cache for the whole scan
	cache, err := os.MkdirTemp("", "ossprey-npm-cache-")
	if err != nil {
		return nil, nil, fmt.Errorf("npm cache: %w", err)
	}
	defer os.RemoveAll(cache)

	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		dir := filepath.Dir(absPath)
		if hasNpmLockfile(dir) {
			return nil, nil // syft's lock cataloger already resolves this project
		}
		return runNpmResolve(ctx, npm, cache, absPath, loc)
	}
	out, err := catalogByGlob(resolver, c.root, "**/package.json", "npm", parse)
	return out, nil, err
}

// hasNpmLockfile reports whether dir already ships a lockfile syft can read.
func hasNpmLockfile(dir string) bool {
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
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

	cmd := exec.CommandContext(ctx, npm, "install",
		"--package-lock-only",
		"--ignore-scripts",
		"--no-audit",
		"--no-fund",
		"--no-update-notifier",
	)
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "npm_config_cache="+cache)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("npm install --package-lock-only: %w: %s", err, strings.TrimSpace(string(out)))
	}

	lock, err := os.ReadFile(filepath.Join(tmp, "package-lock.json"))
	if err != nil {
		return nil, fmt.Errorf("npm produced no package-lock.json: %w", err)
	}
	return parseNpmLock(lock, loc)
}

type npmLockfile struct {
	Packages map[string]struct {
		Version  string `json:"version"`
		Resolved string `json:"resolved"`
	} `json:"packages"`
}

// parseNpmLock extracts resolved (name, version) pairs from an npm
// lockfileVersion 2/3 document. Only entries with a registry tarball
// ("resolved") are emitted — the root project and file:/link: deps have none
// and are not fetchable from the registry.
func parseNpmLock(data []byte, loc file.Location) ([]pkg.Package, error) {
	var lf npmLockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var pkgs []pkg.Package
	for key, entry := range lf.Packages {
		if key == "" || entry.Version == "" || entry.Resolved == "" {
			continue // root project / local (file:,link:) dep — not on the registry
		}
		name := npmNameFromLockKey(key)
		if name == "" {
			continue
		}
		dk := name + "@" + entry.Version
		if _, ok := seen[dk]; ok {
			continue
		}
		seen[dk] = struct{}{}
		pkgs = append(pkgs, pkg.Package{
			Name:      name,
			Version:   entry.Version,
			Type:      pkg.NpmPkg,
			Locations: file.NewLocationSet(loc),
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
