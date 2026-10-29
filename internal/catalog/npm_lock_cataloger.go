package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// NpmLockCataloger covers the npm lockfile shapes syft's lock cataloger misses:
//
//   - npm-shrinkwrap.json, which is package-lock.json under another name (npm
//     prefers it when both exist) but which syft never globs. hasNpmLockfile
//     counts it, so the npm resolve stands down for it: unread, its whole tree
//     went missing.
//   - lockfileVersion 1's nested "dependencies". Syft reads only the top
//     level, so every dependency npm could not hoist (is-odd -> is-number@6
//     beside a top-level is-number@7) was dropped.
//
// Overlap with syft's output is absorbed by Catalog's dedup.
type NpmLockCataloger struct {
	root string
}

func NewNpmLockCataloger(root string) *NpmLockCataloger { return &NpmLockCataloger{root: root} }

func (c *NpmLockCataloger) Name() string { return "ossprey-npm-lock-cataloger" }

func (c *NpmLockCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var out []pkg.Package
	for _, glob := range []string{"**/npm-shrinkwrap.json", "**/package-lock.json"} {
		pkgs, err := catalogByGlob(ctx, resolver, c.root, glob, "npm-lock", parseNpmLockFile)
		if err != nil {
			return out, nil, err
		}
		out = append(out, pkgs...)
	}
	return out, nil, nil
}

// npmLockDep is one lockfileVersion 1 "dependencies" entry, which nests.
type npmLockDep struct {
	Version      string                `json:"version"`
	Resolved     string                `json:"resolved"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

type npmLockDoc struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Resolved string `json:"resolved"`
		Link     bool   `json:"link"`
	} `json:"packages"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

// parseNpmLockFile emits the registry dependencies of one npm lockfile. A
// package-lock.json is read only at lockfileVersion 1 — syft reads 2 and 3
// completely — while a shrinkwrap is read in full.
func parseNpmLockFile(path string, loc file.Location) ([]pkg.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var doc npmLockDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	shrinkwrap := filepath.Base(path) == "npm-shrinkwrap.json"

	var out []pkg.Package
	add := func(name, version, resolved string) {
		out = append(out, pkg.Package{
			Name:      name,
			Version:   version,
			Type:      pkg.NpmPkg,
			Locations: file.NewLocationSet(loc),
			Metadata:  registrySource{URL: resolved},
		})
	}

	if doc.Packages != nil {
		if !shrinkwrap {
			return nil, nil // syft's lock cataloger reads v2/v3 package-locks
		}
		// The same rules npmLockClassifier applies to package-lock.json.
		for key, e := range doc.Packages {
			if key == "" || !strings.Contains(key, "node_modules/") {
				continue // root project / workspace member's own entry
			}
			if e.Link || e.Version == "" || isLocalNpmResolved(e.Resolved) {
				continue
			}
			name := e.Name // aliased dep: the real package name
			if name == "" {
				name = npmNameFromLockKey(key)
			}
			add(name, e.Version, e.Resolved)
		}
		return out, nil
	}
	if !shrinkwrap && doc.LockfileVersion != 1 {
		return nil, nil
	}

	var walk func(deps map[string]npmLockDep)
	walk = func(deps map[string]npmLockDep) {
		for name, d := range deps {
			if n, v, ok := npmV1Version(name, d.Version); ok && !isLocalNpmResolved(d.Resolved) {
				add(n, v, d.Resolved)
			}
			walk(d.Dependencies)
		}
	}
	walk(doc.Dependencies)
	return out, nil
}

// npmV1Version reads a v1 entry's "version", which is a version for a registry
// dep, "npm:<real>@<version>" for an alias, and a file:/git URL otherwise.
func npmV1Version(name, version string) (string, string, bool) {
	if alias, ok := strings.CutPrefix(version, "npm:"); ok {
		i := strings.LastIndex(alias, "@")
		if i <= 0 {
			return "", "", false
		}
		name, version = alias[:i], alias[i+1:]
	}
	if version == "" || strings.ContainsAny(version, ":/") {
		return "", "", false
	}
	return name, version, true
}
