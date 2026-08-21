package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/goccy/go-yaml"
)

// isWorkspaceMember reports whether dir is a declared workspace member of an ancestor (up to root) that ships a lockfile syft can read.
func isWorkspaceMember(dir, root string) bool {
	root, dir = filepath.Clean(root), filepath.Clean(dir)
	if dir == root {
		return false // the root manifest is never its own member
	}
	for a := filepath.Dir(dir); ; a = filepath.Dir(a) {
		if hasNpmLockfile(a) && declaresMember(a, dir) {
			return true
		}
		if a == root || a == filepath.Dir(a) {
			return false
		}
	}
}

// declaresMember reports whether ancestor's workspace globs cover dir.
func declaresMember(ancestor, dir string) bool {
	globs := workspaceGlobs(ancestor)
	if len(globs) == 0 {
		return false
	}
	rel, err := filepath.Rel(ancestor, dir)
	if err != nil {
		return false
	}
	return matchesWorkspaceGlobs(globs, filepath.ToSlash(rel))
}

// workspaceGlobs returns the patterns dir declares. pnpm-workspace.yaml wins where it exists: pnpm ignores package.json's "workspaces", and npm/yarn ignore the yaml.
func workspaceGlobs(dir string) []string {
	if data, err := os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil {
		return parsePnpmWorkspace(data)
	}
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	return parsePackageJSONWorkspaces(data)
}

// parsePackageJSONWorkspaces reads both shapes npm and yarn accept: a bare array, and the object form {"packages": [...]}. yarn 1's "nohoist" sibling is not a member list and is ignored.
func parsePackageJSONWorkspaces(data []byte) []string {
	var doc struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || len(doc.Workspaces) == 0 {
		return nil
	}
	var arr []string
	if json.Unmarshal(doc.Workspaces, &arr) == nil {
		return arr
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(doc.Workspaces, &obj) == nil {
		return obj.Packages
	}
	return nil
}

// parsePnpmWorkspace reads the top-level "packages" list from pnpm-workspace.yaml. No packages key claims no members: verified against pnpm 10, which then reports the root project alone.
func parsePnpmWorkspace(data []byte) []string {
	var doc struct {
		Packages []string `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	return doc.Packages
}

// matchesWorkspaceGlobs reports whether rel matches a positive glob and no "!" exclusion. All three resolvers hand negations to their globber as ignore patterns, so any exclusion wins wherever it is listed.
func matchesWorkspaceGlobs(globs []string, rel string) bool {
	if isVendoredPath(rel) {
		return false // every resolver hard-ignores **/node_modules/**
	}
	matched := false
	for _, raw := range globs {
		g, neg := strings.CutPrefix(strings.TrimSpace(raw), "!")
		if g = normalizeWorkspaceGlob(g); g == "" {
			continue
		}
		if neg {
			// An exclusion prunes its whole subtree: the widest of the three readings, so a doubtful path resolves itself rather than being silently skipped.
			if hit, _ := doublestar.Match(g+"/**", rel); hit {
				return false
			}
			continue
		}
		if hasDotSegment(rel) && !hasDotSegment(g) {
			continue // minimatch, fast-glob and picomatch all default to dot:false, so a dot-dir matches only a pattern that spells it out
		}
		if hit, _ := doublestar.Match(g, rel); hit {
			matched = true
		}
	}
	return matched
}

// hasDotSegment reports whether p has a path segment starting with "." beyond a bare ".".
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if len(seg) > 1 && seg[0] == '.' {
			return true
		}
	}
	return false
}

// normalizeWorkspaceGlob strips the decorations every real resolver strips: a leading "./", a trailing "/", and Windows separators.
func normalizeWorkspaceGlob(g string) string {
	g = filepath.ToSlash(strings.TrimSpace(g))
	return strings.TrimSuffix(strings.TrimPrefix(g, "./"), "/")
}
