package catalog

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

// IsWorkspaceRoot reports whether dir is the root of a workspace whose members
// a bare install there would also install: npm, yarn and bun `workspaces` in
// package.json, pnpm-workspace.yaml `packages`, or a uv `[tool.uv.workspace]`.
// The members' manifests sit below dir, so a scan of dir alone (MaxDepth 1)
// would miss the dependencies of every member a missing lockfile leaves
// unrecorded at the root; the forwarder scans the whole tree instead.
//
// It errs toward true: a manifest that exists but cannot be read or parsed
// gives up the shallow scan rather than risk an unchecked member.
func IsWorkspaceRoot(dir string) bool {
	// pnpm-workspace.yaml wins over package.json, as in workspaceGlobs. One
	// with no packages key claims no members (pnpm 10 reports the root alone).
	if data, err := os.ReadFile(filepath.Join(dir, "pnpm-workspace.yaml")); err == nil {
		return len(parsePnpmWorkspace(data)) > 0 || !validPnpmWorkspace(data)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		if !json.Valid(data) || len(parsePackageJSONWorkspaces(data)) > 0 {
			return true
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return uvWorkspaceRoot(filepath.Join(dir, "pyproject.toml"))
}

// validPnpmWorkspace reports whether data parses as YAML at all, so that a
// broken file errs toward the full scan while a valid one without packages
// does not.
func validPnpmWorkspace(data []byte) bool {
	var doc any
	return yaml.Unmarshal(data, &doc) == nil
}

// uvWorkspaceRoot reports whether the pyproject.toml at path declares a uv
// workspace. A missing file is no workspace; one that cannot be read or
// decoded counts as one.
func uvWorkspaceRoot(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false
	}
	data, err := readTOML(path)
	if err != nil {
		return true
	}
	var doc struct {
		Tool struct {
			UV struct {
				Workspace *map[string]any `toml:"workspace"`
			} `toml:"uv"`
		} `toml:"tool"`
	}
	if _, err := decodeTOML(data, &doc); err != nil {
		return true
	}
	return doc.Tool.UV.Workspace != nil
}
