package catalog

import (
	"encoding/json"
	"errors"
	"io/fs"
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
//
// Every format is probed, whichever manager is running. pnpm ignores
// package.json `workspaces` beside its own YAML, but npm, yarn, bun and uv
// ignore that YAML, and pnpm 10 keeps plain settings in one with no packages
// key, so a YAML that claims no members says nothing about the others.
func IsWorkspaceRoot(dir string) bool {
	if data, found, err := readRootManifest(dir, "pnpm-workspace.yaml"); err != nil {
		return true
	} else if found && (len(parsePnpmWorkspace(data)) > 0 || !validPnpmWorkspace(data)) {
		// One with no packages key claims no members (pnpm 10 reports the root alone).
		return true
	}
	if data, found, err := readRootManifest(dir, "package.json"); err != nil {
		return true
	} else if found && (!json.Valid(data) || len(parsePackageJSONWorkspaces(data)) > 0) {
		return true
	}
	return uvWorkspaceRoot(filepath.Join(dir, "pyproject.toml"))
}

// readRootManifest reads dir/name for the probes that pick a forwarder's scan
// depth. found is false for a missing file. err is non-nil for one that exists
// and cannot be read as a manifest: anything but a regular file (a FIFO would
// block the open, and these probes run before the install is forwarded) or one
// over the manifest size limit. Callers take an error as "scan everything".
func readRootManifest(dir, name string) (data []byte, found bool, err error) {
	data, err = readTOML(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	return data, err == nil, err
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
	data, found, err := readRootManifest(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return true
	}
	if !found {
		return false
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
