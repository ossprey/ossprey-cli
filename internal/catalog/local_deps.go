package catalog

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
)

// HasLocalDeps reports whether a manifest in dir names a dependency by local
// path: npm's `file:`/`link:`/`portal:` and bare paths, a uv source or poetry
// dependency with `path`, or a PEP 508 `name @ file:...` reference. A bare
// install there installs that directory's own dependencies too, and with no
// lockfile (or a stale one) they are recorded only in its manifest, below
// dir, where a scan of dir alone (MaxDepth 1) never reads. The forwarder
// scans the whole tree instead, as it did before the depth limit.
//
// Like IsWorkspaceRoot it errs toward true: a manifest that cannot be read or
// parsed counts, and so does a spelling that only might be a path. A wrong
// true costs the walk; a wrong false leaves a dependency unchecked.
func HasLocalDeps(dir string) bool {
	if data, found, err := readRootManifest(dir, "package.json"); err != nil {
		return true
	} else if found && packageJSONHasLocalDeps(data) {
		return true
	}
	if data, found, err := readRootManifest(dir, "pnpm-workspace.yaml"); err != nil {
		return true
	} else if found && pnpmWorkspaceHasLocalDeps(data) {
		return true
	}
	if data, found, err := readRootManifest(dir, "pyproject.toml"); err != nil {
		return true
	} else if found && pyprojectHasLocalDeps(data) {
		return true
	}
	return false
}

// pnpmWorkspaceHasLocalDeps reads the pnpm-workspace.yaml settings that hold
// dependency specs. pnpm 10 keeps `overrides` there, and a `catalog:`
// reference in package.json takes its spec from `catalog` or `catalogs`, so
// a local path in any of them is one the install follows.
func pnpmWorkspaceHasLocalDeps(data []byte) bool {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return true
	}
	for _, k := range []string{"overrides", "catalog", "catalogs"} {
		if anyString(doc[k], npmSpecReachesDisk) {
			return true
		}
	}
	return false
}

// npmDependencyKeys are the package.json fields whose values are dependency
// specs. overrides, resolutions and pnpm.overrides can redirect a registry
// dependency to a local directory, and a `catalog:` reference takes its spec
// from bun's catalog and catalogs, so they are read too; their values nest.
var npmDependencyKeys = []string{
	"dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
	"overrides", "resolutions", "catalog", "catalogs",
}

func packageJSONHasLocalDeps(data []byte) bool {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return true
	}
	fields := make([]json.RawMessage, 0, len(npmDependencyKeys)+1)
	for _, k := range npmDependencyKeys {
		fields = append(fields, doc[k])
	}
	var pnpm struct {
		Overrides json.RawMessage `json:"overrides"`
	}
	if raw, ok := doc["pnpm"]; ok && json.Unmarshal(raw, &pnpm) == nil {
		fields = append(fields, pnpm.Overrides)
	}
	for _, raw := range fields {
		if len(raw) == 0 {
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return true
		}
		if anyString(v, npmSpecReachesDisk) {
			return true
		}
	}
	return false
}

// npmSpecReachesDisk is isLocalNpmSpec plus a git repository on the local
// disk (`git+file:./vendor/x`), whose manifest may sit below the directory.
// The install resolver keeps its own narrower reading: it can clone such a
// repository, so it must not drop the dependency from its copy.
func npmSpecReachesDisk(spec string) bool {
	return isLocalNpmSpec(spec) || strings.HasPrefix(strings.TrimSpace(spec), "git+file:")
}

func pyprojectHasLocalDeps(data []byte) bool {
	var doc map[string]any
	if _, err := decodeTOML(data, &doc); err != nil {
		return true
	}
	project := tomlTable(doc, "project")
	tool := tomlTable(doc, "tool")
	uv := tomlTable(tool, "uv")
	poetry := tomlTable(tool, "poetry")

	// PEP 508 requirement strings: [project], [dependency-groups], uv's own.
	for _, v := range []any{
		project["dependencies"], project["optional-dependencies"],
		doc["dependency-groups"],
		uv["dev-dependencies"], uv["constraint-dependencies"], uv["override-dependencies"],
	} {
		if anyString(v, isLocalRequirement) {
			return true
		}
	}
	// uv sources: `x = { path = "..." }`, or `{ workspace = true }`, which
	// names a member directory wherever the workspace root is.
	if entryHasKey(uv["sources"], "path", "workspace") {
		return true
	}
	// Poetry: `x = { path = "..." }` in any dependency table, and the same as a
	// requirement string under a URL-style spelling.
	deps := []any{poetry["dependencies"], poetry["dev-dependencies"]}
	for _, g := range tomlTable(poetry, "group") {
		if t, ok := g.(map[string]any); ok {
			deps = append(deps, t["dependencies"])
		}
	}
	for _, v := range deps {
		if entryHasKey(v, "path") || anyString(v, isLocalRequirement) {
			return true
		}
	}
	// Dynamic dependencies come from wherever the build backend reads them:
	// setuptools from the files it names, hatch's requirements_txt hook from
	// its own. Either may sit in a subdirectory, so [project].dynamic counts
	// whatever the backend, and setuptools' table counts without it.
	if anyString(project["dynamic"], isDynamicDependencyField) {
		return true
	}
	dynamic := tomlTable(tomlTable(tool, "setuptools"), "dynamic")
	if dynamic["dependencies"] != nil || dynamic["optional-dependencies"] != nil {
		return true
	}
	return false
}

func isDynamicDependencyField(field string) bool {
	return field == "dependencies" || field == "optional-dependencies"
}

// localRequirement matches a direct reference to something on disk: PEP 508's
// `name @ file:///path`, a local git repository (`name @ git+file:///path`),
// the bare `name @ ./path` poetry and pip accept, and hatch's context form
// (`name @ {root:uri}/sub`), which expands to a file URL.
var localRequirement = regexp.MustCompile(`@\s*(file:|git\+file:|\{|\.|/|~/|[a-zA-Z]:[\\/])`)

func isLocalRequirement(req string) bool {
	return localRequirement.MatchString(req)
}

// tomlTable is the table at doc[key], or nil when it is absent or not a table.
func tomlTable(doc map[string]any, key string) map[string]any {
	t, _ := doc[key].(map[string]any)
	return t
}

// anyString reports whether match holds for a string anywhere inside v, a
// decoded JSON or TOML value.
func anyString(v any, match func(string) bool) bool {
	switch x := v.(type) {
	case string:
		return match(x)
	case []any:
		for _, e := range x {
			if anyString(e, match) {
				return true
			}
		}
	case []map[string]any:
		for _, e := range x {
			if anyString(e, match) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if anyString(e, match) {
				return true
			}
		}
	}
	return false
}

// entryHasKey reports whether any entry of the table v, a map of dependency
// name to spec, has one of keys set. The table's own keys are package names
// (PyPI has a `path`), so only the entries are searched.
func entryHasKey(v any, keys ...string) bool {
	table, _ := v.(map[string]any)
	for _, entry := range table {
		if anyKey(entry, keys...) {
			return true
		}
	}
	return false
}

// anyKey reports whether a table anywhere inside v has one of keys set to
// something other than false.
func anyKey(v any, keys ...string) bool {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if anyKey(e, keys...) {
				return true
			}
		}
	case []map[string]any:
		for _, e := range x {
			if anyKey(e, keys...) {
				return true
			}
		}
	case map[string]any:
		for _, k := range keys {
			if val, ok := x[k]; ok && val != false {
				return true
			}
		}
		for _, e := range x {
			if anyKey(e, keys...) {
				return true
			}
		}
	}
	return false
}
