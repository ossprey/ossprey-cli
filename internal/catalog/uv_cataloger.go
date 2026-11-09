package catalog

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

var uvReqLine = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)==([^\s;]+)`)

// lookupUV returns the path to a *working* `uv`, and whether the host has one.
// Called once per scan by Catalog, which picks the Python resolver from it.
//
// The binary is run, not just found. Choosing uv is choosing *against* pip for
// the whole scan, so a uv that is on PATH but cannot execute — a stale shim, a
// wrong-architecture binary, a broken install — would otherwise fail every
// manifest with no fallback left, and leave those projects on direct
// dependencies alone. Mirrors findPython's probe.
//
// Resolution goes through lookTool, not exec.LookPath, so an ossprey shim at
// the front of PATH is skipped in favour of the real uv — running the shim
// would re-enter ossprey once per manifest until the resolve timeout fires.
func lookupUV(ctx context.Context) (string, bool) {
	path, err := lookTool("uv")
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = toolEnv()
	if err := cmd.Run(); err != nil {
		return "", false
	}
	return path, true
}

// UVCataloger resolves transitive Python deps by invoking the `uv` CLI.
// Prefers `uv export` against uv.lock when present, falls back to
// `uv pip compile --universal pyproject.toml`. Mirrors v1's uv fallback.
//
// uv is the resolved path to the binary; Catalog builds this cataloger only
// when lookupUV found a working one.
type UVCataloger struct {
	root string
	uv   string
}

func NewUVCataloger(root, uv string) *UVCataloger { return &UVCataloger{root: root, uv: uv} }

func (c *UVCataloger) Name() string { return "ossprey-uv-cataloger" }

func (c *UVCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// A cache that cannot be made fails each manifest (below), so each is
	// recorded unresolved.
	cache, cacheErr := os.MkdirTemp("", "ossprey-uv-cache-")
	if cacheErr == nil {
		defer os.RemoveAll(cache)
	}

	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		dir := filepath.Dir(absPath)
		if !hasUVLock(dir) {
			// uv pip compile reads [project] only.
			groupsLeftOut(ctx, c.root, "uv", absPath)
			// Without a [project] table uv can only learn the dependencies by
			// building the project, which --no-build refuses.
			if err := pyprojectNeedsBuild(absPath); err != nil || !hasPEP621Project(absPath) {
				return nil, err
			}
		}
		// uv export re-locks from the pyproject when the lock is stale, so
		// its dependencies are read either way, with those of every
		// workspace member and local source uv reads beside it.
		if err := uvProjectExpandsEnv(absPath, c.root); err != nil {
			return nil, err
		}
		if cacheErr != nil {
			return nil, fmt.Errorf("uv cache: %w", cacheErr)
		}
		// Extras are resolved too: their direct names reach the scan through
		// the pyproject fallback, so leaving their trees out would read as
		// complete. If they cannot resolve, the base tree still counts and
		// the manifest is marked unresolved.
		if !hasOptionalDependencies(absPath) {
			return runUV(ctx, c.uv, cache, dir, uvArgsForPyProject(dir, false), loc)
		}
		pkgs, err := runUV(ctx, c.uv, cache, dir, uvArgsForPyProject(dir, true), loc)
		if err == nil {
			return pkgs, nil
		}
		pkgs, baseErr := runUV(ctx, c.uv, cache, dir, uvArgsForPyProject(dir, false), loc)
		if baseErr != nil {
			return nil, baseErr
		}
		if !pythonCovered(c.root)(absPath) {
			warn.Add(ctx, catalogerEntry("uv", fmt.Errorf("%s: optional dependencies not resolved: %w", absPath, err)))
			markUnresolved(ctx, c.root, absPath)
		}
		return pkgs, nil
	}
	out, err := resolveByGlob(ctx, resolver, c.root, "**/pyproject.toml", "uv", pythonCovered(c.root), parse)
	return out, nil, err
}

// hasOptionalDependencies reports a [project] table declaring any extra.
func hasOptionalDependencies(path string) bool {
	pp, err := readPyProject(path)
	if err != nil || pp == nil {
		return false
	}
	for _, deps := range pp.Project.OptionalDependencies {
		if len(deps) > 0 {
			return true
		}
	}
	return false
}

func hasUVLock(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "uv.lock"))
	return err == nil
}

// uvArgsForPyProject picks the right uv invocation for a project dir.
// Prefers uv.lock (faster, deterministic), falls back to pip compile.
//
// Every scan-path uv call carries --no-build: an sdist-only dependency would
// otherwise have uv run its PEP 517 backend to read its metadata. Such a
// manifest fails instead and is reported unresolved.
func uvArgsForPyProject(dir string, allExtras bool) []string {
	var extras []string
	if allExtras {
		extras = []string{"--all-extras"}
	}
	if hasUVLock(dir) {
		return append([]string{
			"export",
			"--directory", dir,
			"--format", "requirements.txt",
			"--no-header",
			"--no-hashes",
			"--no-emit-project",
			"--no-progress",
			"--no-build",
		}, extras...)
	}
	pyproject := filepath.Join(dir, "pyproject.toml")
	args := append([]string{"pip", "compile", "--universal", "--no-progress", "--no-build"}, extras...)
	if floor := poetryPythonFloor(pyproject); floor != "" {
		args = append(args, "--python-version", floor)
	}
	return append(args, pyproject)
}

// poetryPythonFloor returns the minimum Python (as "major.minor") a Poetry
// project declares, for projects that carry no PEP 621 requires-python.
//
// `uv pip compile --universal` takes its Python floor from requires-python
// alone. A Poetry project states it as `[tool.poetry.dependencies] python =
// "^3.12"` instead, so uv falls back to its own default floor and a
// dependency requiring the project's real floor (e.g. Python>=3.12) comes back
// unsatisfiable, failing the whole manifest. "" leaves uv's behaviour as is:
// requires-python present, no Poetry python, or a constraint with no
// lower bound.
func poetryPythonFloor(path string) string {
	pp, err := readPyProject(path)
	if err != nil || pp == nil || pp.Project.RequiresPython != "" {
		return ""
	}
	spec, _ := pp.Tool.Poetry.Dependencies["python"].(string)
	return pythonConstraintFloor(spec)
}

var (
	pyFloorClause = regexp.MustCompile(`^(\^|~=|~|>=|==)?v?(\d+)\.(\d+)`)
	// Poetry allows whitespace after an operator ("< 4.0"); closing the gap
	// before splitting on spaces keeps each operator on its own version, so an
	// upper bound can never be read as a bare-version floor.
	pyOperatorGap = regexp.MustCompile(`([<>=!~^])\s+`)
)

// pythonConstraintFloor reads the lower bound out of a Poetry version
// constraint ("^3.12", "~3.11", ">=3.10,<4.0", "3.12.*", "^3.9 || ^3.11").
// With alternatives the lowest floor wins; if any alternative is unbounded
// below ("*", "<4", ">3.11"), the result is "" so uv is never constrained
// tighter than the project itself.
func pythonConstraintFloor(spec string) string {
	var best [2]int
	found := false
	spec = pyOperatorGap.ReplaceAllString(spec, "$1")
	for _, alt := range strings.Split(strings.ReplaceAll(spec, "||", "|"), "|") {
		var floor [2]int
		ok := false
		for _, clause := range strings.FieldsFunc(alt, func(r rune) bool { return r == ',' || r == ' ' }) {
			m := pyFloorClause.FindStringSubmatch(clause)
			if m == nil {
				continue
			}
			var v [2]int
			fmt.Sscan(m[2], &v[0])
			fmt.Sscan(m[3], &v[1])
			if !ok || v[0] > floor[0] || (v[0] == floor[0] && v[1] > floor[1]) {
				floor, ok = v, true
			}
		}
		if !ok {
			return ""
		}
		if !found || floor[0] < best[0] || (floor[0] == best[0] && floor[1] < best[1]) {
			best, found = floor, true
		}
	}
	if !found {
		return ""
	}
	return fmt.Sprintf("%d.%d", best[0], best[1])
}

func runUV(ctx context.Context, uv, cache, dir string, args []string, loc file.Location) ([]pkg.Package, error) {
	budget := resolverTimeout()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := exec.CommandContext(ctx, uv, args...)
	cmd.Env = toolEnv("UV_CACHE_DIR=" + cache)
	cmd.WaitDelay = 5 * time.Second // the kill lands on uv, but Output still waits on pipes a grandchild may hold
	stdout, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("uv %s: timed out after %s (raise OSSPREY_RESOLVE_TIMEOUT)", dir, budget)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, newToolError("uv", dir, string(ee.Stderr))
		}
		return nil, fmt.Errorf("uv %s: %w", dir, err)
	}
	return parseUVOutput(stdout, loc), nil
}

func parseUVOutput(out []byte, loc file.Location) []pkg.Package {
	seen := make(map[string]struct{})
	var pkgs []pkg.Package
	scan := bufio.NewScanner(bytes.NewReader(out))
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := uvReqLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.ToLower(m[1])
		version := m[2]
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, pkg.Package{
			Name:      name,
			Version:   version,
			Type:      pkg.PythonPkg,
			Locations: file.NewLocationSet(loc),
		})
	}
	return pkgs
}
