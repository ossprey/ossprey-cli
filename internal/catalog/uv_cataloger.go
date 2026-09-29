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
	if err := exec.CommandContext(ctx, path, "--version").Run(); err != nil {
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
	cache, err := os.MkdirTemp("", "ossprey-uv-cache-")
	if err != nil {
		return nil, nil, fmt.Errorf("uv cache: %w", err)
	}
	defer os.RemoveAll(cache)

	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		dir := filepath.Dir(absPath)
		args := uvArgsForPyProject(dir)
		return runUV(ctx, c.uv, cache, dir, args, loc)
	}
	out, err := catalogByGlob(ctx, resolver, c.root, "**/pyproject.toml", "uv", parse)
	return out, nil, err
}

// uvArgsForPyProject picks the right uv invocation for a project dir.
// Prefers uv.lock (faster, deterministic), falls back to pip compile.
func uvArgsForPyProject(dir string) []string {
	if _, err := os.Stat(filepath.Join(dir, "uv.lock")); err == nil {
		return []string{
			"export",
			"--directory", dir,
			"--format", "requirements.txt",
			"--no-header",
			"--no-hashes",
			"--no-emit-project",
			"--no-progress",
		}
	}
	pyproject := filepath.Join(dir, "pyproject.toml")
	args := []string{"pip", "compile", "--universal", "--no-progress"}
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

var pyFloorClause = regexp.MustCompile(`^(\^|~=|~|>=|==)?\s*v?(\d+)\.(\d+)`)

// pythonConstraintFloor reads the lower bound out of a Poetry version
// constraint ("^3.12", "~3.11", ">=3.10,<4.0", "3.12.*", "^3.9 || ^3.11").
// With alternatives the lowest floor wins; if any alternative is unbounded
// below ("*", "<4", ">3.11"), the result is "" so uv is never constrained
// tighter than the project itself.
func pythonConstraintFloor(spec string) string {
	var best [2]int
	found := false
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
	cmd.WaitDelay = 5 * time.Second // the kill lands on uv, but Output still waits on pipes a PEP 517 build backend may hold
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
