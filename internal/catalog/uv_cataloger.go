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

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// ErrUVNotAvailable signals the `uv` binary is missing.
var ErrUVNotAvailable = errors.New("uv binary not found on PATH")

var uvReqLine = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)==([^\s;]+)`)

// UVCataloger resolves transitive Python deps by invoking the `uv` CLI.
// Prefers `uv export` against uv.lock when present, falls back to
// `uv pip compile --universal pyproject.toml`. Mirrors v1's uv fallback.
type UVCataloger struct {
	root string
}

func NewUVCataloger(root string) *UVCataloger { return &UVCataloger{root: root} }

func (c *UVCataloger) Name() string { return "ossprey-uv-cataloger" }

func (c *UVCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	uv, err := exec.LookPath("uv")
	if err != nil {
		return nil, nil, nil // no uv on PATH — silently skip
	}

	cache, err := os.MkdirTemp("", "ossprey-uv-cache-")
	if err != nil {
		return nil, nil, fmt.Errorf("uv cache: %w", err)
	}
	defer os.RemoveAll(cache)

	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		dir := filepath.Dir(absPath)
		args := uvArgsForPyProject(dir)
		return runUV(ctx, uv, cache, dir, args, loc)
	}
	out, err := catalogByGlob(resolver, c.root, "**/pyproject.toml", "uv", parse)
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
	return []string{
		"pip", "compile",
		"--universal",
		"--no-progress",
		filepath.Join(dir, "pyproject.toml"),
	}
}

func runUV(ctx context.Context, uv, cache, dir string, args []string, loc file.Location) ([]pkg.Package, error) {
	cmd := exec.CommandContext(ctx, uv, args...)
	cmd.Env = append(os.Environ(), "UV_CACHE_DIR="+cache)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("uv %s: %s", dir, strings.TrimSpace(string(ee.Stderr)))
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
