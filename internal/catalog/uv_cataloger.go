package catalog

import (
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

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

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

func (c *UVCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locs, err := resolver.FilesByGlob("**/pyproject.toml")
	if err != nil {
		return nil, nil, fmt.Errorf("uv cataloger: find pyproject.toml: %w", err)
	}

	uv, err := exec.LookPath("uv")
	if err != nil {
		return nil, nil, nil // no uv on PATH — silently skip
	}

	seen := map[string]struct{}{}
	var out []pkg.Package
	for _, loc := range locs {
		root := filepath.Join(c.root, filepath.Dir(loc.RealPath))
		pkgs, err := runUV(uv, root, loc)
		if err != nil || len(pkgs) == 0 {
			continue
		}
		for _, p := range pkgs {
			key := p.Name + "@" + p.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil, nil
}

func runUV(uv, root string, loc file.Location) ([]pkg.Package, error) {
	pyproject := filepath.Join(root, "pyproject.toml")

	var cmd *exec.Cmd
	if fileExists(filepath.Join(root, "uv.lock")) {
		cmd = exec.Command(uv,
			"export",
			"--directory", root,
			"--format", "requirements.txt",
			"--no-header",
			"--no-hashes",
			"--no-emit-project",
			"--no-progress",
		)
	} else {
		cmd = exec.Command(uv,
			"pip", "compile",
			"--universal",
			"--no-progress",
			pyproject,
		)
	}

	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("uv resolve %s: %s", root, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("uv resolve %s: %w", root, err)
	}

	return parseUVOutput(stdout, loc), nil
}

func parseUVOutput(out []byte, loc file.Location) []pkg.Package {
	seen := map[string]struct{}{}
	var pkgs []pkg.Package
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
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
