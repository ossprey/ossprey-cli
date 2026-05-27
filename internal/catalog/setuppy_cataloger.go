package catalog

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// SetupPyCataloger resolves transitive deps from a `setup.py` file by
// invoking `uv pip compile setup.py`. Covers the case where pyproject.toml
// is missing or doesn't declare a `[project]` table (e.g. legacy
// setuptools projects, or pyprojects that only carry tool config like ruff).
//
// uv reads setuptools metadata via PEP 517 build isolation without
// executing project code beyond the build backend, then resolves the
// transitive tree against PyPI.
type SetupPyCataloger struct {
	root string
}

func NewSetupPyCataloger(root string) *SetupPyCataloger { return &SetupPyCataloger{root: root} }

func (c *SetupPyCataloger) Name() string { return "ossprey-setuppy-cataloger" }

func (c *SetupPyCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locs, err := resolver.FilesByGlob("**/setup.py")
	if err != nil {
		return nil, nil, fmt.Errorf("setup.py cataloger: glob: %w", err)
	}

	uv, err := exec.LookPath("uv")
	if err != nil {
		return nil, nil, nil // no uv on PATH — silently skip
	}

	seen := map[string]struct{}{}
	var out []pkg.Package
	for _, loc := range locs {
		root := filepath.Join(c.root, filepath.Dir(loc.RealPath))
		// Skip if pyproject.toml in same dir AND has [project] table — UVCataloger
		// already covered it. We only run when the pyproject path failed (no
		// [project]) or pyproject is absent.
		if hasPEP621Project(filepath.Join(root, "pyproject.toml")) {
			continue
		}
		pkgs, err := runUVCompileSetup(uv, root, loc)
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

func runUVCompileSetup(uv, root string, loc file.Location) ([]pkg.Package, error) {
	cmd := exec.Command(uv,
		"pip", "compile",
		"--universal",
		"--no-progress",
		filepath.Join(root, "setup.py"),
	)
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("uv compile setup.py %s: %s", root, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("uv compile setup.py %s: %w", root, err)
	}
	return parseUVOutput(stdout, loc), nil
}
