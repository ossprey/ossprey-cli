package catalog

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

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

func (c *SetupPyCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
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
		// Skip if pyproject.toml in same dir AND has [project] table — UVCataloger
		// already covered it. We only run when the pyproject path failed (no
		// [project]) or pyproject is absent.
		if hasPEP621Project(filepath.Join(dir, "pyproject.toml")) {
			return nil, nil
		}
		args := []string{"pip", "compile", "--universal", "--no-progress", absPath}
		return runUV(ctx, uv, cache, dir, args, loc)
	}
	out, err := catalogByGlob(resolver, c.root, "**/setup.py", "setup.py", parse)
	return out, nil, err
}
