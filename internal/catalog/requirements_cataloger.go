package catalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// RequirementsCataloger resolves transitive Python deps from a requirements.txt
// by invoking `uv pip compile`. Syft's built-in cataloger reads the file
// literally (direct deps only); this fills in the transitive closure, pinning
// every dependency to a concrete version resolved against PyPI.
type RequirementsCataloger struct {
	root string
	uv   string
}

func NewRequirementsCataloger(root, uv string) *RequirementsCataloger {
	return &RequirementsCataloger{root: root, uv: uv}
}

func (c *RequirementsCataloger) Name() string { return "ossprey-requirements-cataloger" }

func (c *RequirementsCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	cache, err := os.MkdirTemp("", "ossprey-uv-cache-")
	if err != nil {
		return nil, nil, fmt.Errorf("uv cache: %w", err)
	}
	defer os.RemoveAll(cache)

	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		dir := filepath.Dir(absPath)
		args := []string{"pip", "compile", "--universal", "--no-progress", absPath}
		return runUV(ctx, c.uv, cache, dir, args, loc)
	}
	out, err := catalogByGlob(ctx, resolver, c.root, "**/requirements.txt", "requirements", parse)
	return out, nil, err
}
