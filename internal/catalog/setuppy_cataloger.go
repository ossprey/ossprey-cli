package catalog

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// SetupPyCataloger reports legacy setup.py projects as unresolved. It resolves
// nothing: the only way to learn a setup.py's dependencies is to run it, which
// is code from the tree being scanned. Syft's own setup.py parser still reads
// the literal install_requires, so the project keeps its direct dependencies;
// this makes the missing transitive tree visible rather than silent.
//
// It used to run `uv pip compile setup.py`, which builds the project through
// its PEP 517 backend — executing setup.py.
type SetupPyCataloger struct {
	root string
}

func NewSetupPyCataloger(root string) *SetupPyCataloger {
	return &SetupPyCataloger{root: root}
}

func (c *SetupPyCataloger) Name() string { return "ossprey-setuppy-cataloger" }

func (c *SetupPyCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		dir := filepath.Dir(absPath)
		// A [project] table beside it is resolved from the pyproject instead.
		if hasPEP621Project(filepath.Join(dir, "pyproject.toml")) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: resolving setup.py would run it, so direct dependencies only", dir)
	}
	out, err := resolveByGlob(ctx, resolver, c.root, "**/setup.py", "setup.py", func(p string) bool {
		return pyprojectLockCovered(filepath.Join(filepath.Dir(p), "pyproject.toml"))
	}, parse)
	return out, nil, err
}
