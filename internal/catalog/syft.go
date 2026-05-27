package catalog

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

type Package struct {
	Name      string
	Version   string
	Type      string
	Source    []string
	Locations []string
}

// Catalog returns Python + JavaScript packages under path.
//
// Bypasses syft.CreateSBOM (which transitively imports every cataloger Anchore
// ships — ~30 MB of unused code). Instead, instantiates a curated set of
// catalogers — syft's built-ins for lockfiles plus our own custom catalogers
// for resolution gaps (uv, setup.py, direct-deps pyproject/package.json) —
// and runs them all against a directory FileResolver.
//
// All catalogers run unconditionally. Output is deduped by (name, version,
// type) to absorb overlap between syft + uv + parsers.
func Catalog(ctx context.Context, path string) ([]Package, error) {
	absRoot, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	src, err := directorysource.NewFromPath(absRoot)
	if err != nil {
		return nil, fmt.Errorf("syft source: %w", err)
	}
	defer src.Close()

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		return nil, fmt.Errorf("syft resolver: %w", err)
	}

	pyCfg := python.DefaultCatalogerConfig().WithGuessUnpinnedRequirements(true)
	jsCfg := javascript.DefaultCatalogerConfig().WithIncludeDevDependencies(true)

	catalogers := []pkg.Cataloger{
		// Syft built-ins: handle lockfiles + installed-package metadata.
		python.NewPackageCataloger(pyCfg),
		javascript.NewPackageCataloger(),
		javascript.NewLockCataloger(jsCfg),
		// Custom: full transitive resolution via uv (covers hatch, uv, bare
		// pyproject without poetry.lock).
		NewUVCataloger(absRoot),
		// Custom: resolve transitives from setup.py when pyproject is absent
		// or lacks a [project] table (legacy setuptools projects).
		NewSetupPyCataloger(absRoot),
		// Custom: direct-deps fallback for pyproject.toml when uv is missing.
		NewPyProjectCataloger(absRoot),
		// Custom: direct-deps fallback for package.json (syft only emits the
		// root project from package.json, not its deps).
		NewPackageJSONCataloger(absRoot),
	}

	seen := map[string]struct{}{}
	var out []Package
	for _, c := range catalogers {
		pkgs, _, err := c.Catalog(ctx, resolver)
		if err != nil {
			// Per-cataloger errors are non-fatal — skip and continue. Matches
			// syft.CreateSBOM behavior.
			continue
		}
		// Syft's manifest catalogers emit the root project itself from
		// package.json / pyproject.toml — drop those. Our custom catalogers
		// parse deps only, so the rule does not apply.
		isOspreyCataloger := isOspreyCataloger(c.Name())
		for _, p := range pkgs {
			t := ossbomType(p.Type)
			if t == "" {
				continue
			}
			if !isOspreyCataloger && isRootManifestPackage(p) {
				continue
			}
			key := t + "@" + p.Name + "@" + p.Version
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Package{
				Name:      p.Name,
				Version:   p.Version,
				Type:      t,
				Source:    []string{c.Name()},
				Locations: locations(p),
			})
		}
	}

	return out, nil
}

// isOspreyCataloger identifies our own custom catalogers by name. Used to
// scope syft-specific filtering (e.g. root manifest drop) to syft's output.
func isOspreyCataloger(name string) bool {
	switch name {
	case "ossprey-uv-cataloger",
		"ossprey-setuppy-cataloger",
		"ossprey-pyproject-cataloger",
		"ossprey-packagejson-cataloger":
		return true
	}
	return false
}

// Map syft pkg.Type to OSSBOM `component.type` (matches v1 PURL convention).
func ossbomType(t pkg.Type) string {
	switch t {
	case pkg.PythonPkg:
		return "pypi"
	case pkg.NpmPkg:
		return "npm"
	default:
		return ""
	}
}

// isRootManifestPackage returns true when the syft package is the root project's
// own metadata (parsed from package.json or pyproject.toml's [project] table).
// These aren't dependencies — drop them.
func isRootManifestPackage(p pkg.Package) bool {
	for _, l := range p.Locations.ToSlice() {
		base := filepath.Base(l.RealPath)
		if base == "package.json" || base == "pyproject.toml" {
			return true
		}
	}
	return false
}

func locations(p pkg.Package) []string {
	var locs []string
	for _, l := range p.Locations.ToSlice() {
		locs = append(locs, l.RealPath)
	}
	return locs
}
