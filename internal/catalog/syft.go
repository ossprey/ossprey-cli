package catalog

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

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
	// Local marks a package declared as local code (a uv path/workspace source
	// or a poetry path dependency) rather than a public-registry package. The
	// platform filters these out before scanning — they are the repo's own code,
	// never published, so scanning them only yields spurious NOT_FOUND warnings
	// (OSS-1389).
	Local bool
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
		// Custom: resolve transitives from requirements.txt via uv (syft's
		// built-in reads the file literally — direct deps only).
		NewRequirementsCataloger(absRoot),
		// Custom: direct-deps fallback for pyproject.toml when uv is missing.
		NewPyProjectCataloger(absRoot),
		// Custom: resolve npm ranges to concrete versions via `npm install
		// --package-lock-only` when no lockfile is committed (npm analogue of
		// uv). The package.json fallback below then folds in versionless.
		NewNpmResolveCataloger(absRoot),
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
			if isUnpublishedNpmLockEntry(p) {
				continue
			}
			key := dedupKey(t, p.Name, p.Version)
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

	merged := mergeVersionless(out)
	markLocalPackages(merged, findLocalPackageNames(resolver, absRoot))
	return merged, nil
}

// markLocalPackages sets Local=true on every pypi package whose name matches a
// locally-declared package (uv path/workspace source or poetry path dep). Names
// are compared PEP 503-canonically so casing/separator differences between the
// manifest and the cataloguer output don't matter. No-op when local is empty.
func markLocalPackages(pkgs []Package, local map[string]struct{}) {
	if len(local) == 0 {
		return
	}
	for i := range pkgs {
		if pkgs[i].Type != "pypi" {
			continue
		}
		if _, ok := local[canonicalPackageName(pkgs[i].Name)]; ok {
			pkgs[i].Local = true
		}
	}
}

// mergeVersionless collapses a package emitted both with and without a version.
// The direct-deps catalogers (pyproject/package.json) can only report a name
// when the version is unpinned (e.g. "click" from `dependencies = ["click"]`),
// while the uv cataloger resolves the same dep to a concrete version
// ("click@8.4.1"). Those are the same package — the versionless entry is just a
// lower-fidelity view. Drop versionless entries when a versioned sibling of the
// same (type, name) exists, folding their Source/Locations into the siblings so
// no attribution is lost. Entries with no versioned sibling are kept as-is.
func mergeVersionless(pkgs []Package) []Package {
	gkey := func(p Package) string { return p.Type + "@" + normalizeName(p.Name) }

	hasVersioned := map[string]bool{}
	for _, p := range pkgs {
		if p.Version != "" {
			hasVersioned[gkey(p)] = true
		}
	}

	// Keep versioned entries and versionless ones with no versioned sibling;
	// remember where each versioned group landed so we can fold sources into it.
	var out []Package
	groupIdx := map[string][]int{}
	for _, p := range pkgs {
		if p.Version == "" && hasVersioned[gkey(p)] {
			continue // folded below
		}
		if p.Version != "" {
			groupIdx[gkey(p)] = append(groupIdx[gkey(p)], len(out))
		}
		out = append(out, p)
	}

	for _, p := range pkgs {
		if p.Version == "" && hasVersioned[gkey(p)] {
			for _, i := range groupIdx[gkey(p)] {
				out[i].Source = mergeUnique(out[i].Source, p.Source)
				out[i].Locations = mergeUnique(out[i].Locations, p.Locations)
			}
		}
	}
	return out
}

// mergeUnique returns a ∪ b preserving order, dropping duplicates and empties.
func mergeUnique(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, v := range append(append([]string{}, a...), b...) {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// dedupKey collapses a package to its dedup identity: (type, name, version).
// Name is normalized so the same package surfaced by two catalogers with
// different casing (syft emits the canonical name, e.g. "PyYAML"; our custom
// catalogers lowercase) maps to one key instead of two.
func dedupKey(t, name, version string) string {
	return t + "@" + normalizeName(name) + "@" + version
}

// isOspreyCataloger identifies our own custom catalogers by name. Used to
// scope syft-specific filtering (e.g. root manifest drop) to syft's output.
func isOspreyCataloger(name string) bool {
	switch name {
	case "ossprey-uv-cataloger",
		"ossprey-setuppy-cataloger",
		"ossprey-requirements-cataloger",
		"ossprey-pyproject-cataloger",
		"ossprey-npm-cataloger",
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

// isUnpublishedNpmLockEntry reports whether p is a package-lock.json entry with
// no registry tarball ("resolved" is empty): the root project itself, or a
// file:/link:/workspace: dependency. None are fetchable from the npm registry,
// so emitting them only yields spurious NOT_FOUND findings (e.g. the root
// project app@1.0.0 leaking out of syft's lock cataloger).
func isUnpublishedNpmLockEntry(p pkg.Package) bool {
	m, ok := p.Metadata.(pkg.NpmPackageLockEntry)
	return ok && strings.TrimSpace(m.Resolved) == ""
}

func locations(p pkg.Package) []string {
	var locs []string
	for _, l := range p.Locations.ToSlice() {
		locs = append(locs, l.RealPath)
	}
	return locs
}
