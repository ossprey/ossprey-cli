package catalog

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/file"
)

// cargoVendorMarker sits at the root of every crate `cargo vendor` writes, whatever the vendor directory is called.
const cargoVendorMarker = ".cargo-checksum.json"

// cargoVendored hides vendored crates from every cataloger: their manifests and lockfiles describe the crate's own build.
type cargoVendored struct {
	file.Resolver
	dirs []string
}

// withoutCargoVendor wraps r so no lookup returns a file inside a vendored crate below root.
func withoutCargoVendor(r file.Resolver, root string) file.Resolver {
	marks, err := r.FilesByGlob("**/" + cargoVendorMarker)
	if err != nil || len(marks) == 0 {
		return r
	}
	// RealPath is root-relative on POSIX but absolute under the resolved root on Windows.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	rootPrefix := filepath.ToSlash(root) + "/"
	var dirs []string
	for _, m := range marks {
		p := filepath.ToSlash(m.RealPath)
		// A crate scanned directly is what was asked for.
		if path.Dir(strings.TrimPrefix(p, rootPrefix)) == "." {
			continue
		}
		dirs = append(dirs, path.Dir(p)+"/")
	}
	if len(dirs) == 0 {
		return r
	}
	return cargoVendored{Resolver: r, dirs: dirs}
}

func (r cargoVendored) keep(locs []file.Location, err error) ([]file.Location, error) {
	if err != nil {
		return nil, err
	}
	var out []file.Location
	for _, l := range locs {
		if !r.vendored(l.RealPath) {
			out = append(out, l)
		}
	}
	return out, nil
}

func (r cargoVendored) vendored(p string) bool {
	p = filepath.ToSlash(p)
	for _, d := range r.dirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

func (r cargoVendored) FilesByGlob(patterns ...string) ([]file.Location, error) {
	return r.keep(r.Resolver.FilesByGlob(patterns...))
}

func (r cargoVendored) FilesByPath(paths ...string) ([]file.Location, error) {
	return r.keep(r.Resolver.FilesByPath(paths...))
}

func (r cargoVendored) FilesByMIMEType(types ...string) ([]file.Location, error) {
	return r.keep(r.Resolver.FilesByMIMEType(types...))
}
