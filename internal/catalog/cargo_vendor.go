package catalog

import (
	"encoding/json"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/anchore/syft/syft/file"
)

// cargoVendorMarker sits at the root of every crate `cargo vendor` writes, whatever the vendor directory is called.
const cargoVendorMarker = ".cargo-checksum.json"

// maxCargoLockBytes bounds a lockfile read to prove a vendored crate; real ones are a few MB at most.
const maxCargoLockBytes = 32 << 20

// cargoVendored hides the Cargo.toml and Cargo.lock of proven vendored crates; it never hides any other file.
type cargoVendored struct {
	file.Resolver
	dirs []string
}

// withoutCargoVendor wraps r so no lookup returns a vendored crate's own manifest or lockfile below root.
// The marker is a repository file, so it proves nothing alone: the crate must also be locked outside every
// marked directory with the checksum the marker records, and that lockfile already names its dependencies.
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
	marked := map[string]file.Location{}
	for _, m := range marks {
		p := filepath.ToSlash(m.RealPath)
		// A crate scanned directly is what was asked for.
		if path.Dir(strings.TrimPrefix(p, rootPrefix)) == "." {
			continue
		}
		marked[path.Dir(p)] = m
	}
	if len(marked) == 0 {
		return r
	}
	manifests, err := r.FilesByGlob("**/Cargo.toml")
	if err != nil {
		return r
	}
	locked := lockedCrates(r, marked)
	var dirs []string
	for _, m := range manifests {
		dir := path.Dir(filepath.ToSlash(m.RealPath))
		mark, ok := marked[dir]
		if !ok {
			continue
		}
		var manifest struct {
			Package struct {
				Name    string `toml:"name"`
				Version string `toml:"version"`
			} `toml:"package"`
		}
		if decodeTOML(r, m, maxManifestBytes, &manifest) != nil || manifest.Package.Name == "" {
			continue
		}
		sum := locked[manifest.Package.Name+"@"+manifest.Package.Version]
		if sum != "" && sum == vendoredChecksum(r, mark) {
			dirs = append(dirs, dir+"/")
		}
	}
	if len(dirs) == 0 {
		return r
	}
	return cargoVendored{Resolver: r, dirs: dirs}
}

// lockedCrates maps name@version to its checksum in every Cargo.lock outside a marked directory.
func lockedCrates(r file.Resolver, marked map[string]file.Location) map[string]string {
	out := map[string]string{}
	locks, err := r.FilesByGlob("**/Cargo.lock")
	if err != nil {
		return out
	}
	for _, l := range locks {
		if underMarked(filepath.ToSlash(l.RealPath), marked) {
			continue
		}
		var lock struct {
			Package []struct {
				Name     string `toml:"name"`
				Version  string `toml:"version"`
				Checksum string `toml:"checksum"`
			} `toml:"package"`
		}
		if decodeTOML(r, l, maxCargoLockBytes, &lock) != nil {
			continue
		}
		for _, p := range lock.Package {
			out[p.Name+"@"+p.Version] = p.Checksum
		}
	}
	return out
}

func underMarked(p string, marked map[string]file.Location) bool {
	for dir := range marked {
		if strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}

// vendoredChecksum is the .crate checksum `cargo vendor` recorded, or "" when it recorded none or the file is unreadable.
func vendoredChecksum(r file.Resolver, mark file.Location) string {
	data, err := readLocation(r, mark, maxManifestBytes)
	if err != nil {
		return ""
	}
	var marker struct {
		Package string `json:"package"`
	}
	if json.Unmarshal(data, &marker) != nil {
		return ""
	}
	return marker.Package
}

func decodeTOML(r file.Resolver, loc file.Location, limit int64, v any) error {
	data, err := readLocation(r, loc, limit)
	if err != nil {
		return err
	}
	_, err = toml.Decode(string(data), v)
	return err
}

func readLocation(r file.Resolver, loc file.Location, limit int64) ([]byte, error) {
	rc, err := r.FileContentsByLocation(loc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit))
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
	if base := path.Base(p); base != "Cargo.toml" && base != "Cargo.lock" {
		return false
	}
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
