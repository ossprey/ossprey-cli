package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/anchore/syft/syft/file"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"golang.org/x/text/unicode/norm"
)

// cargoVendorMarker sits at the root of every crate `cargo vendor` writes, whatever the vendor directory is called.
const cargoVendorMarker = ".cargo-checksum.json"

// maxCargoProofBytes bounds a marker read; real ones are a few MB at most.
const maxCargoProofBytes = 32 << 20

// cargoVendored hides the Cargo.toml and Cargo.lock of proven vendored crates; it never hides any other file.
type cargoVendored struct {
	file.Resolver
	rootPrefix string
	hidden     map[string]bool
}

// cargoFile is a parsed manifest or cargo config with every directory cargo may resolve its paths against; inexact
// marks a config whose name only case folding matches, which cargo reads on some filesystems only.
type cargoFile struct {
	doc     map[string]any
	bases   []string
	inexact bool
}

// lockedSet is one project's Cargo.lock: checksums per name@version ("" for a path crate) and versions per name.
type lockedSet struct {
	sums     map[string]map[string]bool
	versions map[string][]string
}

// withoutCargoVendor hides the Cargo files of crates the project above them vendored (see CLAUDE.md, OSS-2561).
func withoutCargoVendor(r file.Resolver, root string) file.Resolver {
	marks, err := r.FilesByGlob("**/" + cargoVendorMarker)
	if err != nil || len(marks) == 0 {
		return r
	}
	root = resolvedRoot(root)
	rootSlash := filepath.ToSlash(root)
	rootPrefix := rootSlash + "/"
	marked := map[string]file.Location{}
	for _, m := range marks {
		marked[path.Dir(rootRel(m.RealPath, rootPrefix))] = m
	}
	manifestLocs, err := r.FilesByGlob("**/Cargo.toml")
	if err != nil {
		return r
	}
	dotted, err := r.FilesByGlob("**/.*/*")
	if err != nil {
		return r
	}
	var configLocs []file.Location
	for _, l := range dotted {
		if isCargoConfig(rootRel(l.AccessPath, rootPrefix)) || isCargoConfig(rootRel(l.RealPath, rootPrefix)) {
			configLocs = append(configLocs, l)
		}
	}
	lockLocs, err := r.FilesByGlob("**/Cargo.lock")
	if err != nil {
		return r
	}
	// A symlink leaving the root is reported by its outside path, which cargo may still read from inside.
	for _, locs := range [][]file.Location{marks, manifestLocs, configLocs, lockLocs} {
		for _, l := range locs {
			if outsideRoot(rootRel(l.RealPath, rootPrefix)) || outsideRoot(rootRel(l.AccessPath, rootPrefix)) {
				return r
			}
		}
	}
	manifests, ok := readCargoFiles(r, manifestLocs, rootSlash, 1)
	if !ok {
		return r
	}
	configs, ok := readCargoFiles(r, configLocs, rootSlash, 2)
	if !ok {
		return r
	}
	aboveManifests, aboveConfigs, ok := cargoFilesAbove(root, true, false)
	if !ok {
		return r
	}
	all := append(aboveManifests, aboveConfigs...)
	levels := map[string][]cargoFile{}
	for _, c := range aboveConfigs {
		levels[foldPath(c.bases[0])] = append(levels[foldPath(c.bases[0])], c)
	}
	for _, files := range []map[string]cargoFile{manifests, configs} {
		for _, f := range files {
			all = append(all, f)
		}
	}
	// A config counts at each directory cargo reads it from, which a symlink can make its access path's.
	placed := map[string]bool{}
	for _, l := range configLocs {
		doc := configs[rootRel(l.RealPath, rootPrefix)].doc
		for _, p := range []string{rootRel(l.AccessPath, rootPrefix), rootRel(l.RealPath, rootPrefix)} {
			base := path.Join(rootSlash, path.Dir(path.Dir(p)))
			if isCargoConfig(p) && !placed[p] {
				placed[p] = true
				levels[foldPath(base)] = append(levels[foldPath(base)], cargoFile{doc: doc, bases: []string{base}, inexact: !isExactCargoConfig(p)})
			}
		}
	}
	// cargo reads config from where it runs, and an alias or --manifest-path reaches any crate from any level.
	for _, cs := range levels {
		if base := cs[0].bases[0]; strings.HasPrefix(foldPath(base)+"/", foldPath(rootPrefix)) && vendorDir(levels, base) == "" {
			return r
		}
	}
	owned, unsure := projectCrates(all, marked, rootSlash)
	if unsure {
		return r
	}
	locks := projectLocks(r, lockLocs, manifests, marked, rootPrefix)
	hidden := map[string]bool{}
	for p, m := range manifests {
		dir := path.Dir(p)
		mark, ok := marked[dir]
		// cargo publish strips [workspace], so a manifest holding one is a project's own.
		if !ok || owned[dir] || m.doc["workspace"] != nil {
			continue
		}
		name, _ := tomlLookup(m.doc, "package", "name").(string)
		version, _ := tomlLookup(m.doc, "package", "version").(string)
		sum := vendoredChecksum(r, mark)
		source := foldPath(realPath(path.Join(rootSlash, path.Dir(dir))))
		if name == "" || sum == "" {
			continue
		}
		// The vendoring project is a strict ancestor, so a crate scanned directly is always read.
		for a := dir; a != "." && path.Dir(a) != a; {
			a = path.Dir(a)
			lock, ok := locks[a]
			if !ok {
				continue
			}
			// "" is a path crate of the same name and version, which the project builds itself.
			sums := lock.sums[name+"@"+version]
			if sums[sum] && !sums[""] && lockCoversDeps(lock, m.doc) && vendorDir(levels, path.Join(rootSlash, a)) == source {
				hidden[p] = true
				hidden[dir+"/Cargo.lock"] = true
				break
			}
		}
	}
	if len(hidden) == 0 {
		return r
	}
	return cargoVendored{Resolver: r, rootPrefix: rootPrefix, hidden: hidden}
}

// resolvedRoot is root with its symlinks resolved, since RealPath is root-relative on POSIX but absolute under the resolved root on Windows.
func resolvedRoot(root string) string {
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		return resolved
	}
	return root
}

// isCargoConfig matches .cargo/config(.toml) in any case, as cargo opens them on a case-insensitive filesystem.
func isCargoConfig(p string) bool {
	return isExactCargoConfig(strings.ToLower(p))
}

func isExactCargoConfig(p string) bool {
	return path.Base(path.Dir(p)) == ".cargo" && (path.Base(p) == "config" || path.Base(p) == "config.toml")
}

func outsideRoot(rel string) bool {
	return path.IsAbs(rel) || filepath.VolumeName(rel) != ""
}

// rootRel is a RealPath relative to the scan root, in slash form.
func rootRel(p, rootPrefix string) string {
	return strings.TrimPrefix(filepath.ToSlash(p), rootPrefix)
}

// readCargoFiles parses each file once by real path, with a base up levels from both its real and its access path.
func readCargoFiles(r file.Resolver, locs []file.Location, rootSlash string, up int) (map[string]cargoFile, bool) {
	out := map[string]cargoFile{}
	for _, l := range locs {
		real := rootRel(l.RealPath, rootSlash+"/")
		f, ok := out[real]
		if !ok {
			if err := decodeTOMLAt(r, l, maxManifestBytes, &f.doc); err != nil {
				return nil, false
			}
		}
		for _, p := range []string{real, rootRel(l.AccessPath, rootSlash+"/")} {
			for i := 0; i < up; i++ {
				p = path.Dir(p)
			}
			f.bases = append(f.bases, path.Join(rootSlash, p))
		}
		out[real] = f
	}
	return out, true
}

// cargoFilesAbove reads the configs, and with withManifests the manifests, cargo run inside root also sees: every ancestor's, and CARGO_HOME's; noLinks fails on a symlinked .cargo or config and skips CARGO_HOME only as an ancestor's .cargo by its exact path.
func cargoFilesAbove(root string, withManifests, noLinks bool) (manifests, configs []cargoFile, ok bool) {
	exact := []string{".cargo"}
	if withManifests {
		exact = append(exact, "Cargo.toml")
	}
	seen, key := map[string]bool{}, foldPath
	if noLinks {
		// A folded path can name another directory on a case-sensitive filesystem, leaving CARGO_HOME unread.
		key = path.Clean
	}
	for d := filepath.Dir(root); ; d = filepath.Dir(d) {
		entries, err := cargoDirEntries(d, exact...)
		if err != nil {
			return nil, nil, false
		}
		for _, e := range entries {
			n := e.Name()
			switch strings.ToLower(n) {
			case "cargo.toml":
				if !withManifests {
					continue
				}
				m, ok := readCargoFileAt(filepath.Join(d, n), d)
				if !ok {
					return nil, nil, false
				}
				manifests = append(manifests, m)
			case ".cargo":
				if noLinks && e.Type()&fs.ModeSymlink != 0 {
					return nil, nil, false
				}
				cs, ok := cargoConfigsIn(filepath.Join(d, n), d, n != ".cargo", noLinks)
				if !ok {
					return nil, nil, false
				}
				configs = append(configs, cs...)
				seen[key(filepath.ToSlash(filepath.Join(d, n)))] = true
			}
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	home := os.Getenv("CARGO_HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".cargo")
		}
	}
	if home != "" && !seen[key(filepath.ToSlash(home))] {
		cs, ok := cargoConfigsIn(home, filepath.Dir(home), false, noLinks)
		if !ok {
			return nil, nil, false
		}
		configs = append(configs, cs...)
	}
	return manifests, configs, true
}

// cargoConfigsIn reads config and config.toml in dir in any case; false when one cannot be read, or with noLinks is a symlink.
func cargoConfigsIn(dir, base string, inexact, noLinks bool) ([]cargoFile, bool) {
	entries, err := cargoDirEntries(dir, "config", "config.toml")
	if err != nil {
		return nil, false
	}
	var configs []cargoFile
	for _, e := range entries {
		name := e.Name()
		if n := strings.ToLower(name); n == "config" || n == "config.toml" {
			if noLinks && e.Type()&fs.ModeSymlink != 0 {
				return nil, false
			}
			c, ok := readCargoFileAt(filepath.Join(dir, name), base)
			if !ok {
				return nil, false
			}
			c.inexact = inexact || n != name
			configs = append(configs, c)
		}
	}
	return configs, true
}

// cargoDirEntries lists dir without following links, or when it can be searched but not listed, which of exact it holds; a missing dir holds nothing.
func cargoDirEntries(dir string, exact ...string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return entries, nil
	}
	var found []fs.DirEntry
	for _, n := range exact {
		if info, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			found = append(found, fs.FileInfoToDirEntry(info))
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return found, nil
}

// readCargoFileAt parses the regular file at p on disk, resolving its paths against base.
func readCargoFileAt(p, base string) (cargoFile, bool) {
	data, err := readTOML(p)
	if err != nil {
		return cargoFile{}, false
	}
	f := cargoFile{bases: []string{filepath.ToSlash(base)}}
	_, err = decodeTOML(data, &f.doc)
	return f, err == nil
}

// vendorDir is the folded directory cargo run in dir takes crates.io crates from, or "" when unreplaced or unclear.
func vendorDir(levels map[string][]cargoFile, dir string) string {
	find := func(keys ...string) (string, string) {
		for d := dir; ; d = path.Dir(d) {
			// Two config files at one level, or one named in another case, leave cargo's choice unclear.
			if cs := levels[foldPath(d)]; len(cs) > 1 || len(cs) == 1 && cs[0].inexact {
				return "", ""
			} else if len(cs) == 1 {
				if v, ok := tomlLookup(cs[0].doc, keys...).(string); ok {
					return v, cs[0].bases[0]
				}
			}
			if path.Dir(d) == d {
				return "", ""
			}
		}
	}
	name, _ := find("source", "crates-io", "replace-with")
	// cargo follows a replacement's own replace-with, so only a source replaced once is the vendor tree.
	if again, _ := find("source", name, "replace-with"); name == "" || again != "" {
		return ""
	}
	directory, base := find("source", name, "directory")
	if directory == "" {
		return ""
	}
	return foldPath(realPath(placeRef(base, directory)))
}

func tomlLookup(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// placeRef is ref, relative to the absolute slash path base, as an absolute slash path.
func placeRef(base, ref string) string {
	if path.IsAbs(ref) || filepath.VolumeName(ref) != "" {
		return filepath.ToSlash(ref)
	}
	return path.Join(base, ref)
}

// realPath resolves every symlink in p, or cleans it when it does not exist here.
func realPath(p string) string {
	if real, err := filepath.EvalSymlinks(filepath.FromSlash(p)); err == nil {
		return filepath.ToSlash(real)
	}
	return path.Clean(p)
}

// foldPath folds case and Unicode normalization, as a filesystem may.
func foldPath(p string) string {
	return strings.ToLower(norm.NFC.String(p))
}

// projectCrates returns the marked directories any manifest or cargo config builds by path, or unsure.
func projectCrates(files []cargoFile, marked map[string]file.Location, rootSlash string) (map[string]bool, bool) {
	inRoot := foldPath(rootSlash) + "/"
	byReal := map[string]string{}
	for dir := range marked {
		byReal[foldPath(realPath(path.Join(rootSlash, dir)))] = dir
	}
	owned := map[string]bool{}
	own := func(p string) {
		for _, q := range []string{foldPath(p), foldPath(realPath(p))} {
			if dir, ok := byReal[q]; ok {
				owned[dir] = true
			}
			// A path leaving the root may come back in under another checkout's name.
			if !strings.HasPrefix(q, inRoot) {
				for dir := range marked {
					if strings.HasSuffix(q, "/"+foldPath(dir)) {
						owned[dir] = true
					}
				}
			}
		}
	}
	for _, f := range files {
		literals, globs, unsure := cargoPathRefs(f.doc)
		if unsure {
			return nil, true
		}
		for _, base := range f.bases {
			for _, ref := range literals {
				own(placeRef(base, ref))
				own(placeRef(base, strings.ReplaceAll(ref, `\`, "/")))
			}
			for _, g := range globs {
				g = path.Clean(strings.ReplaceAll(g, `\`, "/"))
				// Go's and cargo's globs differ on classes and **, and an absolute one may name anything.
				if strings.ContainsAny(g, "[]") || strings.Contains(g, "**") || path.IsAbs(g) || filepath.VolumeName(g) != "" {
					return nil, true
				}
				dir := base
				for strings.HasPrefix(g, "../") {
					dir, g = path.Dir(dir), g[3:]
				}
				if g == ".." || strings.Contains("/"+g+"/", "/../") || !strings.HasPrefix(foldPath(dir)+"/", inRoot) {
					return nil, true
				}
				// The base is read literally, so a checkout named with glob characters still expands.
				matches, err := fs.Glob(os.DirFS(filepath.FromSlash(dir)), g)
				if err != nil {
					return nil, true
				}
				for _, m := range matches {
					own(path.Join(dir, m))
				}
			}
		}
	}
	return owned, false
}

// cargoPathRefs collects `path`, `workspace`, `paths` and `members` values, unsure on a `base` or config `include`.
func cargoPathRefs(doc map[string]any) (literals, globs []string, unsure bool) {
	unsure = doc["include"] != nil
	// An alias runs cargo with its own arguments: `cargo vendor` ignores source replacement, and --manifest-path names a crate.
	for _, args := range cargoAliasArgs(doc) {
		for i, arg := range args {
			// --config can undo the replacement for that run.
			if i == 0 && arg == "vendor" || isConfigArg(arg) {
				unsure = true
			}
			if v, ok := strings.CutPrefix(arg, "--manifest-path="); ok {
				literals = append(literals, path.Dir(v))
			} else if arg == "--manifest-path" && i+1 < len(args) {
				literals = append(literals, path.Dir(args[i+1]))
			}
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if t["path"] != nil && t["base"] != nil {
				unsure = true
			}
			for k, e := range t {
				switch e := e.(type) {
				case string:
					if k == "path" || k == "workspace" {
						literals = append(literals, e)
					}
				case []any:
					for _, s := range e {
						if s, ok := s.(string); ok && k == "paths" {
							literals = append(literals, s)
						} else if ok && k == "members" {
							globs = append(globs, s)
						}
					}
				}
				walk(e)
			}
		case []map[string]any:
			for _, e := range t {
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(doc)
	return literals, globs, unsure
}

// cargoAliasArgs is each [alias] value in doc split into the arguments cargo runs it with.
func cargoAliasArgs(doc map[string]any) [][]string {
	aliases, _ := doc["alias"].(map[string]any)
	var out [][]string
	for _, a := range aliases {
		var args []string
		switch a := a.(type) {
		case string:
			args = strings.Fields(a)
		case []any:
			for _, s := range a {
				if s, ok := s.(string); ok {
					args = append(args, s)
				}
			}
		}
		out = append(out, args)
	}
	return out
}

func isConfigArg(arg string) bool {
	return arg == "--config" || strings.HasPrefix(arg, "--config=")
}

// lockCoversDeps reports whether the lock holds a release meeting each normal and build dependency doc turns on.
func lockCoversDeps(lock lockedSet, doc map[string]any) bool {
	on := defaultFeatureDeps(doc)
	tables := []any{doc["dependencies"], doc["build-dependencies"], doc["build_dependencies"]}
	if targets, ok := doc["target"].(map[string]any); ok {
		for _, t := range targets {
			tables = append(tables, tomlLookup(t, "dependencies"), tomlLookup(t, "build-dependencies"), tomlLookup(t, "build_dependencies"))
		}
	}
	for _, t := range tables {
		deps, _ := t.(map[string]any)
		for alias, spec := range deps {
			name, req := alias, ""
			switch s := spec.(type) {
			case string:
				req = s
			case map[string]any:
				if optional, _ := s["optional"].(bool); optional && !on[alias] {
					continue
				}
				if pkg, ok := s["package"].(string); ok {
					name = pkg
				}
				req, _ = s["version"].(string)
			}
			versions, ok := lock.versions[name]
			if !ok {
				return false
			}
			met := req == ""
			for _, v := range versions {
				if m, ok := registry.CargoSatisfies(req, v); ok && m {
					met = true
				}
			}
			if !met {
				return false
			}
		}
	}
	return true
}

// defaultFeatureDeps returns the dependency keys doc's default features turn on, following its own features.
func defaultFeatureDeps(doc map[string]any) map[string]bool {
	features, _ := doc["features"].(map[string]any)
	on, seen := map[string]bool{}, map[string]bool{}
	var enable func(f string)
	enable = func(f string) {
		if seen[f] {
			return
		}
		seen[f] = true
		list, ok := features[f].([]any)
		if !ok {
			// An optional dependency is also a feature of its own name.
			on[f] = true
			return
		}
		for _, e := range list {
			s, _ := e.(string)
			if dep, ok := strings.CutPrefix(s, "dep:"); ok {
				on[dep] = true
			} else if dep, _, ok := strings.Cut(s, "/"); ok {
				// "dep?/feature" turns on a feature only of a dependency something else turned on.
				if !strings.HasSuffix(dep, "?") {
					on[dep] = true
				}
			} else {
				enable(s)
			}
		}
	}
	enable("default")
	return on
}

// projectLocks reads the Cargo.lock of each unmarked directory that also holds a Cargo.toml.
func projectLocks(r file.Resolver, locks []file.Location, manifests map[string]cargoFile, marked map[string]file.Location, rootPrefix string) map[string]lockedSet {
	out := map[string]lockedSet{}
	for _, l := range locks {
		p := rootRel(l.RealPath, rootPrefix)
		dir := path.Dir(p)
		if _, ok := marked[dir]; ok || underMarked(p, marked) {
			continue
		}
		if _, ok := manifests[path.Join(dir, "Cargo.toml")]; !ok {
			continue
		}
		var lock struct {
			Package []struct {
				Name     string `toml:"name"`
				Version  string `toml:"version"`
				Source   string `toml:"source"`
				Checksum string `toml:"checksum"`
			} `toml:"package"`
		}
		// The lockfile caps, as for syft's own parse: this one runs before withBoundedLocks hides anything.
		data, err := readLock(r, l)
		if err != nil {
			continue
		}
		if _, err := decodeTOML(data, &lock); err != nil {
			continue
		}
		set := lockedSet{sums: map[string]map[string]bool{}, versions: map[string][]string{}}
		for _, p := range lock.Package {
			set.versions[p.Name] = append(set.versions[p.Name], p.Version)
			// A git crate has a source but no checksum, and proves nothing either way.
			if p.Checksum == "" && p.Source != "" {
				continue
			}
			key := p.Name + "@" + p.Version
			if set.sums[key] == nil {
				set.sums[key] = map[string]bool{}
			}
			set.sums[key][p.Checksum] = true
		}
		out[dir] = set
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

// vendoredChecksum is the .crate checksum `cargo vendor` recorded, or "".
func vendoredChecksum(r file.Resolver, mark file.Location) string {
	data, err := readLocation(r, mark, maxCargoProofBytes)
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

func decodeTOMLAt(r file.Resolver, loc file.Location, limit int64, v any) error {
	data, err := readLocation(r, loc, limit)
	if err != nil {
		return err
	}
	_, err = decodeTOML(data, v)
	return err
}

// readLocation refuses a file over limit, since a truncated one could drop a reference.
func readLocation(r file.Resolver, loc file.Location, limit int64) ([]byte, error) {
	rc, err := r.FileContentsByLocation(loc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &fs.PathError{Op: "read", Path: loc.RealPath, Err: fmt.Errorf("over the %d byte limit", limit)}
	}
	return data, nil
}

// keep drops a hidden file only when reached by its own path, never through a symlink to it.
func (r cargoVendored) keep(locs []file.Location, err error) ([]file.Location, error) {
	if err != nil {
		return nil, err
	}
	var out []file.Location
	for _, l := range locs {
		real := rootRel(l.RealPath, r.rootPrefix)
		if !r.hidden[real] || rootRel(l.AccessPath, r.rootPrefix) != real {
			out = append(out, l)
		}
	}
	return out, nil
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
