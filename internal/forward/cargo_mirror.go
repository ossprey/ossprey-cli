package forward

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/catalog"
)

// cargoMirror is a farm of links at s standing for the project, where cargo add can write only copies: every directory on the way to the working directory, the root and each member is a real one, the root's lock and each manifest are copies, and every other entry links to the project's.
type cargoMirror struct {
	s string
	// real are the directories mirrored as real ones, spelled as cargo spells them.
	real map[string]bool
	// manifestDirs are the directories of the root's and members' manifests.
	manifestDirs map[string]bool
	// run is where cargo runs after -C.
	run string
}

// buildCargoMirror mirrors the workspace for cargo add under the user cache, with files' bytes and modes as its copies, for a cargo started in cwd that runs in run after -C, both as cargo spells them; cargo writes through no link because it resolves no path it is given or finds, only joins and normalizes them (verified with cargo 1.97.0 and 1.99.1).
func buildCargoMirror(ws cargoWorkspace, files []cargoFile, cwd, run string) (*cargoMirror, error) {
	base, err := cargoMirrorBase()
	if err != nil {
		return nil, fmt.Errorf("no private directory to mirror the workspace in (%v)", err)
	}
	s, err := os.MkdirTemp(base, "cargo-add-")
	if err != nil {
		return nil, err
	}
	mi := &cargoMirror{s: canonicalDir(s), real: map[string]bool{}, manifestDirs: map[string]bool{}, run: run}
	if err := mi.build(ws, files, cwd); err != nil {
		mi.remove()
		return nil, err
	}
	return mi, nil
}

// cargoMirrorBase is ossprey's directory in the user cache, which only this user may write to.
func cargoMirrorBase() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	base := filepath.Join(cache, "ossprey")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	return base, privateDir(base)
}

func (mi *cargoMirror) build(ws cargoWorkspace, files []cargoFile, cwd string) error {
	// A config above the mirror that cargo does not read for the project would apply to the run (verified), so there may be none; CARGO_HOME's is read once either way.
	reads := map[string]bool{}
	for _, d := range ancestors(ws.ConfigDir) {
		reads[d] = true
	}
	home := canonicalDir(catalog.CargoHome(ws.ConfigDir))
	for _, d := range ancestors(filepath.Dir(mi.s)) {
		dot := filepath.Join(d, ".cargo")
		if reads[d] || canonicalDir(dot) == home {
			continue
		}
		for _, name := range []string{"config", "config.toml"} {
			if _, err := os.Lstat(filepath.Join(dot, name)); err == nil {
				return fmt.Errorf("%s would apply to cargo add in the mirror under %s and not to the project", filepath.Join(dot, name), mi.s)
			}
		}
	}
	// The lock and each manifest are a copy or nothing, never a link, since cargo writes a lock in place and a manifest beside a link's target (verified).
	copies := map[string]cargoFile{}
	for _, f := range files {
		mi.addReal(filepath.Dir(f.path))
		copies[f.path] = f
	}
	for _, m := range ws.Manifests {
		mi.manifestDirs[filepath.Dir(m)] = true
	}
	mi.addReal(cwd)
	mi.addReal(mi.run)

	// Real directories and copies first, so no link can stand where one belongs.
	dirs := slices.Sorted(maps.Keys(mi.real))
	for _, d := range dirs {
		if err := os.MkdirAll(mirrorPath(mi.s, d), 0o700); err != nil {
			return err
		}
	}
	for p, f := range copies {
		if !f.existed {
			continue
		}
		at := mirrorPath(mi.s, p)
		if err := os.WriteFile(at, f.data, 0o600); err != nil {
			return err
		}
		if err := os.Chmod(at, f.mode); err != nil {
			return err
		}
	}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			return fmt.Errorf("cannot list %s to mirror it (%v)", d, err)
		}
		for _, e := range entries {
			full := filepath.Join(d, e.Name())
			at := mirrorPath(mi.s, full)
			if _, err := os.Lstat(at); err == nil || copies[full].path != "" {
				// A real directory, a copy, or the name of a file that had none, which may have appeared since.
				continue
			}
			if err := os.Symlink(full, at); err != nil {
				return fmt.Errorf("cannot link %s into the mirror (%v)%s", full, err, cargoSymlinkHint)
			}
		}
	}
	return nil
}

// addReal mirrors dir and every directory above it as real directories.
func (mi *cargoMirror) addReal(dir string) {
	for _, d := range ancestors(dir) {
		mi.real[d] = true
	}
}

// at is where the project path p, spelled as cargo spells it, sits in the mirror.
func (mi *cargoMirror) at(p string) string {
	return mirrorPath(mi.s, p)
}

// args rewrites -C, --manifest-path and an absolute --path to absolute paths in the mirror, so cargo never reaches the project through a link and computes a dependency's relative path as it would there.
func (mi *cargoMirror) args(args []string) ([]string, error) {
	verb := verbIndex("cargo", args)
	globals := globalValueFlags["cargo"]
	g := cargoSplitShorts(args[:verb], globals)
	var out []string
	for i := 0; i < len(g); i++ {
		out = append(out, g[i])
		switch {
		case g[i] == "-C" && i+1 < len(g):
			// Each -C names the same directory once absolute, the one cargo would end in.
			out = append(out, mirrorPath(mi.s, mi.run))
			i++
		case globals[g[i]] && i+1 < len(g):
			out = append(out, g[i+1])
			i++
		}
	}
	out = append(out, args[verb])
	rest := cargoSplitShorts(args[verb+1:], cargoResolveShorts)
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		v, manifest := strings.CutPrefix(a, "--manifest-path=")
		dep, path := strings.CutPrefix(a, "--path=")
		switch {
		case a == "--":
			return append(out, rest[i:]...), nil
		case (a == "--manifest-path" || a == "-m") && i+1 < len(rest):
			v, manifest = rest[i+1], true
			i++
		case a == "--path" && i+1 < len(rest):
			dep, path = rest[i+1], true
			i++
		case manifest, path:
		case cargoResolveShorts[a] && i+1 < len(rest):
			out = append(out, a, rest[i+1])
			i++
			continue
		default:
			out = append(out, a)
			continue
		}
		if path {
			out = append(out, "--path", mi.dependency(dep))
			continue
		}
		p, err := mi.manifest(v)
		if err != nil {
			return nil, err
		}
		out = append(out, "--manifest-path", p)
	}
	return out, nil
}

// manifest is the mirror's copy of the manifest a --manifest-path value names, joined to where cargo runs and normalized as cargo does, links left alone (verified with cargo 1.99.1); one that is no manifest of the workspace has none.
func (mi *cargoMirror) manifest(v string) (string, error) {
	p := filepath.Clean(cargoConfigPath(v, mi.run))
	if !mi.manifestDirs[filepath.Dir(p)] {
		return "", fmt.Errorf("--manifest-path %s names no manifest of the workspace cargo metadata found", v)
	}
	return mirrorPath(mi.s, p), nil
}

// dependency is an absolute --path value in the mirror, where the same crate is reached through links, so cargo records the path relative to the manifest as it would in the project; one on a volume the mirror lacks, or a relative one, stays as given.
func (mi *cargoMirror) dependency(v string) string {
	if !filepath.IsAbs(v) || !mi.real[filepath.VolumeName(v)+string(filepath.Separator)] {
		return v
	}
	return mirrorPath(mi.s, filepath.Clean(v))
}

// strip are strings.NewReplacer's old, new pairs that spell each mirror path as the project path it stands for.
func (mi *cargoMirror) strip() []string {
	vols := map[string]bool{}
	for d := range mi.real {
		vols[filepath.VolumeName(d)] = true
	}
	var out []string
	for _, v := range slices.Sorted(maps.Keys(vols)) {
		out = append(out, mirrorPath(mi.s, v+string(filepath.Separator)), v)
	}
	return out
}

// remove deletes the mirror; os.RemoveAll follows no link out of it.
func (mi *cargoMirror) remove() {
	os.RemoveAll(mi.s)
}

// mirrorPath is where the absolute path p sits in a mirror at s: s/p, with a Windows volume as one directory (C:\x is s\C\x).
func mirrorPath(s, p string) string {
	vol := filepath.VolumeName(p)
	return filepath.Join(s, strings.NewReplacer(":", "", `\`, "_", "/", "_").Replace(vol), p[len(vol):])
}

// ancestors are dir and every directory above it, nearest first.
func ancestors(dir string) []string {
	out := []string{dir}
	for d := dir; filepath.Dir(d) != d; {
		d = filepath.Dir(d)
		out = append(out, d)
	}
	return out
}
