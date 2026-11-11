package forward

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

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
	// cargo reads them above its working directory as it spells it, which on Windows may go through a link.
	for _, d := range ancestors(mi.run) {
		reads[canonicalDir(d)] = true
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
		copies[fileKey(f.path)] = f
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
	for _, f := range files {
		if !f.existed {
			continue
		}
		at := mirrorPath(mi.s, f.path)
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
			if _, err := os.Lstat(at); err == nil || copies[fileKey(full)].path != "" {
				// A real directory, a copy, or the name of a file that had none, which may have appeared since, in any spelling.
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
		case cargoResolveShorts[a] && i+1 < len(rest) && !cargoOptionalSkips(a, rest[i+1]):
			out = append(out, a, rest[i+1])
			i++
			continue
		default:
			out = append(out, a)
			continue
		}
		if path {
			d, err := mi.dependency(dep)
			if err != nil {
				return nil, err
			}
			out = append(out, "--path", d)
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

// dependency is an absolute --path value in the mirror, where the same crate is reached through links, so cargo records the path relative to the manifest as it would in the project; one on a volume the mirror lacks, or a relative one, stays as given, and Windows' \x or C:x, which cargo would place from the mirror, refuses, as does a path on the mirror's own drive that the mirror lacks, which cargo would record relative to the mirror.
func (mi *cargoMirror) dependency(v string) (string, error) {
	if driveRelative(v) {
		return "", fmt.Errorf("--path %s is relative to a drive or its root, which cargo would read from ossprey's copy of the workspace; give the full path or one relative to the working directory", v)
	}
	if !filepath.IsAbs(v) {
		return v, nil
	}
	p := filepath.Clean(v)
	vol := filepath.VolumeName(p)
	if real, ok := mi.volume(vol); ok {
		return mirrorPath(mi.s, real+p[len(vol):]), nil
	}
	if sameVolume(vol, filepath.VolumeName(mi.s)) {
		return "", fmt.Errorf("--path %s is on the drive of ossprey's copy of the workspace and not of the project, so cargo would record it relative to the copy; give a path on the project's drive or another one", v)
	}
	return v, nil
}

// volume is the mirror's spelling of the volume vol, a drive letter matched in either case since Rust reads c: as C:, or false when the mirror has none.
func (mi *cargoMirror) volume(vol string) (string, bool) {
	if mi.real[vol+string(filepath.Separator)] {
		return vol, true
	}
	for _, d := range slices.Sorted(maps.Keys(mi.real)) {
		if real := filepath.VolumeName(d); sameVolume(real, vol) {
			return real, true
		}
	}
	return "", false
}

// sameVolume reports whether Rust reads the volumes a and b as one: drive letters in either case, anything else spelled alike.
func sameVolume(a, b string) bool {
	if isDrive(a) && isDrive(b) {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// isDrive reports whether vol is a drive letter and its colon.
func isDrive(vol string) bool {
	return len(vol) == 2 && vol[1] == ':' && ('A' <= vol[0] && vol[0] <= 'Z' || 'a' <= vol[0] && vol[0] <= 'z')
}

// driveRelative reports whether p is Windows' \x or C:x, rooted with no drive or on a drive with no root.
func driveRelative(p string) bool {
	return !filepath.IsAbs(p) && (filepath.VolumeName(p) != "" || p != "" && os.IsPathSeparator(p[0]))
}

// strip are strings.NewReplacer's old, new pairs that spell each mirror path as the project path it stands for, each ending in a separator since one volume's directory may begin another's.
func (mi *cargoMirror) strip() []string {
	vols := map[string]bool{}
	for d := range mi.real {
		vols[filepath.VolumeName(d)] = true
	}
	var out []string
	for _, v := range slices.Sorted(maps.Keys(vols)) {
		root := v + string(filepath.Separator)
		out = append(out, mirrorPath(mi.s, root)+string(filepath.Separator), root)
	}
	return out
}

// sameWorkspace fails unless got, what cargo metadata finds in the mirror, is ws there: an absolute path in a Cargo.toml leads cargo out of the mirror, to another root or to a member it reaches only through a link, which cargo add would write (verified with cargo 1.99.1).
func (mi *cargoMirror) sameWorkspace(got, ws cargoWorkspace) error {
	project := strings.NewReplacer(mi.strip()...)
	if got.Lock != mi.at(ws.Lock) {
		return fmt.Errorf("it would take %s as the workspace root, not %s", filepath.Dir(project.Replace(got.Lock)), filepath.Dir(ws.Lock))
	}
	want := map[string]bool{}
	for _, m := range ws.Manifests {
		want[mi.at(m)] = true
	}
	for _, m := range got.Manifests {
		if !want[m] {
			return fmt.Errorf("it would take %s as a member too", project.Replace(m))
		}
		delete(want, m)
	}
	for _, m := range ws.Manifests {
		if want[mi.at(m)] {
			return fmt.Errorf("it would not take %s as a member", m)
		}
	}
	return nil
}

// added fails unless what cargo add left in the mirror stands for the project, given what cargo metadata found there before and after the add: a relative path in a copy may not climb out of the mirror, since the project stops `..` at its volume's root, and a path dependency the add brought in that is no member here may be none in the project either, or the lock would lack its dev-dependencies (verified with cargo 1.99.1).
func (mi *cargoMirror) added(before, after, ws cargoWorkspace, files []cargoFile) error {
	for _, f := range files {
		if f.path == ws.Lock || !f.existed {
			continue
		}
		p, err := mi.leaves(f)
		if err != nil {
			return err
		}
		if p != "" {
			return fmt.Errorf("after the add %s would hold the path %q, which leads out of ossprey's copy of the workspace to another directory than in the project; make the dependency's path relative to its Cargo.toml", f.path, p)
		}
	}
	old := map[string]bool{}
	for _, d := range before.Deps {
		old[d] = true
	}
	for _, m := range after.Manifests {
		old[filepath.Dir(m)] = true
	}
	root := filepath.Dir(ws.Lock)
	for _, d := range after.Deps {
		if old[d] {
			continue
		}
		pointer, err := cargoWorkspacePointer(filepath.Join(d, "Cargo.toml"))
		if err != nil {
			return err
		}
		// The project takes one under its root as a member, as cargo spells both or through a link, or one whose package.workspace leads to its root; the mirror takes neither once the path leaves it.
		if !within(mi.s, d) && (within(root, d) || within(canonicalDir(root), canonicalDir(d))) || pointer != "" && (filepath.IsAbs(pointer) || !within(mi.s, filepath.Join(d, pointer))) {
			return fmt.Errorf("cargo would see another workspace in ossprey's copy of it after the add, since it would not take %s as a member; %s", d, cargoAbsoluteHint)
		}
	}
	if after.Lock != before.Lock {
		return fmt.Errorf("cargo would see another workspace in ossprey's copy of it after the add, rooted at %s; %s", filepath.Dir(after.Lock), cargoAbsoluteHint)
	}
	return nil
}

// leaves is a relative path the manifest copy f holds that climbs out of its volume in the mirror, or "".
func (mi *cargoMirror) leaves(f cargoFile) (string, error) {
	var doc map[string]any
	if err := toml.Unmarshal(f.data, &doc); err != nil {
		return "", fmt.Errorf("cannot read %s as cargo add left it (%v)", f.path, err)
	}
	dir := mi.at(filepath.Dir(f.path))
	top := mi.at(filepath.VolumeName(f.path) + string(filepath.Separator))
	out := ""
	cargoPaths(doc, "", func(p string) {
		if out == "" && !filepath.IsAbs(p) && (driveRelative(p) || !within(top, filepath.Join(dir, p))) {
			out = p
		}
	})
	return out, nil
}

// cargoPaths yields every `path` value in a decoded manifest, and package.workspace, wherever they sit bar package.metadata and workspace.metadata.
func cargoPaths(v any, key string, yield func(string)) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			// Those tables hold whatever other tools put there, and cargo follows no path in them.
			if k == "metadata" && (key == "package" || key == "project" || key == "workspace") {
				continue
			}
			cargoPaths(x, k, yield)
		}
	case []map[string]any:
		for _, x := range v {
			cargoPaths(x, key, yield)
		}
	case []any:
		for _, x := range v {
			cargoPaths(x, key, yield)
		}
	case string:
		if key == "path" || key == "workspace" {
			yield(v)
		}
	}
}

// cargoWorkspacePointer is the workspace root a crate's manifest names in package.workspace, or in a legacy [project], or "".
func cargoWorkspacePointer(manifest string) (string, error) {
	data, _, err := readCargoFile(manifest)
	if err != nil {
		return "", err
	}
	var m struct {
		Package struct {
			Workspace string `toml:"workspace"`
		} `toml:"package"`
		Project struct {
			Workspace string `toml:"workspace"`
		} `toml:"project"`
	}
	if err := toml.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("cannot read %s (%v)", manifest, err)
	}
	return cmp.Or(m.Package.Workspace, m.Project.Workspace), nil
}

// within reports whether the clean path p is dir or lies under it.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// remove deletes the mirror; os.RemoveAll follows no link out of it.
func (mi *cargoMirror) remove() {
	os.RemoveAll(mi.s)
}

// mirrorPath is where the absolute path p sits in a mirror at s: s/p, with a Windows volume as one directory (C:\x is s\C\x).
func mirrorPath(s, p string) string {
	vol := filepath.VolumeName(p)
	return filepath.Join(s, mirrorVolume(vol), p[len(vol):])
}

// mirrorVolume is the one directory name vol gets and no other volume does, in any case: a drive's letter, else the volume in hex, never one character.
func mirrorVolume(vol string) string {
	if isDrive(vol) {
		return vol[:1]
	}
	return hex.EncodeToString([]byte(vol))
}

// fileKey is one key for every spelling of the file p, folding case only on Windows and macOS, whose filesystems may fold it, and taking Windows' short names.
func fileKey(p string) string {
	k := filepath.Join(canonicalDir(filepath.Dir(p)), filepath.Base(p))
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(k)
	}
	return k
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
