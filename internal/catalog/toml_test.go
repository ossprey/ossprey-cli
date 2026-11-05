package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// deepTOMLKey is one dotted key nested depth levels.
func deepTOMLKey(depth int) string {
	return strings.Repeat("a.", depth) + "z = 1\n"
}

// OSS-2098: the parser allocates quadratically in nesting, about 643 MB for this 8 KB key.
func TestDecodeTOMLAllocationStaysBounded(t *testing.T) {
	data := []byte(deepTOMLKey(4000))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var v map[string]any
	_, err := decodeTOML(data, &v)
	runtime.ReadMemStats(&after)

	if !errors.Is(err, errTOMLTooDeep) {
		t.Errorf("decodeTOML() error = %v, want errTOMLTooDeep", err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 16<<20 {
		t.Errorf("decoding an 8 KB key allocated %d MB", alloc>>20)
	}
}

func TestDecodeTOMLRejectsEveryWayToNest(t *testing.T) {
	n := maxTOMLDepth + 36
	for name, doc := range map[string]string{
		"dotted key": deepTOMLKey(n),
		// A count of the dots left of the first = sees none here.
		"quoted = in the key": `"=".` + deepTOMLKey(n),
		"inline tables":       "x = " + strings.Repeat("{a=", n) + "1" + strings.Repeat("}", n) + "\n",
		// The parser accepts TOML 1.1 newlines inside inline tables.
		"multi-line inline tables": "x = " + strings.Repeat("{\na=", n) + "1" + strings.Repeat("\n}", n) + "\n",
		"table header":             "[" + strings.Repeat("a.", n) + "z]\nx = 1\n",
		"array of tables header":   "[[" + strings.Repeat("a.", n) + "z]]\nx = 1\n",
		"header and key together":  "[" + strings.Repeat("a.", 40) + "z]\n" + strings.Repeat("b.", 40) + "z = 1\n",
		"arrays":                   "x = " + strings.Repeat("[", n) + "1" + strings.Repeat("]", n) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			var v map[string]any
			if _, err := decodeTOML([]byte(doc), &v); !errors.Is(err, errTOMLTooDeep) {
				t.Errorf("decodeTOML() error = %v, want errTOMLTooDeep", err)
			}
		})
	}
}

func TestDecodeTOMLStillParsesRealManifests(t *testing.T) {
	// Dots, brackets and = that only nest when read outside a string or comment.
	noise := strings.Repeat("a.", 2*maxTOMLDepth) + strings.Repeat("{[", maxTOMLDepth) + " = x"
	for name, doc := range map[string]string{
		"cfg target":           `[target.'cfg(all(unix, not(target_os = "macos")))'.dependencies]` + "\nnix = \"0.27\"\n",
		"quoted dotted keys":   `"` + noise + `" = "1"` + "\n'b." + noise + "' = \"2\"\n",
		"multi-line strings":   "x = \"\"\"\n" + noise + "\n\"\"\"\ny = '''\n" + noise + "\n'''\n",
		"comments":             "# " + noise + "\nx = [ # " + noise + "\n  1,\n]\n",
		"escaped quotes":       `x = "\"` + noise + `\\"` + "\n",
		"floats in long array": "x = [" + strings.Repeat("1.5, ", 4*maxTOMLDepth) + "1.5]\n",
	} {
		t.Run(name, func(t *testing.T) {
			var v map[string]any
			if _, err := decodeTOML([]byte(doc), &v); err != nil {
				t.Errorf("decodeTOML() error = %v, want it parsed", err)
			}
		})
	}
}

func TestDecodeTOMLReadsACfgTargetTable(t *testing.T) {
	doc := `[target.'cfg(all(unix, not(target_os = "macos")))'.dependencies]
nix = { version = "0.27", features = ["fs"] }
`
	var m cargoManifest
	if _, err := decodeTOML([]byte(doc), &m); err != nil {
		t.Fatalf("decodeTOML: %v", err)
	}
	if _, ok := m.Target[`cfg(all(unix, not(target_os = "macos")))`].Dependencies["nix"]; !ok {
		t.Errorf("nix missing from %v", m.Target)
	}
}

func TestReadTOMLParsesALargeWorkspaceRoot(t *testing.T) {
	var b strings.Builder
	b.WriteString("[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\n")
	const n = 5000
	for i := range n {
		fmt.Fprintf(&b, "dep-%d = { version = \"1.0.%d\", features = [\"derive\", \"std\"], default-features = false }\n", i, i)
	}
	path := writeFile(t, t.TempDir(), "Cargo.toml", b.String())

	data, err := readTOML(path)
	if err != nil {
		t.Fatalf("readTOML: %v", err)
	}
	var m cargoManifest
	if _, err := decodeTOML(data, &m); err != nil {
		t.Fatalf("decodeTOML: %v", err)
	}
	if got := len(m.Workspace.Dependencies); got != n {
		t.Errorf("read %d workspace dependencies, want %d", got, n)
	}
}

func TestReadTOMLRefusesAnOversizedManifest(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "pyproject.toml", strings.Repeat("#", maxManifestBytes+1))
	if _, err := readTOML(path); err == nil || !strings.HasPrefix(err.Error(), "read "+path+": ") {
		t.Errorf("readTOML() error = %v, want the size refusal naming %s", err, path)
	}
	// Callers treat a manifest gone since the glob as nothing found.
	if _, err := readTOML(filepath.Join(dir, "gone.toml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("readTOML() error = %v, want fs.ErrNotExist", err)
	}
}

// A device whose size says 0 but whose read never ends is refused before it is read.
func TestReadTOMLBoundsTheReadNotJustTheSize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/zero on Windows")
	}
	path := filepath.Join(t.TempDir(), "Cargo.toml")
	if err := os.Symlink("/dev/zero", path); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := readTOML(path); err == nil || err.Error() != "read "+path+": not a regular file" {
		t.Errorf("readTOML() error = %v, want the regular-file refusal naming %s", err, path)
	}
}

// dirResolver is the resolver Catalog reads dir through.
func dirResolver(t *testing.T, dir string) file.Resolver {
	t.Helper()
	src, err := newDirectorySource(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	r, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Lockfiles get caps of their own: one just inside the old 32 MiB and 64-level caps cost syft's parser seconds and gigabytes, and is now refused from a bounded read.
func TestBoundedLocksRefuseWhatTheOldCapsLetThrough(t *testing.T) {
	// 60 nested inline tables a line, the shape BurntSushi/toml pays most for, out to 31 MiB.
	var near strings.Builder
	for i := 0; near.Len() < 31<<20; i++ {
		fmt.Fprintf(&near, "k%d = %s1%s\n", i, strings.Repeat("{a=", 60), strings.Repeat("}", 60))
	}
	for name, c := range map[string]struct {
		body, why string
	}{
		"near the old caps":                 {near.String(), "byte limit"},
		"a dotted key past the lock depth":  {deepTOMLKey(maxLockDepth + 1), "nested deeper than 16 levels"},
		"inline tables past the lock depth": {"x = " + strings.Repeat("{a=", maxLockDepth+1) + "1" + strings.Repeat("}", maxLockDepth+1) + "\n", "nested deeper than 16 levels"},
		"a header past the lock depth":      {"[" + strings.Repeat("a.", maxLockDepth+1) + "z]\nk = 1\n", "nested deeper than 16 levels"},
		"at the lock depth":                 {deepTOMLKey(maxLockDepth), ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"app/poetry.lock": c.body})
			r := dirResolver(t, dir)
			ctx := warn.NewContext(context.Background(), false)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			bounded := withBoundedLocks(ctx, r, dir)
			took := time.Since(start)
			runtime.ReadMemStats(&after)

			locs, err := bounded.FilesByGlob("**/poetry.lock")
			drained := warn.Drain(ctx)
			if c.why == "" {
				if err != nil || len(locs) != 1 || drained != "" {
					t.Errorf("FilesByGlob() = %v, %v with warnings %q, want the lock kept in silence", locs, err, drained)
				}
				return
			}
			if err != nil || len(locs) != 0 {
				t.Errorf("FilesByGlob() = %v, %v, want the lock hidden", locs, err)
			}
			if strings.Count(drained, "\n") != 1 || !strings.Contains(drained, c.why) || !strings.Contains(drained, " "+filepath.Join("app", "poetry.lock")+":") {
				t.Errorf("warnings = %q, want one naming app/poetry.lock for %q", drained, c.why)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<20 || took > 5*time.Second {
				t.Errorf("refusing it took %v and allocated %d MB", took, alloc>>20)
			}
		})
	}
}

// The worst shapes just inside the lockfile caps are kept for syft, and one decode of each as syft's lock parsers do it stays bounded.
func TestBoundedLocksKeepOnlyWhatSyftParsesWithinBounds(t *testing.T) {
	d := maxLockDepth
	for name, line := range map[string]func(i int) string{
		"nested inline tables": func(i int) string {
			return fmt.Sprintf("k%d = %s1%s\n", i, strings.Repeat("{a=", d), strings.Repeat("}", d))
		},
		"dotted keys": func(i int) string { return fmt.Sprintf("k%d%s = 1\n", i, strings.Repeat(".a", d)) },
		"headers":     func(i int) string { return fmt.Sprintf("[k%d%s]\nx = 1\n", i, strings.Repeat(".a", d)) },
	} {
		t.Run(name, func(t *testing.T) {
			var b strings.Builder
			for i := 0; ; i++ {
				l := line(i)
				if b.Len()+len(l) > maxLockBytes {
					break
				}
				b.WriteString(l)
			}
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"app/uv.lock": b.String()})
			ctx := warn.NewContext(context.Background(), false)
			if locs, err := withBoundedLocks(ctx, dirResolver(t, dir), dir).FilesByGlob("**/uv.lock"); err != nil || len(locs) != 1 {
				t.Fatalf("FilesByGlob() = %v, %v with warnings %q, want the lock kept for syft", locs, err, warn.Drain(ctx))
			}

			var v struct {
				Version int `toml:"version"`
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := toml.NewDecoder(strings.NewReader(b.String())).Decode(&v)
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			// The worst, nested inline tables, allocates 1.4 GiB a decode here and 5.6 GiB at the old 8 MiB cap.
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 2<<30 {
				t.Errorf("decoding %d bytes allocated %d MB", b.Len(), alloc>>20)
			}
		})
	}
}

// readCounter counts the file reads through a resolver and runs onRead before each.
type readCounter struct {
	file.Resolver
	reads  int
	onRead func()
}

func (r *readCounter) FileContentsByLocation(l file.Location) (io.ReadCloser, error) {
	r.reads++
	if r.onRead != nil {
		r.onRead()
	}
	return r.Resolver.FileContentsByLocation(l)
}

// Once the scan's context ends, no lockfile is read any more and every one not yet checked stays hidden from syft.
func TestBoundedLocksStopReadingOnceTheContextEnds(t *testing.T) {
	locks := []string{"a/poetry.lock", "b/uv.lock", "c/Cargo.lock"}
	for name, c := range map[string]struct {
		cancelAfter int
		visible     []string
	}{
		"cancelled before":           {cancelAfter: 0},
		"cancelled during the first": {cancelAfter: 1, visible: locks[:1]},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{locks[0]: "[metadata]\nlock-version = \"2.0\"\n", locks[1]: "version = 1\n", locks[2]: "version = 3\n"})
			ctx, cancel := context.WithCancel(warn.NewContext(context.Background(), false))
			defer cancel()
			r := &readCounter{Resolver: dirResolver(t, dir)}
			if c.cancelAfter == 0 {
				cancel()
			} else {
				r.onRead = func() {
					if r.reads == c.cancelAfter {
						cancel()
					}
				}
			}
			bounded := withBoundedLocks(ctx, r, dir)
			if r.reads != c.cancelAfter {
				t.Errorf("read %d lockfiles, want %d", r.reads, c.cancelAfter)
			}
			// RealPath is root-relative on Unix but absolute on Windows, so both are compared from the root.
			rootPrefix := filepath.ToSlash(resolvedRoot(dir)) + "/"
			var visible []string
			for _, glob := range syftTOMLLocks {
				locs, err := bounded.FilesByGlob(glob)
				if err != nil {
					t.Fatal(err)
				}
				for _, l := range locs {
					visible = append(visible, strings.TrimPrefix(rootRel(l.RealPath, rootPrefix), "/"))
				}
			}
			if fmt.Sprint(visible) != fmt.Sprint(c.visible) {
				t.Errorf("visible lockfiles = %v, want %v", visible, c.visible)
			}
			if drained := warn.Drain(ctx); drained != "" {
				t.Errorf("warnings = %q, want none past the deadline", drained)
			}
		})
	}
}
