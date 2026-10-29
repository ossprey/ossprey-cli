package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	if _, err := readTOML(path); err == nil || !strings.HasPrefix(err.Error(), "pyproject.toml is ") {
		t.Errorf("readTOML() error = %v, want the size refusal naming the file", err)
	}
	// Callers treat a manifest gone since the glob as nothing found.
	if _, err := readTOML(filepath.Join(dir, "gone.toml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("readTOML() error = %v, want fs.ErrNotExist", err)
	}
}
