package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestCatalogNoExecNeverShellsOut plants fake npm/uv binaries first on PATH
// that record every invocation, then catalogs a tree that would normally
// trigger both resolvers (a lockfile-less package.json and a pyproject.toml).
// With NoExec set, neither tool may run — the pre-commit path depends on it.
func TestCatalogNoExecNeverShellsOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}

	sentinel := filepath.Join(t.TempDir(), "invoked")
	binDir := t.TempDir()
	script := "#!/bin/sh\necho ran >> " + sentinel + "\nexit 0\n"
	for _, name := range []string{"npm", "uv"} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	proj := t.TempDir()
	writeFixture(t, proj, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`)
	writeFixture(t, proj, "pyproject.toml", "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"click\"]\n")

	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true, NoExec: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("NoExec catalog shelled out to npm/uv (sentinel exists, stat err = %v)", err)
	}

	// The pure parsers must still have produced the direct deps.
	found := map[string]bool{}
	for _, p := range pkgs {
		found[p.Type+"/"+p.Name] = true
	}
	for _, want := range []string{"npm/left-pad", "pypi/click"} {
		if !found[want] {
			t.Errorf("expected %s in NoExec catalog output, got %+v", want, pkgs)
		}
	}
}

func writeFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
