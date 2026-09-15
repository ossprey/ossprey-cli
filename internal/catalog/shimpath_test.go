package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/shim"
)

// shimScript is a stand-in for a real ossprey shim: it carries the marker that
// shim.IsShim keys on, and records that it ran.
func shimScript(sentinel, tag string) string {
	return "#!/bin/sh\n# " + shim.Marker + "\necho " + tag + " >> " + sentinel + "\nexit 0\n"
}

// TestCatalogNeverInvokesAnOssprevShim is the regression test for the scan
// recursion (OSS-1993): the resolver catalogers used exec.LookPath, so on a
// machine with `ossprey shim install` the `npm`/`uv` they found was the shim,
// which re-entered `ossprey npm install ...` — which found no packages named,
// scanned the temp manifest, and shelled out to the shim again. A plain
// `ossprey scan .` fork-bombed itself until the per-resolve timeout fired, and
// emitted a whole nested scan's output inside one cataloger warning.
//
// With only shims on PATH there is no real tool, so the catalogers must skip
// exactly as they do when the tool is absent — never execute the shim.
func TestCatalogNeverInvokesAnOssprevShim(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}

	sentinel := filepath.Join(t.TempDir(), "invoked")
	shimDir := t.TempDir()
	for _, name := range []string{"npm", "uv"} {
		if err := os.WriteFile(filepath.Join(shimDir, name), []byte(shimScript(sentinel, name)), 0o755); err != nil {
			t.Fatalf("write fake %s shim: %v", name, err)
		}
	}
	t.Setenv("PATH", shimDir)

	proj := t.TempDir()
	writeFixture(t, proj, "package.json", `{"name":"app","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}`)
	writeFixture(t, proj, "pyproject.toml", "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"click\"]\n")

	pkgs, err := Catalog(context.Background(), proj, Options{SkipVersionLookup: true})
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if b, err := os.ReadFile(sentinel); err == nil {
		t.Fatalf("catalog executed an ossprey shim (would recurse into ossprey): %s", strings.TrimSpace(string(b)))
	}

	// Skipping the shim must not cost us the direct-dep fallbacks.
	found := map[string]bool{}
	for _, p := range pkgs {
		found[p.Type+"/"+p.Name] = true
	}
	for _, want := range []string{"npm/left-pad", "pypi/click"} {
		if !found[want] {
			t.Errorf("expected %s in catalog output, got %+v", want, pkgs)
		}
	}
}

// TestLookToolPrefersTheRealToolOverAShim covers the ordinary installed case:
// the shim directory is first on PATH (that is the whole point of it), and the
// real tool sits behind it. The cataloger must reach past the shim.
func TestLookToolPrefersTheRealToolOverAShim(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH interception uses shell scripts")
	}

	shimDir, realDir := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(shimDir, "npm"), []byte(shimScript("/dev/null", "shim")), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	real := filepath.Join(realDir, "npm")
	if err := os.WriteFile(real, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write real npm: %v", err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+realDir)

	got, err := lookTool("npm")
	if err != nil {
		t.Fatalf("lookTool: %v", err)
	}
	if got != real {
		t.Fatalf("lookTool resolved %q, want the real npm at %q", got, real)
	}
}

// TestToolEnvBypassesShims is the second half of the recursion guard: even if a
// shim is reached by a route PATH scanning cannot see — a symlinked PATH entry,
// or npm/uv re-invoking itself — the bypass makes it forward unchecked instead
// of re-entering ossprey.
func TestToolEnvBypassesShims(t *testing.T) {
	env := toolEnv("npm_config_cache=/tmp/cache")
	if !slices.Contains(env, shim.BypassEnv+"=1") {
		t.Errorf("toolEnv did not set %s=1: %v", shim.BypassEnv, env)
	}
	if !slices.Contains(env, "npm_config_cache=/tmp/cache") {
		t.Errorf("toolEnv dropped the caller's own variable: %v", env)
	}
}
