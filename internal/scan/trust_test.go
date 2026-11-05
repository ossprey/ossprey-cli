package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/trust"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// A trusted package is not sent: it must be absent from the SBOM itself, so
// the submission, `--local` and `-o` all agree — and the drop is counted, not
// silent.
func TestRunLeavesTrustedPackagesOutOfTheSBOM(t *testing.T) {
	dir := t.TempDir()
	lock := `{"name": "app", "version": "1.0.0", "lockfileVersion": 3, "packages": {
	  "": {"name": "app", "version": "1.0.0"},
	  "node_modules/@acme/web": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/@acme/web/-/web-2.0.0.tgz"},
	  "node_modules/acme-npm": {"version": "1.0.0", "resolved": "https://npm.internal.example/repo/acme-npm/-/acme-npm-1.0.0.tgz"},
	  "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
	}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	policy, err := trust.Parse([]string{"https://npm.internal.example/repo/"}, []string{"@acme"})
	if err != nil {
		t.Fatal(err)
	}

	ctx := warn.NewContext(context.Background(), true)
	sbom, err := Run(ctx, Options{Path: dir, NoExec: true, SkipVersionLookup: true, Trust: policy})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(componentNames(sbom), " "); got != "left-pad" {
		t.Errorf("components = %q, want only left-pad", got)
	}
	encoded, err := json.Marshal(sbom.ToMiniBOM())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"@acme", "acme-npm"} {
		if strings.Contains(string(encoded), name) {
			t.Errorf("wire SBOM mentions %s:\n%s", name, encoded)
		}
	}

	out := warn.Drain(ctx)
	if !strings.Contains(out, "2 packages are from trusted sources") ||
		!strings.Contains(out, "@acme/web@2.0.0") || !strings.Contains(out, "acme-npm@1.0.0") {
		t.Errorf("trusted packages not reported:\n%s", out)
	}
}

// A crate one lock fetches from a refused source stays in the SBOM, even where another lock names the trusted index on the same origin.
func TestRunKeepsACrateAnyLockFetchesFromARefusedSource(t *testing.T) {
	t.Setenv("CARGO_HOME", t.TempDir())
	dir := t.TempDir()
	entry := func(name, source string) string {
		return "[[package]]\nname = \"" + name + "\"\nversion = \"1.0.0\"\nsource = \"" + source + "\"\n\n"
	}
	const internal, escaped = "sparse+https://crates.corp.example/internal/", "sparse+https://crates.corp.example/public%2F..%2Finternal/"
	locks := map[string]string{
		"a/Cargo.lock": "version = 4\n\n" + entry("acme-core", internal) + entry("acme-refused-later", internal) + entry("acme-refused-first", escaped),
		"b/Cargo.lock": "version = 4\n\n" + entry("acme-core", internal) + entry("acme-refused-later", escaped) + entry("acme-refused-first", internal),
	}
	for name, lock := range locks {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(lock), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	policy, err := trust.Parse([]string{"https://crates.corp.example/internal/"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	sbom, err := Run(warn.NewContext(context.Background(), false), Options{Path: dir, NoExec: true, SkipVersionLookup: true, Trust: policy})
	if err != nil {
		t.Fatal(err)
	}
	names := componentNames(sbom)
	slices.Sort(names)
	if got := strings.Join(names, " "); got != "acme-refused-first acme-refused-later" {
		t.Errorf("components = %q, want both refused crates and not acme-core", got)
	}
}
