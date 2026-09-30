package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
