package forward

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Linux keeps cargo.toml apart from Cargo.toml, so a config of that name given to --config reaches cargo in the mirror rather than being taken for the manifest's copy (OSS-2553).
func TestRunCargoAdd_ConfigNamedCargoTomlReachesTheMirror(t *testing.T) {
	root, ws := cargoProject(t)
	const config = "[term]\nquiet = false\n"
	writeFile(t, filepath.Join(root, "cargo.toml"), config)
	f := &fakeCargo{t: t, root: root, lock: evilLock}
	cargoRunFn = func(ctx context.Context, dir string, env, args []string, stderr io.Writer) error {
		// cargo reads a --config file where it runs.
		if data, err := os.ReadFile(filepath.Join(dir, "cargo.toml")); err != nil || string(data) != config {
			t.Errorf("cargo in the mirror reads cargo.toml as %q (%v), want the project's config", data, err)
		}
		return f.run(ctx, dir, env, args, stderr)
	}
	swap(t, nil, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return cleanCrates(), nil })
	if _, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "--config", "cargo.toml", "-p", "a", "evil"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := readFile(t, ws.Manifests[1]); got != memberManifest+addedEvil {
		t.Errorf("member manifest = %q, want cargo's", got)
	}
	if got := readFile(t, filepath.Join(root, "cargo.toml")); got != config {
		t.Errorf("cargo.toml = %q, want it untouched", got)
	}
}
