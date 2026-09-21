package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

func write(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectUnscannedFindsCargo(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "crates/engine/Cargo.toml")
	write(t, root, "Cargo.lock")

	got := DetectUnscanned(context.Background(), root)
	if len(got) != 1 || got[0].Ecosystem != "cargo" {
		t.Fatalf("want one cargo entry, got %+v", got)
	}
	if len(got[0].Manifests) != 2 {
		t.Fatalf("want both manifests, got %v", got[0].Manifests)
	}
	if got[0].Manifests[0] != "Cargo.lock" || got[0].Manifests[1] != "crates/engine/Cargo.toml" {
		t.Fatalf("want sorted slash paths, got %v", got[0].Manifests)
	}
}

func TestDetectUnscannedIgnoresVendoredTrees(t *testing.T) {
	root := t.TempDir()
	write(t, root, "node_modules/dep/Cargo.toml")
	write(t, root, "target/debug/Cargo.lock")
	write(t, root, ".git/Cargo.toml")

	if got := DetectUnscanned(context.Background(), root); len(got) != 0 {
		t.Fatalf("want nothing from vendored trees, got %+v", got)
	}
}

func TestDetectUnscannedIgnoresCataloguedEcosystems(t *testing.T) {
	// package.json and pyproject.toml are catalogued, so they must never warn.
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "pyproject.toml")
	write(t, root, "requirements.txt")

	if got := DetectUnscanned(context.Background(), root); len(got) != 0 {
		t.Fatalf("want nothing for catalogued ecosystems, got %+v", got)
	}
}

func TestDetectUnscannedCleanTree(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "src/index.js")

	if got := DetectUnscanned(context.Background(), root); len(got) != 0 {
		t.Fatalf("want no entries, got %+v", got)
	}
}

func TestDetectUnscannedWarnsOnAnUnreadableSubtree(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0o000 directory regardless")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, "locked/Cargo.toml")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	ctx := warn.NewContext(context.Background(), true)
	DetectUnscanned(ctx, root)

	// The manifest is hidden by the permissions, so the walk must say the
	// coverage is uncertain rather than report a confidently empty result.
	if got := warn.Drain(ctx); !strings.Contains(got, "coverage is not certain") {
		t.Fatalf("want an uncertain-coverage warning, got %q", got)
	}
}

func TestUnscannedNote(t *testing.T) {
	if UnscannedNote(nil) != "" {
		t.Fatal("want empty note for nothing unscanned")
	}
	note := UnscannedNote([]Unscanned{{Ecosystem: "cargo", Manifests: []string{"Cargo.lock"}}})
	if note == "" {
		t.Fatal("want a note naming the ecosystem")
	}
}
