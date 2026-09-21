package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/severity"
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

func TestHasUnscannedManifestsFindsCargo(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "crates/engine/Cargo.toml")

	if !HasUnscannedManifests(context.Background(), root) {
		t.Fatal("want true for a tree holding a Cargo.toml")
	}
}

func TestHasUnscannedManifestsIgnoresVendoredTrees(t *testing.T) {
	root := t.TempDir()
	write(t, root, "node_modules/dep/Cargo.toml")
	write(t, root, "target/debug/Cargo.lock")
	write(t, root, ".git/Cargo.toml")

	if HasUnscannedManifests(context.Background(), root) {
		t.Fatal("want false: vendored and build trees are not the project")
	}
}

func TestHasUnscannedManifestsIgnoresCataloguedEcosystems(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "pyproject.toml")
	write(t, root, "requirements.txt")

	if HasUnscannedManifests(context.Background(), root) {
		t.Fatal("want false: those ecosystems are catalogued")
	}
}

func TestHasUnscannedManifestsWarnsOnAnUnreadableSubtree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0o000 does not stop directory listing on Windows")
	}
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
	HasUnscannedManifests(ctx, root)

	if got := warn.Drain(ctx); !strings.Contains(got, "coverage is not certain") {
		t.Fatalf("want an uncertain-coverage warning, got %q", got)
	}
}

func TestMarkPartialDowngradesOnlyClean(t *testing.T) {
	clean := NewReport(&ossbom.SBOM{}, severity.FailingFloor)
	clean.MarkPartial()
	if clean.Verdict != VerdictPartial {
		t.Fatalf("want partial, got %q", clean.Verdict)
	}

	// A scan that found malware is a malware verdict, incomplete or not.
	mal := Report{Verdict: VerdictMalware}
	mal.MarkPartial()
	if mal.Verdict != VerdictMalware {
		t.Fatalf("want malware preserved, got %q", mal.Verdict)
	}

	info := Report{Verdict: VerdictInformational}
	info.MarkPartial()
	if info.Verdict != VerdictInformational {
		t.Fatalf("want informational preserved, got %q", info.Verdict)
	}
}
