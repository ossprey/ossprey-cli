package scan

import (
	"os"
	"path/filepath"
	"testing"
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

	got := DetectUnscanned(root)
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

	if got := DetectUnscanned(root); len(got) != 0 {
		t.Fatalf("want nothing from vendored trees, got %+v", got)
	}
}

func TestDetectUnscannedCoversEveryUncataloguedEcosystem(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod")
	write(t, root, "pom.xml")
	write(t, root, "Gemfile.lock")
	write(t, root, "composer.json")
	write(t, root, "Podfile")
	write(t, root, "pubspec.yaml")
	write(t, root, "packages.config")

	got := DetectUnscanned(root)
	ecos := make([]string, 0, len(got))
	for _, e := range got {
		ecos = append(ecos, e.Ecosystem)
	}
	want := []string{"cocoapods", "composer", "gem", "golang", "maven", "nuget", "pub"}
	if len(ecos) != len(want) {
		t.Fatalf("want %v, got %v", want, ecos)
	}
	for i := range want {
		if ecos[i] != want[i] {
			t.Fatalf("want sorted %v, got %v", want, ecos)
		}
	}
}

func TestDetectUnscannedIgnoresCataloguedEcosystems(t *testing.T) {
	// package.json and pyproject.toml are catalogued, so they must never warn.
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "pyproject.toml")
	write(t, root, "requirements.txt")

	if got := DetectUnscanned(root); len(got) != 0 {
		t.Fatalf("want nothing for catalogued ecosystems, got %+v", got)
	}
}

func TestDetectUnscannedCleanTree(t *testing.T) {
	root := t.TempDir()
	write(t, root, "package.json")
	write(t, root, "src/index.js")

	if got := DetectUnscanned(root); len(got) != 0 {
		t.Fatalf("want no entries, got %+v", got)
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
