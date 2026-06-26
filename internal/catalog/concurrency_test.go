package catalog

import (
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func TestCatalogConcurrency(t *testing.T) {
	t.Setenv("OSSPREY_SCAN_CONCURRENCY", "")
	if got := catalogConcurrency(); got != 8 {
		t.Errorf("default = %d, want 8", got)
	}
	t.Setenv("OSSPREY_SCAN_CONCURRENCY", "3")
	if got := catalogConcurrency(); got != 3 {
		t.Errorf("override = %d, want 3", got)
	}
	for _, bad := range []string{"0", "-1", "abc"} {
		t.Setenv("OSSPREY_SCAN_CONCURRENCY", bad)
		if got := catalogConcurrency(); got != 8 {
			t.Errorf("invalid(%q) = %d, want default 8", bad, got)
		}
	}
}

func buildResolver(t *testing.T, dir string) file.Resolver {
	t.Helper()
	src, err := directorysource.NewFromPath(dir)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	t.Cleanup(func() { src.Close() })
	r, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	return r
}

func TestCatalogByGlob_DeterministicUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	const n = 24
	for i := 0; i < n; i++ {
		writeFile(t, dir, fmt.Sprintf("m%02d.dep", i), "x")
	}
	resolver := buildResolver(t, dir)

	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		base := filepath.Base(loc.RealPath)
		idx, _ := strconv.Atoi(base[1:3])
		time.Sleep(time.Duration(n-idx) * time.Millisecond)
		return []pkg.Package{{
			Name:      fmt.Sprintf("pkg%02d", idx),
			Version:   "1.0.0",
			Type:      pkg.NpmPkg,
			Locations: file.NewLocationSet(loc),
		}}, nil
	}

	t.Setenv("OSSPREY_SCAN_CONCURRENCY", "1")
	seq, err := catalogByGlob(resolver, dir, "**/*.dep", "test", parse)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OSSPREY_SCAN_CONCURRENCY", "8")
	conc, err := catalogByGlob(resolver, dir, "**/*.dep", "test", parse)
	if err != nil {
		t.Fatal(err)
	}

	if len(seq) != n || len(conc) != n {
		t.Fatalf("len seq=%d conc=%d, want %d", len(seq), len(conc), n)
	}
	for i := range seq {
		if seq[i].Name != conc[i].Name || seq[i].Version != conc[i].Version {
			t.Fatalf("order/content differs at %d: seq=%s conc=%s", i, seq[i].Name, conc[i].Name)
		}
	}
}

// Duplicate (name,version) across files collapses to one entry under concurrency.
func TestCatalogByGlob_DedupUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.dep", "b.dep", "c.dep"} {
		writeFile(t, dir, name, "x")
	}
	resolver := buildResolver(t, dir)
	parse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		return []pkg.Package{{Name: "dup", Version: "1.0.0", Type: pkg.NpmPkg, Locations: file.NewLocationSet(loc)}}, nil
	}
	t.Setenv("OSSPREY_SCAN_CONCURRENCY", "8")
	out, err := catalogByGlob(resolver, dir, "**/*.dep", "test", parse)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d packages, want 1 (deduped): %v", len(out), out)
	}
}
