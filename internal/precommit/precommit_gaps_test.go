package precommit

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/trust"
)

// The hook must stay offline and never run a package manager against the
// synthetic trees: catalog is called with NoExec and no version lookup, and
// the trust policy is passed through.
func TestStagedDeltaCatalogsOfflineAndNoExec(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, "package.json", `{"name":"app","dependencies":{"left-pad":"^1.3.0"}}`)
	gitT(t, dir, "add", "-A")

	policy := trust.Policy{NpmScopes: []string{"@acme"}}
	var seen []catalog.Options
	old := catalogFn
	catalogFn = func(ctx context.Context, root string, o catalog.Options) ([]catalog.Package, error) {
		seen = append(seen, o)
		return nil, nil
	}
	t.Cleanup(func() { catalogFn = old })

	if _, err := StagedDelta(context.Background(), dir, policy); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("catalog called %d times, want staged + head", len(seen))
	}
	for _, o := range seen {
		if !o.NoExec || !o.SkipVersionLookup {
			t.Errorf("catalog options %+v: want NoExec and SkipVersionLookup", o)
		}
		if !reflect.DeepEqual(o.Trust, policy) {
			t.Errorf("trust policy not passed through: %+v", o.Trust)
		}
	}
}

// A commit touching no manifest never catalogs anything.
func TestStagedDeltaSkipsCatalogWithoutManifestChanges(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, "main.go", "package main\n")
	gitT(t, dir, "add", "-A")

	old := catalogFn
	catalogFn = func(context.Context, string, catalog.Options) ([]catalog.Package, error) {
		t.Fatal("catalog ran for a commit with no manifest change")
		return nil, nil
	}
	t.Cleanup(func() { catalogFn = old })

	d, err := StagedDelta(context.Background(), dir, trust.Policy{})
	if err != nil || len(d.Packages) != 0 {
		t.Fatalf("delta = %+v, %v", d, err)
	}
}

// Paths with spaces survive git's -z listing and the temp-tree round trip.
func TestStagedDeltaPathWithSpaces(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, "README.md", "x")
	commitAll(t, dir)
	writeRepoFile(t, dir, "my app/requirements.txt", "requests==2.31.0\n")
	gitT(t, dir, "add", "-A")

	got, err := StagedDelta(context.Background(), dir, trust.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{Type: "pypi", Name: "requests", Version: "2.31.0", Path: "my app/requirements.txt"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Fatalf("got %+v, want %+v", got.Packages, want)
	}
}

// A brand-new lockfile next to an existing one reports only what is new.
func TestStagedDeltaNewNestedLockfileCountsAsAdded(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
	commitAll(t, dir)
	writeRepoFile(t, dir, "api/package-lock.json", npmLock(map[string]string{"is-odd": "3.0.1"}))
	gitT(t, dir, "add", "-A")

	got, err := StagedDelta(context.Background(), dir, trust.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{{Type: "npm", Name: "is-odd", Version: "3.0.1", Path: "api/package-lock.json"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Fatalf("got %+v, want %+v", got.Packages, want)
	}
}

func TestDiffPackagesRules(t *testing.T) {
	head := []catalog.Package{
		{Type: "pypi", Name: "Requests", Version: "2.31.0"},
		{Type: "npm", Name: "left-pad", Version: "1.3.0"},
	}
	staged := []catalog.Package{
		// Same release, different name spelling: not new.
		{Type: "pypi", Name: "requests ", Version: "2.31.0"},
		// Versionless range for a package HEAD already pins: not new.
		{Type: "npm", Name: "left-pad", Version: ""},
		// The repo's own workspace code: never a registry package.
		{Type: "npm", Name: "my-workspace", Version: "0.0.1", Local: true},
		// Same name in another ecosystem is a different package.
		{Type: "npm", Name: "requests", Version: "2.31.0", Locations: []string{"package-lock.json"}},
		// Seen in two manifests: reported once.
		{Type: "npm", Name: "is-odd", Version: "3.0.1", Locations: []string{"web/package-lock.json"}},
		{Type: "npm", Name: "is-odd", Version: "3.0.1", Locations: []string{"package-lock.json"}},
		// A versionless name HEAD does not have at all is new.
		{Type: "pypi", Name: "flask", Version: "", Locations: []string{"pyproject.toml"}},
	}
	got := diffPackages(staged, head, t.TempDir(), []string{"package-lock.json", "web/package-lock.json", "pyproject.toml"})
	want := []Package{
		{Type: "npm", Name: "is-odd", Version: "3.0.1", Path: "web/package-lock.json"},
		{Type: "npm", Name: "requests", Version: "2.31.0", Path: "package-lock.json"},
		{Type: "pypi", Name: "flask", Version: "", Path: "pyproject.toml"},
	}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Fatalf("delta:\n got %+v\nwant %+v", got.Packages, want)
	}
	if got.Trusted != 0 {
		t.Fatalf("trusted = %d", got.Trusted)
	}
}

// On an unborn branch, StagedDelta run from a subdirectory (a hook started in
// one, `ossprey precommit` from sub/) still sees the whole index, with paths
// git can read back.
func TestStagedDeltaUnbornBranchFromSubdirectory(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
	writeRepoFile(t, dir, "sub/package-lock.json", npmLock(map[string]string{"is-odd": "3.0.1"}))
	writeRepoFile(t, dir, "my app/requirements.txt", "requests==2.31.0\n")
	gitT(t, dir, "add", "-A") // no commit: unborn branch

	got, err := StagedDelta(context.Background(), filepath.Join(dir, "sub"), trust.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Type: "npm", Name: "is-odd", Version: "3.0.1", Path: "sub/package-lock.json"},
		{Type: "npm", Name: "left-pad", Version: "1.3.0", Path: "package-lock.json"},
		{Type: "pypi", Name: "requests", Version: "2.31.0", Path: "my app/requirements.txt"},
	}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Fatalf("got %+v, want %+v", got.Packages, want)
	}
}
