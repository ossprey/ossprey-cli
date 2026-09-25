package forward

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// noLocalBins makes every name look absent from node_modules, so a parse test
// does not depend on the directory it runs in.
func noLocalBins(t *testing.T) {
	t.Helper()
	old := localBinFn
	localBinFn = func(string, bool) bool { return false }
	t.Cleanup(func() { localBinFn = old })
}

func TestNpxParse(t *testing.T) {
	noLocalBins(t)
	npm := func(name, version string) check.Spec {
		return check.Spec{Ecosystem: "npm", Name: name, Version: version}
	}
	cases := []struct {
		name  string
		args  []string
		specs []check.Spec
		non   []string
	}{
		{"bare command", []string{"cowsay"}, []check.Spec{npm("cowsay", "")}, nil},
		// Only the first positional is a package: moo is cowsay's argv, and a
		// real npm package too.
		{"program args are not packages", []string{"cowsay", "moo"}, []check.Spec{npm("cowsay", "")}, nil},
		{"program flags are not ours", []string{"cowsay", "-p", "evil"}, []check.Spec{npm("cowsay", "")}, nil},
		{"pinned", []string{"cowsay@1.5.0", "moo"}, []check.Spec{npm("cowsay", "1.5.0")}, nil},
		{"scoped pinned", []string{"@angular/cli@17.0.0", "new", "app"}, []check.Spec{npm("@angular/cli", "17.0.0")}, nil},
		{"dist-tag resolves latest", []string{"create-vite@latest", "app"}, []check.Spec{npm("create-vite", "")}, nil},
		{"range resolves latest", []string{"cowsay@^1"}, []check.Spec{npm("cowsay", "")}, nil},
		{"leading options", []string{"-y", "--quiet", "create-react-app", "my-app"}, []check.Spec{npm("create-react-app", "")}, nil},
		{"value flag before command", []string{"--registry", "https://r.example", "cowsay"}, []check.Spec{npm("cowsay", "")}, nil},
		{"double dash", []string{"--yes", "--", "cowsay", "moo"}, []check.Spec{npm("cowsay", "")}, nil},
		// With -p, the positional is a command the packages provide.
		{"package flag", []string{"-p", "typescript@5.4.0", "tsc", "--version"}, []check.Spec{npm("typescript", "5.4.0")}, nil},
		{"package flag inline and repeated", []string{"--package=yo", "--package", "generator-code", "--", "yo", "code"},
			[]check.Spec{npm("yo", ""), npm("generator-code", "")}, nil},
		{"call with package", []string{"-p", "cowsay", "-c", "cowsay hi"}, []check.Spec{npm("cowsay", "")}, nil},
		{"call alone fetches nothing", []string{"-c", "eslint ."}, nil, nil},
		{"alias", []string{"npm:cowsay@1.5.0"}, []check.Spec{npm("cowsay", "1.5.0")}, nil},
		{"git target", []string{"github:user/repo"}, nil, []string{"github:user/repo"}},
		{"local path", []string{"./tool"}, nil, []string{"./tool"}},
		{"nothing", []string{"--version"}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := npxParse(tc.args)
			if !reflect.DeepEqual(got.Specs, tc.specs) {
				t.Errorf("specs = %+v, want %+v", got.Specs, tc.specs)
			}
			if !reflect.DeepEqual(got.NonPackages, tc.non) {
				t.Errorf("non-packages = %v, want %v", got.NonPackages, tc.non)
			}
		})
	}
}

func TestNpxLocalBinIsNotChecked(t *testing.T) {
	old := localBinFn
	localBinFn = func(name string, _ bool) bool { return name == "eslint" }
	t.Cleanup(func() { localBinFn = old })

	if got := npxParse([]string{"eslint", "."}).Specs; len(got) != 0 {
		t.Errorf("a project-local bin runs from node_modules and fetches nothing; got specs %+v", got)
	}
	// A pinned version is fetched unless the local copy matches, so it is checked.
	if got := npxParse([]string{"eslint@9.0.0", "."}).Specs; len(got) != 1 {
		t.Errorf("a pinned command must still be checked; got %+v", got)
	}
}

func TestLocalBin(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "node_modules", ".bin"), 0o755))
	must(os.WriteFile(filepath.Join(root, "node_modules", ".bin", "tsc"), nil, 0o755))
	must(os.MkdirAll(filepath.Join(root, "node_modules", "@scope", "tool"), 0o755))
	must(os.WriteFile(filepath.Join(root, "node_modules", "@scope", "tool", "package.json"), []byte("{}"), 0o644))
	sub := filepath.Join(root, "src", "deep")
	must(os.MkdirAll(sub, 0o755))
	t.Chdir(sub)

	if !localBin("tsc", true) {
		t.Error("tsc is a bin in the nearest project's node_modules/.bin")
	}
	if localBin("tsc", false) {
		t.Error("a -p package is looked up as a package, not as a bin")
	}
	if !localBin("@scope/tool", false) {
		t.Error("@scope/tool is installed in the project")
	}
	if localBin("cowsay", true) {
		t.Error("cowsay is not installed")
	}

	// A nearer project root stops the walk: npm does not look past it.
	must(os.WriteFile(filepath.Join(sub, "package.json"), []byte("{}"), 0o644))
	if localBin("tsc", true) {
		t.Error("the walk must stop at the nearest package.json")
	}
}

func TestRun_Npx_ChecksThePackageBeforeRunningIt(t *testing.T) {
	noLocalBins(t)
	var order []string
	var gotSpecs []check.Spec
	swap(t, func(_ context.Context, bin string, _ []string) error {
		order = append(order, "exec:"+bin)
		return nil
	}, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		order, gotSpecs = append(order, "check"), o.Specs
		return ossbom.New(ossbom.Environment{}), nil
	})

	args := []string{"-y", "cowsay@1.5.0", "moo"}
	if err := Run(context.Background(), Options{Bin: "npx", Args: args}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := []string{"check", "exec:npx"}; !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want %v", order, want)
	}
	if want := []check.Spec{{Ecosystem: "npm", Name: "cowsay", Version: "1.5.0"}}; !reflect.DeepEqual(gotSpecs, want) {
		t.Errorf("checked %+v, want %+v", gotSpecs, want)
	}
}

func TestRun_Npx_MalwareBlocks(t *testing.T) {
	noLocalBins(t)
	ex := &stubExec{}
	swap(t, ex.fn, malwareSBOM)

	err := Run(context.Background(), Options{Bin: "npx", Args: []string{"evil@1.0.0"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("npx must not run a package flagged as malware")
	}
}

// Naming nothing to fetch is not a manifest install: npx runs something already
// on disk, so it must forward without scanning the project.
func TestRun_Npx_NothingToFetchForwardsWithoutScan(t *testing.T) {
	old := localBinFn
	localBinFn = func(string, bool) bool { return true }
	t.Cleanup(func() { localBinFn = old })

	for _, args := range [][]string{{"eslint", "."}, {"-c", "echo hi"}, {"--version"}, {"github:user/repo"}} {
		ex := &stubExec{}
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			t.Errorf("%v: nothing is fetched, so nothing should be checked", args)
			return nil, nil
		})
		if err := Run(context.Background(), Options{Bin: "npx", Args: args}); err != nil {
			t.Fatalf("%v: Run: %v", args, err)
		}
		if !ex.called || !reflect.DeepEqual(ex.args, args) {
			t.Errorf("%v: forwarded %v (called=%v)", args, ex.args, ex.called)
		}
	}
}

func TestRun_Npx_ResolvesUnpinnedToLatest(t *testing.T) {
	noLocalBins(t)
	ex := &stubExec{}
	var got string
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o.Specs[0].Version
		return ossbom.New(ossbom.Environment{}), nil
	})
	err := Run(context.Background(), Options{
		Bin:           "npx",
		Args:          []string{"create-vite@latest", "app"},
		ResolveLatest: func(context.Context, string, string) (string, error) { return "5.2.0", nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got != "5.2.0" {
		t.Errorf("checked version %q, want the registry's latest", got)
	}
}

// npx writes no lockfile, so passive mode submits the named package alongside
// the run rather than cataloguing the directory afterwards.
func TestRun_Npx_PassiveSubmitsTheNamedPackage(t *testing.T) {
	noLocalBins(t)
	ex := &stubExec{}
	var got check.Options
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		got = o
		return malwareSBOM(context.Background(), o)
	})
	err := Run(context.Background(), Options{Bin: "npx", Args: []string{"evil@1.0.0"}, Passive: true})
	if err != nil {
		t.Fatalf("passive never blocks: %v", err)
	}
	if !ex.called {
		t.Error("passive must run npx")
	}
	if !got.SubmitOnly || len(got.Specs) != 1 || got.Specs[0].Name != "evil" {
		t.Errorf("submitted %+v, want evil submit-only", got)
	}
}
