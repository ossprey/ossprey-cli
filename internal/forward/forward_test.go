package forward

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

func TestLookup(t *testing.T) {
	for _, bin := range []string{"npm", "yarn", "pip", "poetry", "uv"} {
		if _, ok := Lookup(bin); !ok {
			t.Errorf("Lookup(%q): not found", bin)
		}
	}
	if _, ok := Lookup("cargo"); ok {
		t.Error("Lookup(cargo): expected not found")
	}
}

func TestInstallDetection(t *testing.T) {
	tests := []struct {
		bin       string
		args      []string
		wantStart int
		wantOK    bool
	}{
		{"npm", []string{"install", "lodash"}, 1, true},
		{"npm", []string{"i", "lodash"}, 1, true},
		{"npm", []string{"add", "lodash"}, 1, true},
		{"npm", []string{"ci"}, 1, true},
		{"npm", []string{"run", "build"}, 0, false},
		{"yarn", []string{"add", "react"}, 1, true},
		{"yarn", []string{"install"}, 1, true}, // bare manifest install
		{"pip", []string{"install", "requests"}, 1, true},
		{"pip", []string{"list"}, 0, false},
		{"poetry", []string{"add", "flask"}, 1, true},
		{"poetry", []string{"install"}, 1, true}, // bare manifest install
		{"uv", []string{"add", "httpx"}, 1, true},
		{"uv", []string{"pip", "install", "httpx"}, 2, true},
		{"uv", []string{"pip", "list"}, 0, false},
		{"uv", []string{"sync"}, 1, true}, // lockfile-based manifest install
	}
	for _, tt := range tests {
		m, _ := Lookup(tt.bin)
		start, ok := m.installAt(tt.args)
		if ok != tt.wantOK || (ok && start != tt.wantStart) {
			t.Errorf("%s %v: got (start=%d, ok=%v), want (start=%d, ok=%v)",
				tt.bin, tt.args, start, ok, tt.wantStart, tt.wantOK)
		}
	}
}

func TestParseSpecs(t *testing.T) {
	npm, _ := Lookup("npm")
	pip, _ := Lookup("pip")
	uvm, _ := Lookup("uv")

	tests := []struct {
		name         string
		m            *Manager
		args         []string
		wantSpecs    []check.Spec
		wantNonPkgs  []string
		wantReqFiles []string
	}{
		{
			name: "npm mixed with flags",
			m:    npm,
			args: []string{"lodash@4.17.21", "--save-dev", "@babel/core@7.0.0", "react"},
			wantSpecs: []check.Spec{
				{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
				{Ecosystem: "npm", Name: "@babel/core", Version: "7.0.0"},
				{Ecosystem: "npm", Name: "react", Version: ""},
			},
		},
		{
			name: "pip with == and bare",
			m:    pip,
			args: []string{"requests==2.31.0", "flask"},
			wantSpecs: []check.Spec{
				{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
				{Ecosystem: "pypi", Name: "flask", Version: ""},
			},
		},
		{
			name:      "all flags -> none",
			m:         pip,
			args:      []string{"-U", "--quiet"},
			wantSpecs: nil,
		},
		{
			name: "npm value-flag does not swallow its value as a package",
			m:    npm,
			args: []string{"react", "--registry", "https://r.example.com", "lodash"},
			wantSpecs: []check.Spec{
				{Ecosystem: "npm", Name: "react", Version: ""},
				{Ecosystem: "npm", Name: "lodash", Version: ""},
			},
		},
		{
			name: "pip target flag value is not a package",
			m:    pip,
			args: []string{"requests", "-t", "/opt/libs", "flask"},
			wantSpecs: []check.Spec{
				{Ecosystem: "pypi", Name: "requests", Version: ""},
				{Ecosystem: "pypi", Name: "flask", Version: ""},
			},
		},
		{
			name:         "pip requirements file is tracked separately",
			m:            pip,
			args:         []string{"-r", "requirements.txt"},
			wantSpecs:    nil,
			wantReqFiles: []string{"requirements.txt"},
		},
		{
			name: "npm local tarball and vcs ref are non-packages, real package kept",
			m:    npm,
			args: []string{"./local-tarball.tgz", "git+https://github.com/x/y.git", "lodash"},
			wantSpecs: []check.Spec{
				{Ecosystem: "npm", Name: "lodash", Version: ""},
			},
			wantNonPkgs: []string{"./local-tarball.tgz", "git+https://github.com/x/y.git"},
		},
		{
			name:      "pip editable local path is consumed by -e",
			m:         pip,
			args:      []string{"-e", ".", "requests"},
			wantSpecs: []check.Spec{{Ecosystem: "pypi", Name: "requests", Version: ""}},
		},
		{
			name:      "pip index-url value is not a package",
			m:         pip,
			args:      []string{"requests", "--index-url", "https://pypi.org/simple"},
			wantSpecs: []check.Spec{{Ecosystem: "pypi", Name: "requests", Version: ""}},
		},
		{
			name:         "pip inline --requirement= tracks the file",
			m:            pip,
			args:         []string{"--requirement=dev-requirements.txt", "requests"},
			wantSpecs:    []check.Spec{{Ecosystem: "pypi", Name: "requests", Version: ""}},
			wantReqFiles: []string{"dev-requirements.txt"},
		},
		{
			name: "uv pip install: target value and requirements file handled",
			m:    uvm,
			args: []string{"httpx==0.27.0", "-t", "vendor", "-r", "reqs.txt", "rich"},
			wantSpecs: []check.Spec{
				{Ecosystem: "pypi", Name: "httpx", Version: "0.27.0"},
				{Ecosystem: "pypi", Name: "rich", Version: ""},
			},
			wantReqFiles: []string{"reqs.txt"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSpecs(tt.m, tt.args)
			if !reflect.DeepEqual(got.Specs, tt.wantSpecs) {
				t.Errorf("Specs = %+v, want %+v", got.Specs, tt.wantSpecs)
			}
			if !reflect.DeepEqual(got.NonPackages, tt.wantNonPkgs) {
				t.Errorf("NonPackages = %+v, want %+v", got.NonPackages, tt.wantNonPkgs)
			}
			if !reflect.DeepEqual(got.ReqFiles, tt.wantReqFiles) {
				t.Errorf("ReqFiles = %+v, want %+v", got.ReqFiles, tt.wantReqFiles)
			}
		})
	}
}

// stubExec records the last forwarded command and returns nil.
type stubExec struct {
	called bool
	bin    string
	args   []string
}

func (s *stubExec) fn(_ context.Context, bin string, args []string) error {
	s.called, s.bin, s.args = true, bin, args
	return nil
}

// swap replaces the exec + check seams and restores them after the test. The
// scan-project seam is replaced with a stub that fails the test if Run reaches
// the project-scan path unexpectedly; tests that exercise it call swapScan.
func swap(t *testing.T, exec func(context.Context, string, []string) error, chk func(context.Context, check.Options) (*ossbom.SBOM, error)) {
	t.Helper()
	oe, oc, os := execFn, checkFn, scanProjectFn
	execFn, checkFn = exec, chk
	scanProjectFn = func(context.Context, string, string, string) (*ossbom.SBOM, error) {
		t.Error("scanProjectFn called unexpectedly")
		return ossbom.New(ossbom.Environment{}), nil
	}
	t.Cleanup(func() { execFn, checkFn, scanProjectFn = oe, oc, os })
}

// swapScan replaces the project-scan seam for tests that exercise the bare /
// manifest-install path.
func swapScan(t *testing.T, fn func(context.Context, string, string, string) (*ossbom.SBOM, error)) {
	t.Helper()
	old := scanProjectFn
	scanProjectFn = fn
	t.Cleanup(func() { scanProjectFn = old })
}

func cleanSBOM(_ context.Context, _ check.Options) (*ossbom.SBOM, error) {
	return ossbom.New(ossbom.Environment{}), nil
}

func malwareSBOM(_ context.Context, opts check.Options) (*ossbom.SBOM, error) {
	s := ossbom.New(ossbom.Environment{})
	s.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:npm/evil@1.0.0", "bad"))
	return s, nil
}

func TestRun_NonInstall_ForwardsWithoutCheck(t *testing.T) {
	ex := &stubExec{}
	checkCalled := false
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		checkCalled = true
		return cleanSBOM(ctx, o)
	})

	err := Run(context.Background(), Options{Bin: "npm", Args: []string{"run", "build"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if checkCalled {
		t.Error("check should not run for non-install command")
	}
	if !ex.called || ex.bin != "npm" || !reflect.DeepEqual(ex.args, []string{"run", "build"}) {
		t.Errorf("exec: called=%v bin=%q args=%v", ex.called, ex.bin, ex.args)
	}
}

// OSS-1284: a bare `ossprey npm install` (no named packages) must NOT fall
// through unchecked — it should scan the project's manifest/lockfile.
func TestRun_BareInstall_ScansProjectManifest(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	var scanCalled bool
	var scanDir string
	swapScan(t, func(_ context.Context, dir, _, _ string) (*ossbom.SBOM, error) {
		scanCalled, scanDir = true, dir
		return ossbom.New(ossbom.Environment{}), nil
	})

	err := Run(context.Background(), Options{Bin: "npm", Args: []string{"install"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !scanCalled {
		t.Error("bare `npm install` must scan the project manifest, not fall through unchecked")
	}
	if scanDir != "." {
		t.Errorf("scan dir = %q, want \".\"", scanDir)
	}
	if !ex.called || !reflect.DeepEqual(ex.args, []string{"install"}) {
		t.Errorf("clean scan must forward original args; got called=%v args=%v", ex.called, ex.args)
	}
}

func TestRun_BareInstall_MalwareInManifestBlocks(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	swapScan(t, func(_ context.Context, _, _, _ string) (*ossbom.SBOM, error) {
		s := ossbom.New(ossbom.Environment{})
		s.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:npm/evil@1.0.0", "bad"))
		return s, nil
	})

	err := Run(context.Background(), Options{Bin: "npm", Args: []string{"install"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err: got %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("exec must NOT be called when the manifest scan finds malware")
	}
}

func TestRun_RequirementsFile_ScansProject(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)
	var scanCalled bool
	swapScan(t, func(_ context.Context, _, _, _ string) (*ossbom.SBOM, error) {
		scanCalled = true
		return ossbom.New(ossbom.Environment{}), nil
	})

	err := Run(context.Background(), Options{Bin: "pip", Args: []string{"install", "-r", "requirements.txt"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !scanCalled {
		t.Error("`pip install -r requirements.txt` must scan the project, not fall through")
	}
	if !ex.called {
		t.Error("clean scan must forward to pip")
	}
}

func TestRun_NamedPackages_DoNotScanProject(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM) // swap's scanProjectFn fails the test if called
	err := Run(context.Background(), Options{Bin: "npm", Args: []string{"install", "lodash@4.17.21"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ex.called {
		t.Error("expected forward after checking named package")
	}
}

func TestRun_OnlyLocalTarget_ForwardsWithoutScan(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM) // scanProjectFn fails the test if called
	err := Run(context.Background(), Options{Bin: "npm", Args: []string{"install", "./local.tgz"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ex.called || !reflect.DeepEqual(ex.args, []string{"install", "./local.tgz"}) {
		t.Errorf("local-only install should forward unchanged; got %v", ex.args)
	}
}

func TestRun_ManifestInstallVerbs_ScanProject(t *testing.T) {
	cases := []struct {
		bin  string
		args []string
	}{
		{"npm", []string{"ci"}},
		{"yarn", []string{"install"}},
		{"poetry", []string{"install"}},
		{"uv", []string{"sync"}},
		{"uv", []string{"pip", "install", "-r", "requirements.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.bin+" "+tc.args[0], func(t *testing.T) {
			ex := &stubExec{}
			swap(t, ex.fn, cleanSBOM)
			var scanCalled bool
			swapScan(t, func(_ context.Context, _, _, _ string) (*ossbom.SBOM, error) {
				scanCalled = true
				return ossbom.New(ossbom.Environment{}), nil
			})
			if err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !scanCalled {
				t.Errorf("`%s %v` must scan the project manifest", tc.bin, tc.args)
			}
			if !ex.called {
				t.Error("clean scan must forward")
			}
		})
	}
}

func TestRun_Clean_Forwards(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, cleanSBOM)

	err := Run(context.Background(), Options{Bin: "pip", Args: []string{"install", "requests==2.31.0"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ex.called {
		t.Error("expected exec to be called on clean result")
	}
}

func TestRun_MultiPackage_ChecksAllAndForwards(t *testing.T) {
	ex := &stubExec{}
	var gotSpecs []check.Spec
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		gotSpecs = o.Specs
		return ossbom.New(ossbom.Environment{}), nil
	})

	args := []string{"install", "lodash@4.17.21", "react@18.2.0", "@babel/core@7.0.0"}
	err := Run(context.Background(), Options{Bin: "npm", Args: args})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []check.Spec{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
		{Ecosystem: "npm", Name: "react", Version: "18.2.0"},
		{Ecosystem: "npm", Name: "@babel/core", Version: "7.0.0"},
	}
	if !reflect.DeepEqual(gotSpecs, want) {
		t.Errorf("checked specs = %+v, want %+v", gotSpecs, want)
	}
	if !ex.called || !reflect.DeepEqual(ex.args, args) {
		t.Errorf("exec args = %v, want %v (called=%v)", ex.args, args, ex.called)
	}
}

func TestRun_MultiPackage_MalwareInAnyBlocks(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, malwareSBOM)

	err := Run(context.Background(), Options{
		Bin:  "npm",
		Args: []string{"install", "lodash@4.17.21", "evil@1.0.0", "react@18.2.0"},
	})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err: got %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("exec must NOT be called when any package is malware")
	}
}

func TestRun_MultiPackage_SkipsNonPackagesChecksRest(t *testing.T) {
	ex := &stubExec{}
	var gotSpecs []check.Spec
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		gotSpecs = o.Specs
		return ossbom.New(ossbom.Environment{}), nil
	})

	args := []string{"install", "requests==2.31.0", "-t", "./vendor", "./local.whl", "flask==3.0.0"}
	err := Run(context.Background(), Options{Bin: "pip", Args: args})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []check.Spec{
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
		{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"},
	}
	if !reflect.DeepEqual(gotSpecs, want) {
		t.Errorf("checked specs = %+v, want %+v", gotSpecs, want)
	}
	if !ex.called || !reflect.DeepEqual(ex.args, args) {
		t.Errorf("exec must forward original args unchanged; got %v", ex.args)
	}
}

func TestRun_Malware_Blocks(t *testing.T) {
	ex := &stubExec{}
	swap(t, ex.fn, malwareSBOM)

	err := Run(context.Background(), Options{Bin: "npm", Args: []string{"install", "evil@1.0.0"}})
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err: got %v, want ErrBlocked", err)
	}
	if ex.called {
		t.Error("exec must NOT be called when malware is found")
	}
}

func TestRun_ResolvesLatest(t *testing.T) {
	ex := &stubExec{}
	var gotVersion string
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		gotVersion = o.Specs[0].Version
		return ossbom.New(ossbom.Environment{}), nil
	})

	err := Run(context.Background(), Options{
		Bin:           "npm",
		Args:          []string{"install", "lodash"},
		ResolveLatest: func(_ context.Context, _, _ string) (string, error) { return "9.9.9", nil },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotVersion != "9.9.9" {
		t.Errorf("resolved version: got %q, want 9.9.9", gotVersion)
	}
}

func TestRun_ResolveFailsOpen(t *testing.T) {
	ex := &stubExec{}
	checkCalled := false
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		checkCalled = true
		return cleanSBOM(ctx, o)
	})

	err := Run(context.Background(), Options{
		Bin:           "npm",
		Args:          []string{"install", "lodash"},
		ResolveLatest: func(_ context.Context, _, _ string) (string, error) { return "", errors.New("registry down") },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if checkCalled {
		t.Error("check should be skipped when all specs fail to resolve")
	}
	if !ex.called {
		t.Error("install should still be forwarded (fail open)")
	}
}
