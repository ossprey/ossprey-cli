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
		{"yarn", []string{"install"}, 0, false},
		{"pip", []string{"install", "requests"}, 1, true},
		{"pip", []string{"list"}, 0, false},
		{"poetry", []string{"add", "flask"}, 1, true},
		{"uv", []string{"add", "httpx"}, 1, true},
		{"uv", []string{"pip", "install", "httpx"}, 2, true},
		{"uv", []string{"pip", "list"}, 0, false},
		{"uv", []string{"sync"}, 0, false},
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

	tests := []struct {
		name string
		m    *Manager
		args []string
		want []check.Spec
	}{
		{
			name: "npm mixed with flags",
			m:    npm,
			args: []string{"lodash@4.17.21", "--save-dev", "@babel/core@7.0.0", "react"},
			want: []check.Spec{
				{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
				{Ecosystem: "npm", Name: "@babel/core", Version: "7.0.0"},
				{Ecosystem: "npm", Name: "react", Version: ""},
			},
		},
		{
			name: "pip with == and bare",
			m:    pip,
			args: []string{"requests==2.31.0", "flask"},
			want: []check.Spec{
				{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
				{Ecosystem: "pypi", Name: "flask", Version: ""},
			},
		},
		{
			name: "all flags -> none",
			m:    pip,
			args: []string{"-U", "--quiet"},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSpecs(tt.m, tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSpecs = %+v, want %+v", got, tt.want)
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

// swap replaces the package test seams and returns a restore func.
func swap(t *testing.T, exec func(context.Context, string, []string) error, chk func(context.Context, check.Options) (*ossbom.SBOM, error)) {
	t.Helper()
	oe, oc := execFn, checkFn
	execFn, checkFn = exec, chk
	t.Cleanup(func() { execFn, checkFn = oe, oc })
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
