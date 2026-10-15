package forward

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Each of these installed a package without checking it: the verb was not
// recognised, a flag swallowed or hid the package, or the spec was checked
// under a name or version that is not the one installed.
func TestInstallsThatWentUnchecked(t *testing.T) {
	for _, tc := range []struct {
		bin  string
		args []string
		want []string
	}{
		{"npm", []string{"isntall", "evil"}, []string{"evil"}},
		{"npm", []string{"upgrade", "evil"}, []string{"evil"}},
		{"npm", []string{"it", "evil"}, []string{"evil"}},
		{"npm", []string{"install", "lodash@npm:evil"}, []string{"evil"}},
		{"npm", []string{"install", "--before", "2020-01-01", "evil"}, []string{"evil"}},
		{"pnpm", []string{"upgrade", "evil"}, []string{"evil"}},
		{"pnpm", []string{"it"}, nil},
		{"yarn", nil, nil},
		{"yarn", []string{"--frozen-lockfile"}, nil},
		{"yarn", []string{"--cwd", "web"}, nil},
		{"yarn", []string{"workspace", "web", "add", "evil"}, []string{"evil"}},
		{"yarn", []string{"global", "add", "evil"}, []string{"evil"}},
		{"pip", []string{"install", "evil[x]"}, []string{"evil"}},
		{"pip", []string{"install", "--trusted-host", "h.example", "evil"}, []string{"evil"}},
		{"pip", []string{"--trusted-host", "h.example", "install", "evil"}, []string{"evil"}},
		{"poetry", []string{"add", "--platform", "linux", "evil@^7.0"}, []string{"evil"}},
		{"uv", []string{"add", "--editable", "evil"}, []string{"evil"}},
		{"uv", []string{"tool", "install", "-e", "evil"}, []string{"evil"}},
		{"uv", []string{"tool", "install", "--from", "x", "y", "-w", "evil"}, []string{"x", "evil"}},
		{"uv", []string{"tool", "install", "ruff", "--with-executables-from", "evil"}, []string{"evil", "ruff"}},
		{"uv", []string{"tool", "install", "ruff", "--with", "ok,evil>=1,<2"}, []string{"ok", "evil", "ruff"}},
		{"uv", []string{"add", "--script", "s.py", "evil"}, []string{"evil"}},
		{"uv", []string{"pip", "install", "--constraints", "c.txt", "evil"}, []string{"evil"}},
	} {
		got, ok := specNames(t, tc.bin, tc.args)
		if !ok {
			t.Errorf("%s %v: not treated as an install", tc.bin, tc.args)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s %v: checks %q, want %q", tc.bin, tc.args, got, tc.want)
		}
	}
	for _, tc := range []struct {
		bin  string
		args []string
	}{
		{"yarn", []string{"--version"}},
		{"yarn", []string{"-h"}},
		{"yarn", []string{"workspace", "web"}},
		{"yarn", []string{"workspace", "web", "build"}},
		{"yarn", []string{"global", "list"}},
	} {
		if _, ok := specNames(t, tc.bin, tc.args); ok {
			t.Errorf("%s %v: treated as an install", tc.bin, tc.args)
		}
	}
}

// `--requirements` is uv's spelling of -r; unlisted, the file read as a package
// and the install was not a manifest install at all.
func TestUVRequirementsLongFlagIsARequirementsFile(t *testing.T) {
	for _, args := range [][]string{
		{"pip", "install", "--requirements", "r.txt"},
		{"pip", "install", "--requirements=r.txt"},
		{"add", "--requirements", "r.txt"},
	} {
		m := managers["uv"]
		start, ok := m.installAt(args)
		if !ok {
			t.Fatalf("uv %v: not an install", args)
		}
		p := ParseSpecs(m, args[start:])
		if len(p.Specs) != 0 || !slices.Equal(p.ReqFiles, []string{"r.txt"}) || !manifestInstall(p) {
			t.Errorf("uv %v: parsed %+v, want a manifest install of r.txt", args, p)
		}
	}
}

// `yarn global add` installs outside the project, so passive mode must not
// read the project's lockfile in its place.
func TestYarnGlobalWritesNoLocalLockfile(t *testing.T) {
	if writesLocalLockfile(managers["yarn"], []string{"global", "add", "x"}) {
		t.Error("yarn global add: expected no local lockfile")
	}
	if !writesLocalLockfile(managers["yarn"], []string{"workspace", "web", "add", "x"}) {
		t.Error("yarn workspace add: expected the local lockfile")
	}
}

// `pip install -r req.txt flask` installs both. Checking only flask left the
// file's packages unchecked; now the project scan and the named package go in
// one submission, and malware in either blocks.
func TestRun_RequirementsFilePlusNamedPackagesChecksBoth(t *testing.T) {
	for _, tc := range []struct {
		bin  string
		args []string
	}{
		{"pip", []string{"install", "-r", "req.txt", "flask"}},
		{"uv", []string{"pip", "install", "-r", "req.txt", "flask"}},
	} {
		ex := &stubExec{}
		swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
			t.Error("checkFn called: the requirements file would go unchecked")
			return ossbom.New(ossbom.Environment{}), nil
		})
		var got scanRequest
		swapScan(t, func(_ context.Context, req scanRequest) (*ossbom.SBOM, error) {
			got = req
			s := ossbom.New(ossbom.Environment{})
			s.AddVulnerability(ossbom.NewMalwareVulnerability("V1", "pkg:pypi/evil@1.0.0", "bad"))
			return s, nil
		})
		pin := func(context.Context, string, string) (string, error) { return "3.0.0", nil }
		err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args, ResolveLatest: pin})
		if err != ErrBlocked {
			t.Errorf("%s %v: err = %v, want ErrBlocked", tc.bin, tc.args, err)
		}
		if ex.called {
			t.Errorf("%s %v: the manager ran despite malware in the requirements file", tc.bin, tc.args)
		}
		want := []check.Spec{{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"}}
		if got.Dir != "." || !reflect.DeepEqual(got.Specs, want) {
			t.Errorf("%s %v: scan request %+v, want dir . with specs %+v", tc.bin, tc.args, got, want)
		}
	}
}

// A range or tag is resolved from what was asked for, not sent as a version
// and not replaced by latest.
func TestRun_RangeIsResolvedWithItsConstraint(t *testing.T) {
	ex := &stubExec{}
	var checked []check.Spec
	swap(t, ex.fn, func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		checked = o.Specs
		return ossbom.New(ossbom.Environment{}), nil
	})
	var asked []string
	resolve := func(_ context.Context, eco, name, constraint string) (string, error) {
		asked = append(asked, name+"|"+constraint)
		return "4.17.21", nil
	}
	args := []string{"install", "lodash@^4.17.0", "alias@npm:evil@next", "left-pad@1.3.0"}
	if err := Run(context.Background(), Options{Bin: "npm", Args: args, Resolve: resolve}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := []string{"lodash|^4.17.0", "evil|next"}; !slices.Equal(asked, want) {
		t.Errorf("resolved %q, want %q", asked, want)
	}
	want := []check.Spec{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
		{Ecosystem: "npm", Name: "evil", Version: "4.17.21"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
	}
	if !reflect.DeepEqual(checked, want) {
		t.Errorf("checked %+v, want %+v", checked, want)
	}
}
