package forward

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/trust"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

func acmePolicy(t *testing.T) trust.Policy {
	t.Helper()
	p, err := trust.Parse([]string{"https://npm.internal.example/repo/"}, []string{"@acme"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func captureErrOut(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := errOut
	errOut = &buf
	t.Cleanup(func() { errOut = old })
	return &buf
}

// A trusted scope is dropped before version resolution, so the private
// package is never looked up on — or sent to — anything public.
func TestRun_TrustedScopeIsNotCheckedOrResolved(t *testing.T) {
	out := captureErrOut(t)
	ex := &stubExec{}
	var checked []check.Spec
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		checked = o.Specs
		return cleanSBOM(ctx, o)
	})
	var resolved []string
	resolve := func(_ context.Context, _, name string) (string, error) {
		resolved = append(resolved, name)
		return "1.0.0", nil
	}

	ctx := warn.NewContext(context.Background(), false)
	err := Run(ctx, Options{
		Bin: "npm", Args: []string{"install", "@acme/web", "left-pad"},
		ResolveLatest: resolve, Trust: acmePolicy(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked) != 1 || checked[0].Name != "left-pad" {
		t.Errorf("checked %v, want only left-pad", checked)
	}
	if !reflect.DeepEqual(resolved, []string{"left-pad"}) {
		t.Errorf("resolved %v, want only left-pad", resolved)
	}
	if !ex.called {
		t.Error("install was not forwarded")
	}
	if !strings.Contains(out.String(), "@acme/web (npm) is from a trusted source") {
		t.Errorf("trusted package not reported:\n%s", out)
	}
}

// With every named package trusted, the empty spec list must not be read as a
// bare install — that would scan the whole project instead.
func TestRun_AllNamedPackagesTrustedForwardsWithoutAScan(t *testing.T) {
	out := captureErrOut(t)
	ex := &stubExec{}
	swap(t, ex.fn, func(context.Context, check.Options) (*ossbom.SBOM, error) {
		t.Error("check ran for an all-trusted install")
		return nil, nil
	}) // swap's scanProjectFn fails the test if reached

	err := Run(context.Background(), Options{
		Bin: "pnpm", Args: []string{"add", "@acme/web", "@ACME/tools@1.2.0"}, Trust: acmePolicy(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ex.called {
		t.Error("install was not forwarded")
	}
	if !strings.Contains(out.String(), "every package named is from a trusted source") {
		t.Errorf("missing forward notice:\n%s", out)
	}
}

// The registry rule cannot apply to a named install: where a package not yet
// installed will come from is not recorded anywhere. A pypi name matching
// nothing but a registry is checked as before.
func TestRun_NamedInstallIgnoresRegistryRule(t *testing.T) {
	ex := &stubExec{}
	var checked []check.Spec
	swap(t, ex.fn, func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		checked = o.Specs
		return cleanSBOM(ctx, o)
	})
	err := Run(context.Background(), Options{
		Bin: "pip", Args: []string{"install", "acme-core==1.0.0"}, Trust: acmePolicy(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked) != 1 || checked[0].Name != "acme-core" {
		t.Errorf("checked %v, want acme-core", checked)
	}
}

// Project scans apply the whole policy, so every route to one must carry it.
func TestRun_ProjectScansCarryThePolicy(t *testing.T) {
	policy := acmePolicy(t)
	for _, tc := range []struct {
		name    string
		bin     string
		args    []string
		passive bool
	}{
		{"blocking bare install", "npm", []string{"install"}, false},
		{"passive after install", "npm", []string{"install"}, true},
		{"passive manifest alongside", "pip", []string{"install", "-r", "requirements.txt"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captureErrOut(t)
			ex := &stubExec{}
			swap(t, ex.fn, cleanSBOM)
			var got trust.Policy
			swapScan(t, func(_ context.Context, req scanRequest) (*ossbom.SBOM, error) {
				got = req.Trust
				return ossbom.New(ossbom.Environment{}), nil
			})
			if err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args, Passive: tc.passive, Trust: policy}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, policy) {
				t.Errorf("scan request trust = %+v, want %+v", got, policy)
			}
		})
	}
}
