//go:build smoke

package smoke

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// A named install is checked with the dependencies it brings in, not the
// named package alone (OSS-2481). is-odd depends on is-number, so a check that
// resolved the tree submits both, and a malicious is-number blocks an install
// that never named it.

func npmBin(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm not installed; skipping the npm forwarder end-to-end test")
	}
}

func TestNamedNpmInstallChecksItsDependencies(t *testing.T) {
	npmBin(t)
	api := newFakeAPI(t, "")
	dir := pnpmProject(t, nil)

	res := runForwardVerbose(t, dir, api.URL, "npm", "install", "--no-audit", "--no-fund", "is-odd@3.0.1")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	_, purls := api.stats()
	for _, want := range []string{"pkg:npm/is-odd@3.0.1", "pkg:npm/is-number@6.0.0"} {
		if !slices.Contains(purls, want) {
			t.Errorf("%s was not checked; purls submitted: %v", want, purls)
		}
	}
	if !strings.Contains(res.stderr, "(1 requested + 1 dependencies)") {
		t.Errorf("verbose verdict does not say what was covered:\n%s", res.stderr)
	}
	if !installed(dir, "is-odd") {
		t.Error("npm did not install is-odd — the forward to the real npm failed")
	}
}

func TestNamedNpmInstallBlocksOnAMaliciousDependency(t *testing.T) {
	npmBin(t)
	api := newFakeAPI(t, "pkg:npm/is-number@6.0.0")
	dir := pnpmProject(t, nil)

	res := runForward(t, dir, api.URL, "npm", "install", "--no-audit", "--no-fund", "is-odd@3.0.1")
	if res.exitCode != 1 {
		t.Fatalf("exit %d, want 1 (blocked)\nstderr: %s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "is-number:6.0.0 contains malware") {
		t.Errorf("block does not name the dependency:\n%s", res.stderr)
	}
	if installed(dir, "is-odd") {
		t.Error("blocked install still created node_modules")
	}
}

// pip's dry run (or uv, where the host has one) resolves what `pip install`
// brings in. The forwarded pip is itself run with --dry-run so the test
// installs nothing into the host's Python.
func TestNamedPipInstallChecksItsDependencies(t *testing.T) {
	if _, err := exec.LookPath("pip"); err != nil {
		t.Skip("pip not installed; skipping the pip forwarder end-to-end test")
	}
	api := newFakeAPI(t, "")
	dir := t.TempDir()

	res := runForwardVerbose(t, dir, api.URL, "pip", "install", "--dry-run", "requests==2.32.3")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	_, purls := api.stats()
	if !slices.Contains(purls, "pkg:pypi/requests@2.32.3") {
		t.Errorf("requests was not checked; purls submitted: %v", purls)
	}
	var deps []string
	for _, p := range purls {
		if strings.HasPrefix(p, "pkg:pypi/urllib3@") || strings.HasPrefix(p, "pkg:pypi/certifi@") {
			deps = append(deps, p)
		}
	}
	if len(deps) != 2 {
		t.Errorf("requests' dependencies were not checked; purls submitted: %v", purls)
	}
}
