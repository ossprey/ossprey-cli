//go:build smoke

// End-to-end coverage for the forwarders other than pnpm, against the real
// managers and a fake API: a flagged package blocks with exit 1 before the
// manager runs, and a manager's own exit code comes back unchanged.
//
// Run with: go test -tags smoke -run TestForwardGaps -v ./test/smoke/...

package smoke

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func needBin(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed", name)
	}
}

func dirEmpty(t *testing.T, dir string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(entries) == 0
}

// Every block happens before the manager starts, so none of these touch a
// registry: the package is pinned and the fake API flags it.
func TestForwardGapsBlockBeforeTheManagerRuns(t *testing.T) {
	const npmPurl, pypiPurl = "pkg:npm/left-pad@1.3.0", "pkg:pypi/six@1.16.0"
	for _, tc := range []struct {
		name, need, purl string
		args             []string
		// setup writes the project and returns where an install would land.
		setup func(t *testing.T, dir string) string
	}{
		{"npm install", "npm", npmPurl, []string{"npm", "install", "left-pad@1.3.0"}, jsProject},
		{"npm global flag before verb", "npm", npmPurl, []string{"npm", "--loglevel", "silent", "install", "-D", "left-pad@1.3.0"}, jsProject},
		{"yarn add", "yarn", npmPurl, []string{"yarn", "add", "-D", "left-pad@1.3.0"}, jsProject},
		{"bun add", "bun", npmPurl, []string{"bun", "add", "--dev", "left-pad@1.3.0"}, jsProject},
		{"npx", "npx", npmPurl, []string{"npx", "left-pad@1.3.0"}, jsProject},
		{"pip install", "pip", pypiPurl, []string{"pip", "install", "--target", "site", "six==1.16.0"}, pyTarget},
		{"pip3 install", "pip3", pypiPurl, []string{"pip3", "--isolated", "install", "--target", "site", "six==1.16.0"}, pyTarget},
		{"uv pip install", "uv", pypiPurl, []string{"uv", "pip", "install", "--target", "site", "six==1.16.0"}, pyTarget},
		{"uv add", "uv", pypiPurl, []string{"uv", "add", "--dev", "six==1.16.0"}, pyProject},
		{"uvx", "uvx", pypiPurl, []string{"uvx", "--from", "six==1.16.0", "python"}, pyTarget},
		{"poetry add", "poetry", pypiPurl, []string{"poetry", "add", "--group", "dev", "six==1.16.0"}, pyProject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			needBin(t, tc.need)
			api := newFakeAPI(t, tc.purl)
			dir := t.TempDir()
			landing := tc.setup(t, dir)

			res := runForward(t, dir, api.URL, tc.args...)
			if res.exitCode != 1 {
				t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
			}
			if !strings.Contains(res.stderr, "contains malware") ||
				!strings.Contains(res.stderr, "ossprey: blocked `"+strings.Join(tc.args, " ")+"`") {
				t.Errorf("missing malware report or block line:\n%s", res.stderr)
			}
			if _, purls := api.stats(); !slices.Contains(purls, tc.purl) {
				t.Errorf("submitted %v, want %s", purls, tc.purl)
			}
			if landing != "" && !dirEmpty(t, filepath.Join(dir, landing)) {
				t.Errorf("the manager ran despite the block: %s is not empty", landing)
			}
			if b, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")); err == nil && strings.Contains(string(b), "six") {
				t.Errorf("the manager ran despite the block: pyproject.toml now names six:\n%s", b)
			}
		})
	}
}

func jsProject(t *testing.T, dir string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"gaps-smoke","version":"1.0.0","private":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return "node_modules"
}

func pyTarget(t *testing.T, dir string) string {
	t.Helper()
	return "site"
}

func pyProject(t *testing.T, dir string) string {
	t.Helper()
	toml := "[project]\nname = \"gaps-smoke\"\nversion = \"0.1.0\"\nrequires-python = \">=3.8\"\ndependencies = []\n"
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	return ""
}

// A non-install reaches the real manager untouched, costs no API call, and its
// exit code (not 1, not 2) is the forwarder's.
func TestForwardGapsExitCodePassesThroughExactly(t *testing.T) {
	needBin(t, "npm")
	api := newFakeAPI(t, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"gaps-smoke","version":"1.0.0","private":true,"scripts":{"fail":"exit 7"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runForward(t, dir, api.URL, "npm", "run", "fail")
	if res.exitCode != 7 {
		t.Errorf("exit %d, want npm's own 7\nstderr: %s", res.exitCode, res.stderr)
	}
	if reqs, _ := api.stats(); reqs != 0 {
		t.Errorf("`npm run` made %d API calls, want 0", reqs)
	}
}
