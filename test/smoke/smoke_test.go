//go:build smoke

// Package smoke contains end-to-end CLI smoke tests. Builds the ossprey binary
// once via TestMain and exercises it as a subprocess against static fixtures —
// mirrors the v1 pytest smoke suite at ../../../ossprey-python-client/test/smoke/.
//
// Run with: go test -tags smoke ./test/smoke/...
// Skip slow/network tests: go test -tags smoke -short ./test/smoke/...
package smoke

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "ossprey-smoke-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdtemp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	binPath = filepath.Join(tmp, "ossprey")
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	build := exec.Command("go", "build", "-o", binPath, "./cmd/ossprey")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", err, out)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func fixturesDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "test_packages")
}

type runResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func runOssprey(t *testing.T, pkgDir string, args ...string) runResult {
	t.Helper()
	full := append([]string{"scan", pkgDir, "--dry-run-safe"}, args...)
	cmd := exec.Command(binPath, full...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run ossprey: %v\nstderr: %s", err, stderr.String())
		}
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

type sbom struct {
	Components      []map[string]any `json:"components"`
	Vulnerabilities []map[string]any `json:"vulnerabilities"`
}

func readSBOM(t *testing.T, path string) sbom {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var s sbom
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	return s
}

func componentNames(s sbom) []string {
	out := make([]string, 0, len(s.Components))
	for _, c := range s.Components {
		if name, ok := c["name"].(string); ok {
			out = append(out, strings.ToLower(name))
		}
	}
	return out
}

func assertHas(t *testing.T, names []string, want string) {
	t.Helper()
	for _, n := range names {
		if n == want {
			return
		}
	}
	t.Errorf("missing %q in components: %v", want, names)
}

func assertContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected %q in output, got: %s", needle, haystack)
	}
}

// 1. Existing test_packages — scan each, expect clean SBOM.
func TestExistingPackages(t *testing.T) {
	cases := []struct {
		name          string
		minComponents int
	}{
		{"python_simple_math", 2},
		{"poetry_simple_math", 6},
		{"poetry_broken_simple_math", 1},
		{"npm_simple_math", 300},
		{"yarn_simple_math", 300},
		{"yarn_massive_math", 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgDir := filepath.Join(fixturesDir(t), tc.name)
			sbomFile := filepath.Join(t.TempDir(), "sbom.json")
			res := runOssprey(t, pkgDir, "-o", sbomFile)
			if res.exitCode != 0 {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
			}
			assertContains(t, res.stdout, "No malware found")
			s := readSBOM(t, sbomFile)
			if len(s.Components) < tc.minComponents {
				t.Errorf("components: got %d, want >= %d", len(s.Components), tc.minComponents)
			}
		})
	}
}

// 2. Packaging-format coverage — one fixture per ecosystem.
func TestPackagingVariants(t *testing.T) {
	cases := []struct {
		name          string
		minComponents int
	}{
		{"uv_simple_math", 2},
		{"hatch_simple_math", 2},
		{"pip_tools_simple_math", 2},
		{"pipfile_simple_math", 2},
		{"npm_no_lock_simple_math", 1},
		{"yarn_berry_simple_math", 2},
		{"pnpm_simple_math", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgDir := filepath.Join(fixturesDir(t), tc.name)
			if _, err := os.Stat(pkgDir); err != nil {
				t.Fatalf("fixture missing: %v", err)
			}
			sbomFile := filepath.Join(t.TempDir(), "sbom.json")
			res := runOssprey(t, pkgDir, "-o", sbomFile)
			if res.exitCode != 0 {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
			}
			assertContains(t, res.stdout, "No malware found")
			s := readSBOM(t, sbomFile)
			if len(s.Components) < tc.minComponents {
				t.Errorf("components: got %d, want >= %d", len(s.Components), tc.minComponents)
			}
		})
	}
}

// 3. Dry-run malicious — injects a fake vuln and exits 1.
func TestDryRunMalicious(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	sbomFile := filepath.Join(t.TempDir(), "sbom.json")

	cmd := exec.Command(binPath, "scan", pkgDir, "--dry-run-malicious", "-o", sbomFile)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected non-zero exit, got 0\nstdout: %s", stdout.String())
	}
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 {
		t.Fatalf("expected exit 1, got %v\nstderr: %s", err, stderr.String())
	}
	lower := strings.ToLower(stdout.String())
	if !strings.Contains(lower, "malware") && !strings.Contains(lower, "warning") {
		t.Errorf("expected malware/warning in stdout, got: %s", stdout.String())
	}
	s := readSBOM(t, sbomFile)
	if len(s.Vulnerabilities) < 1 {
		t.Errorf("expected >= 1 vulnerability, got %d", len(s.Vulnerabilities))
	}
}

// 4. Static fixtures for each Python build system + real package — verify
// the CLI surfaces the named dep. No network: fixtures written by hand, no
// resolver invoked.
//
// Mirrors v1 _params(PY_BUILDERS, PY_PACKAGES). Static-only: skipped builders
// (poetry, uv, hatch, pipenv) require the resolver/installer to populate the
// lock; v2 parses static manifests + lockfiles only.

type builderFn func(dir, name, version string) error

func writeFile(dir, rel, content string) error {
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	return os.WriteFile(full, []byte(content), 0o644)
}

func buildPyRequirements(dir, name, version string) error {
	return writeFile(dir, "requirements.txt", fmt.Sprintf("%s==%s\n", name, version))
}

func buildPyPipTools(dir, name, version string) error {
	if err := writeFile(dir, "requirements.in", name+"\n"); err != nil {
		return err
	}
	body := fmt.Sprintf("# autogenerated by pip-compile\n%s==%s\n    # via -r requirements.in\n", name, version)
	return writeFile(dir, "requirements.txt", body)
}

func buildPyPoetry(dir, name, version string) error {
	proj := fmt.Sprintf(`[project]
name = "smoke-poetry-%s"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["%s==%s"]

[build-system]
requires = ["poetry-core>=2.0.0,<3.0.0"]
build-backend = "poetry.core.masonry.api"
`, name, name, version)
	if err := writeFile(dir, "pyproject.toml", proj); err != nil {
		return err
	}
	lock := fmt.Sprintf(`# autogenerated
[[package]]
name = "%s"
version = "%s"
description = ""
optional = false
python-versions = ">=3.8"
`, name, version)
	return writeFile(dir, "poetry.lock", lock)
}

func buildJSNpmLock(dir, name, version string) error {
	pkgJSON := map[string]any{
		"name":         "smoke-npm-" + name,
		"version":      "1.0.0",
		"private":      true,
		"dependencies": map[string]string{name: version},
	}
	pj, _ := json.MarshalIndent(pkgJSON, "", "  ")
	if err := writeFile(dir, "package.json", string(pj)); err != nil {
		return err
	}
	lock := map[string]any{
		"name":            "smoke-npm-" + name,
		"version":         "1.0.0",
		"lockfileVersion": 3,
		"requires":        true,
		"packages": map[string]any{
			"": map[string]any{
				"name":         "smoke-npm-" + name,
				"version":      "1.0.0",
				"dependencies": map[string]string{name: version},
			},
			"node_modules/" + name: map[string]any{"version": version},
		},
	}
	lj, _ := json.MarshalIndent(lock, "", "  ")
	return writeFile(dir, "package-lock.json", string(lj))
}

func buildJSNpmManifest(dir, name, version string) error {
	pkgJSON := map[string]any{
		"name":         "smoke-npm-manifest-" + name,
		"version":      "1.0.0",
		"private":      true,
		"dependencies": map[string]string{name: version},
	}
	pj, _ := json.MarshalIndent(pkgJSON, "", "  ")
	return writeFile(dir, "package.json", string(pj))
}

func buildJSYarnClassic(dir, name, version string) error {
	pkgJSON := map[string]any{
		"name":         "smoke-yarn-" + name,
		"version":      "1.0.0",
		"private":      true,
		"dependencies": map[string]string{name: version},
	}
	pj, _ := json.MarshalIndent(pkgJSON, "", "  ")
	if err := writeFile(dir, "package.json", string(pj)); err != nil {
		return err
	}
	lock := fmt.Sprintf(`# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"%s@%s":
  version "%s"
  resolved "https://registry.yarnpkg.com/%s/-/%s-%s.tgz"
`, name, version, version, name, name, version)
	return writeFile(dir, "yarn.lock", lock)
}

func TestPythonBuildSystems(t *testing.T) {
	builders := []struct {
		id string
		fn builderFn
	}{
		{"py-requirements", buildPyRequirements},
		{"py-pip-tools", buildPyPipTools},
		{"py-poetry", buildPyPoetry},
	}
	packages := []struct {
		name, version string
	}{
		{"flask", "3.0.0"},
		{"django", "5.0"},
		{"requests", "2.31.0"},
		{"numpy", "1.26.3"},
		{"click", "8.1.7"},
	}
	for _, b := range builders {
		for _, p := range packages {
			t.Run(b.id+"-"+p.name, func(t *testing.T) {
				dir := t.TempDir()
				if err := b.fn(dir, p.name, p.version); err != nil {
					t.Fatalf("build fixture: %v", err)
				}
				sbomFile := filepath.Join(t.TempDir(), "sbom.json")
				res := runOssprey(t, dir, "-o", sbomFile)
				if res.exitCode != 0 {
					t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
				}
				assertContains(t, res.stdout, "No malware found")
				s := readSBOM(t, sbomFile)
				assertHas(t, componentNames(s), p.name)
			})
		}
	}
}

func TestJSBuildSystems(t *testing.T) {
	builders := []struct {
		id string
		fn builderFn
	}{
		{"js-npm-lock", buildJSNpmLock},
		{"js-npm-manifest", buildJSNpmManifest},
		{"js-yarn-classic", buildJSYarnClassic},
	}
	packages := []struct {
		name, version string
	}{
		{"express", "4.18.2"},
		{"react", "18.2.0"},
		{"axios", "1.6.5"},
		{"lodash", "4.17.21"},
	}
	for _, b := range builders {
		for _, p := range packages {
			t.Run(b.id+"-"+p.name, func(t *testing.T) {
				dir := t.TempDir()
				if err := b.fn(dir, p.name, p.version); err != nil {
					t.Fatalf("build fixture: %v", err)
				}
				sbomFile := filepath.Join(t.TempDir(), "sbom.json")
				res := runOssprey(t, dir, "-o", sbomFile)
				if res.exitCode != 0 {
					t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
				}
				assertContains(t, res.stdout, "No malware found")
				s := readSBOM(t, sbomFile)
				assertHas(t, componentNames(s), p.name)
			})
		}
	}
}

// 5. GitHub clone — slow + network. Skipped under -short.
func TestGitHubRepos(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping GitHub clone tests in -short mode")
	}
	cases := []struct {
		url        string
		expectComp string
	}{
		{"https://github.com/pallets/click", "colorama"},
		{"https://github.com/psf/requests", "urllib3"},
	}
	for _, tc := range cases {
		name := tc.url[strings.LastIndex(tc.url, "/")+1:]
		t.Run(name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), name)
			clone := exec.Command("git", "clone", "--depth", "1", tc.url, dest)
			if out, err := clone.CombinedOutput(); err != nil {
				t.Fatalf("git clone: %v\n%s", err, out)
			}
			sbomFile := filepath.Join(t.TempDir(), "sbom.json")
			res := runOssprey(t, dest, "-o", sbomFile)
			if res.exitCode != 0 {
				t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
			}
			assertContains(t, res.stdout, "No malware found")
			s := readSBOM(t, sbomFile)
			assertHas(t, componentNames(s), tc.expectComp)
		})
	}
}
