//go:build smoke

package smoke

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runScanEnv runs `ossprey scan` with extra environment and no dry-run flag
// implied, so callers choose --local or --dry-run-safe themselves.
func runScanEnv(t *testing.T, env []string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binPath, append([]string{"scan"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run ossprey: %v\nstderr: %s", err, stderr.String())
		}
		code = ee.ExitCode()
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

// componentIDs returns name@version for every component in an SBOM file.
func componentIDs(t *testing.T, path string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, c := range readSBOM(t, path).Components {
		name, _ := c["name"].(string)
		version, _ := c["version"].(string)
		out[strings.ToLower(name)+"@"+version] = true
	}
	return out
}

// Lockfile formats docs/ecosystems.md lists that no test_packages fixture
// carries. Lockfile only, so no resolver runs and nothing touches the network.
func TestScanLockfilesWithoutFixtures(t *testing.T) {
	cases := []struct {
		name, file, body string
		want             []string
	}{
		{"uv.lock", "uv.lock", "version = 1\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
			[]string{"requests@2.31.0"}},
		{"pdm.lock", "pdm.lock", "[metadata]\ngroups = [\"default\"]\nlock_version = \"4.4\"\ncontent_hash = \"sha256:x\"\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nrequires_python = \">=3.7\"\nsummary = \"x\"\nfiles = []\n",
			[]string{"requests@2.31.0"}},
		{"package-lock v1", "package-lock.json", `{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`,
			[]string{"left-pad@1.3.0"}},
		{"pnpm-lock v9", "pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n",
			[]string{"left-pad@1.3.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := writeFile(dir, tc.file, tc.body); err != nil {
				t.Fatal(err)
			}
			sbomFile := filepath.Join(t.TempDir(), "sbom.json")
			res := runScanEnv(t, nil, dir, "--dry-run-safe", "--no-version-lookup", "-o", sbomFile)
			if res.exitCode != 0 {
				t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
			}
			got := componentIDs(t, sbomFile)
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing %s in %v", w, got)
				}
			}
		})
	}
}

const trustLock = `{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},
"node_modules/@acme/web":{"version":"2.0.0","resolved":"https://registry.npmjs.org/@acme/web/-/web-2.0.0.tgz"},
"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`

// Trust is machine-level only: a trust.json committed to the scanned repo must
// not exempt its own packages, or a pull request could hide its dependencies.
func TestScanTrustIsNeverReadFromTheRepo(t *testing.T) {
	repo := t.TempDir()
	policy := `{"registries":["https://registry.npmjs.org/"],"npm_scopes":["@acme"]}`
	for rel, body := range map[string]string{
		"package-lock.json":   trustLock,
		"trust.json":          policy,
		".ossprey/trust.json": policy,
	} {
		if err := writeFile(repo, rel, body); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{
		"OSSPREY_CONFIG_DIR=" + t.TempDir(),
		"OSSPREY_TRUSTED_REGISTRIES=",
		"OSSPREY_TRUSTED_NPM_SCOPES=",
	}
	cmd := exec.Command(binPath, "scan", ".", "--local", "--no-version-lookup")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("scan --local: %v", err)
	}
	if !strings.Contains(string(out), "@acme/web") || !strings.Contains(string(out), "left-pad") {
		t.Errorf("a repo-committed trust.json exempted packages:\n%s", out)
	}

	// Positive control: the same scope from the environment is honoured, and
	// the drop is announced on stderr, never on --local's stdout.
	res := runScanEnv(t, []string{"OSSPREY_CONFIG_DIR=" + t.TempDir(), "OSSPREY_TRUSTED_NPM_SCOPES=@acme"},
		repo, "--local", "--no-version-lookup")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	if strings.Contains(res.stdout, "@acme/web") {
		t.Errorf("trusted package still in the SBOM:\n%s", res.stdout)
	}
	if !strings.Contains(res.stderr, "trusted source") {
		t.Errorf("trusted drop not announced on stderr:\n%s", res.stderr)
	}
}

// --timeout never turns a deadline into a failure: exit 0, the SBOM file is
// still written, and stderr says the deadline was hit.
func TestScanTimeoutKeepsExitCodeAndWritesSBOM(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "npm_simple_math")
	sbomFile := filepath.Join(t.TempDir(), "sbom.json")
	res := runScanEnv(t, nil, pkgDir, "--dry-run-safe", "--timeout", "1ns", "-o", sbomFile)
	if res.exitCode != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", res.exitCode, res.stderr)
	}
	assertContains(t, res.stderr, "scan deadline")
	readSBOM(t, sbomFile) // valid JSON, possibly empty
}

// An empty project is a clean scan with zero components, not an error.
func TestScanEmptyProject(t *testing.T) {
	dir := t.TempDir()
	reportFile := filepath.Join(t.TempDir(), "report.json")
	res := runScanEnv(t, nil, dir, "--dry-run-safe", "--report", reportFile)
	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
	}
	assertContains(t, res.stdout, "No malware found")
	r := readReport(t, reportFile)
	if r.Verdict != "clean" || r.Components != 0 {
		t.Errorf("report = %+v, want clean with 0 components", r)
	}
}
