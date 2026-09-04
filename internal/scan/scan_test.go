package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/severity"
)

// fixture returns the absolute path to a test/test_packages/<name> directory.
func fixture(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = <repo>/internal/scan/scan_test.go → repo root is 2 levels up.
	repo := filepath.Join(filepath.Dir(thisFile), "..", "..")
	return filepath.Join(repo, "test", "test_packages", name)
}

// componentNames returns sorted lowercase names of components in the SBOM.
func componentNames(sbom *ossbom.SBOM) []string {
	names := make([]string, 0, len(sbom.Components))
	for _, c := range sbom.Components {
		names = append(names, strings.ToLower(c.Name))
	}
	return names
}

func TestRun_Fixtures(t *testing.T) {
	tests := []struct {
		name          string
		fixture       string
		minComponents int
		mustContain   []string
	}{
		{
			name:          "python_simple_math",
			fixture:       "python_simple_math",
			minComponents: 2,
			mustContain:   []string{"numpy", "requests"},
		},
		{
			name:          "poetry_simple_math",
			fixture:       "poetry_simple_math",
			minComponents: 6,
			mustContain:   []string{"numpy", "requests", "certifi", "idna", "urllib3"},
		},
		{
			name:          "npm_simple_math",
			fixture:       "npm_simple_math",
			minComponents: 300,
			mustContain:   []string{"axios", "lodash"},
		},
		{
			name:          "yarn_simple_math",
			fixture:       "yarn_simple_math",
			minComponents: 300,
			mustContain:   []string{"axios", "lodash", "jest"},
		},
		{
			name:          "uv_simple_math",
			fixture:       "uv_simple_math",
			minComponents: 2,
			mustContain:   []string{"requests", "click"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noCI(t)
			sbom, err := Run(context.Background(), Options{Path: fixture(t, tt.fixture)})
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}

			if got := len(sbom.Components); got < tt.minComponents {
				t.Errorf("component count: got %d, want >= %d", got, tt.minComponents)
			}

			// Outside CI, Project falls back to the scanned directory's base name.
			if sbom.Env.Project != tt.fixture {
				t.Errorf("env.Project: got %q, want %q", sbom.Env.Project, tt.fixture)
			}
			if sbom.Name != tt.fixture {
				t.Errorf("sbom.Name: got %q, want %q", sbom.Name, tt.fixture)
			}

			names := componentNames(sbom)
			seen := make(map[string]bool, len(names))
			for _, n := range names {
				seen[n] = true
			}
			for _, want := range tt.mustContain {
				if !seen[want] {
					t.Errorf("missing expected component %q (got: %v)", want, names)
				}
			}
		})
	}
}

// TestRun_FlagsLocalPackages is the OSS-1389 end-to-end: internal packages
// wired to local paths in [tool.uv.sources] are catalogued as pypi components
// and flagged metadata.local=true, while a real registry dep is not.
func TestRun_FlagsLocalPackages(t *testing.T) {
	dir := t.TempDir()
	manifest := `[project]
name = "app"
dependencies = ["common", "models", "requests>=2.0"]

[tool.uv.sources]
common = { path = "../common", editable = true }
models = { path = "../models", editable = true }
`
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write pyproject: %v", err)
	}

	sbom, err := Run(context.Background(), Options{Path: dir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	isLocal := func(c ossbom.Component) bool {
		v, ok := c.Metadata["local"].(bool)
		return ok && v
	}
	local := map[string]bool{}
	for _, c := range sbom.Components {
		if isLocal(c) {
			local[strings.ToLower(c.Name)] = true
		}
		if strings.ToLower(c.Name) == "requests" && isLocal(c) {
			t.Error("requests (registry dep) must not be flagged local")
		}
	}
	for _, want := range []string{"common", "models"} {
		if !local[want] {
			t.Errorf("expected %q flagged local; components=%v", want, componentNames(sbom))
		}
	}
}

func TestRun_MissingPath(t *testing.T) {
	_, err := Run(context.Background(), Options{Path: "does-not-exist-fixture"})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
	if !strings.Contains(err.Error(), "scan path") {
		t.Errorf("error message: got %q, want substring %q", err.Error(), "scan path")
	}
}

func TestRun_EmptyDir(t *testing.T) {
	// v2 doesn't error on empty directories — returns an SBOM with no components.
	// (v1 raised NoPackageManagerException; v2 is a thin static cataloguer.)
	dir := t.TempDir()
	sbom, err := Run(context.Background(), Options{Path: dir})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(sbom.Components) != 0 {
		t.Errorf("expected 0 components on empty dir, got %d", len(sbom.Components))
	}
}

func TestInjectTestVulnerability(t *testing.T) {
	tests := []struct {
		name    string
		sbom    func() *ossbom.SBOM
		wantErr error
		wantID  string
		wantIn  string // substring expected in vuln purl
	}{
		{
			name: "with components",
			sbom: func() *ossbom.SBOM {
				s := ossbom.New(ossbom.Environment{})
				s.AddComponent(ossbom.Component{Name: "requests", Version: "2.31.0", Type: "pypi"})
				return s
			},
			wantID: "TEST-2024-0001",
			wantIn: "pkg:pypi/requests@2.31.0",
		},
		{
			name: "no components",
			sbom: func() *ossbom.SBOM {
				return ossbom.New(ossbom.Environment{})
			},
			wantErr: ErrNoComponents,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.sbom()
			err := InjectTestVulnerability(s)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err: got %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if len(s.Vulnerabilities) != 1 {
				t.Fatalf("vuln count: got %d, want 1", len(s.Vulnerabilities))
			}
			v := s.Vulnerabilities[0]
			if v.ID != tt.wantID {
				t.Errorf("id: got %q, want %q", v.ID, tt.wantID)
			}
			if !strings.Contains(v.Purl, tt.wantIn) {
				t.Errorf("purl: got %q, want substring %q", v.Purl, tt.wantIn)
			}
		})
	}
}

func TestMalwareReports(t *testing.T) {
	tests := []struct {
		name        string
		vulns       []ossbom.Vulnerability
		wantHas     bool
		wantNReport int
		wantMatch   string
		wantNInfo   int
		wantInfo    string
	}{
		{
			name:        "no vulnerabilities",
			vulns:       nil,
			wantHas:     false,
			wantNReport: 0,
		},
		{
			name: "one vulnerability",
			vulns: []ossbom.Vulnerability{
				{ID: "X", Purl: "pkg:pypi/requests@2.31.0"},
			},
			wantHas:     true,
			wantNReport: 1,
			wantMatch:   "WARNING: requests:2.31.0 contains malware. Remediate this immediately",
		},
		{
			name: "two vulnerabilities",
			vulns: []ossbom.Vulnerability{
				{ID: "X", Purl: "pkg:pypi/requests@2.31.0"},
				{ID: "Y", Purl: "pkg:npm/lodash@4.17.21"},
			},
			wantHas:     true,
			wantNReport: 2,
		},
		{
			// Info is the only level below the failing floor.
			name: "informational only does not fail",
			vulns: []ossbom.Vulnerability{
				{
					ID:          "Z",
					Purl:        "pkg:npm/removed@0.0.1-security",
					Description: "This package was previously identified as malicious and removed from NPM",
					Severity:    "Info",
				},
			},
			wantHas:     false,
			wantNReport: 0,
			wantNInfo:   1,
			wantInfo: "removed:0.0.1-security was flagged for information only: " +
				"This package was previously identified as malicious and removed from NPM",
		},
		{
			// Info must not mask a real detection in the same SBOM.
			name: "informational alongside a real detection still fails",
			vulns: []ossbom.Vulnerability{
				{ID: "Z", Purl: "pkg:npm/removed@0.0.1-security", Severity: "Info"},
				{ID: "X", Purl: "pkg:pypi/requests@2.31.0", Severity: "Critical"},
			},
			wantHas:     true,
			wantNReport: 1,
			wantMatch:   "WARNING: requests:2.31.0 contains malware. Remediate this immediately",
			wantNInfo:   1,
		},
		{
			// Casing has varied in the store, so parsing is case-insensitive.
			name: "uppercase INFO still does not fail",
			vulns: []ossbom.Vulnerability{
				{ID: "Z", Purl: "pkg:npm/removed@0.0.1-security", Severity: "INFO"},
			},
			wantHas:     false,
			wantNReport: 0,
			wantNInfo:   1,
		},
		{
			// Fail closed: an ungraded finding is exactly what an older server
			// sends, and what an OSV-sourced finding carries.
			name: "unrecognised severity fails",
			vulns: []ossbom.Vulnerability{
				{ID: "X", Purl: "pkg:pypi/requests@2.31.0", Severity: "bogus"},
			},
			wantHas:     true,
			wantNReport: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ossbom.New(ossbom.Environment{})
			for _, v := range tt.vulns {
				s.AddVulnerability(v)
			}
			summary, has := MalwareReports(s, severity.FailingFloor)
			reports, informational := summary.Failing, summary.Informational
			if has != tt.wantHas {
				t.Errorf("has: got %v, want %v", has, tt.wantHas)
			}
			if len(reports) != tt.wantNReport {
				t.Fatalf("reports: got %d, want %d", len(reports), tt.wantNReport)
			}
			if tt.wantMatch != "" && reports[0] != tt.wantMatch {
				t.Errorf("report[0]: got %q, want %q", reports[0], tt.wantMatch)
			}
			if len(informational) != tt.wantNInfo {
				t.Fatalf("informational: got %d, want %d", len(informational), tt.wantNInfo)
			}
			if tt.wantInfo != "" && informational[0] != tt.wantInfo {
				t.Errorf("informational[0]: got %q, want %q", informational[0], tt.wantInfo)
			}
		})
	}
}

func TestParsePurl(t *testing.T) {
	tests := []struct {
		purl     string
		wantEco  string
		wantName string
		wantVers string
	}{
		{"pkg:pypi/requests@2.31.0", "pypi", "requests", "2.31.0"},
		{"pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21"},
		// A scoped npm name carries its own leading '@'; the version is still
		// what follows the last one.
		{"pkg:npm/@scope/pkg@1.2.3", "npm", "@scope/pkg", "1.2.3"},
		{"pkg:npm/@scope/pkg", "npm", "@scope/pkg", ""},
		// The spec spells a scope "%40scope"; a hand-rolled split would leave
		// the escape in the package name the user is shown.
		{"pkg:npm/%40scope/pkg@1.2.3", "npm", "@scope/pkg", "1.2.3"},
		// Qualifiers and a subpath belong to neither the name nor the version.
		{"pkg:npm/pkg@1.2.3?arch=x86#src/lib", "npm", "pkg", "1.2.3"},
		{"pkg:pypi/requests@2.31.0?extension=whl", "pypi", "requests", "2.31.0"},
		// Not PURLs at all — the fallback salvages what it can rather than
		// printing "WARNING: : contains malware" at somebody.
		{"requests@2.31.0", "", "requests", "2.31.0"},
		{"requests", "", "requests", ""},
		{"", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			eco, name, version := parsePurl(tt.purl)
			if eco != tt.wantEco || name != tt.wantName || version != tt.wantVers {
				t.Errorf("parsePurl(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.purl, eco, name, version, tt.wantEco, tt.wantName, tt.wantVers)
			}
		})
	}
}

// noCI clears the markers internal/env detects on, so a test of the local
// fallback does not inherit the CI it is running in.
func noCI(t *testing.T) {
	t.Helper()
	t.Setenv("TF_BUILD", "")
	t.Setenv("GITHUB_ACTIONS", "")
}

func TestRunNamesTheScanFromCI(t *testing.T) {
	noCI(t)
	t.Setenv("TF_BUILD", "True")
	t.Setenv("SYSTEM_TEAMPROJECT", "MyProject")
	t.Setenv("BUILD_REPOSITORY_NAME", "my-repo")
	t.Setenv("BUILD_SOURCEBRANCH", "refs/heads/main")

	sbom, err := Run(context.Background(), Options{Path: fixture(t, "python_simple_math")})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if sbom.Env.Project != "my-repo" {
		t.Errorf("env.Project: got %q, want %q", sbom.Env.Project, "my-repo")
	}
	if sbom.Name != "my-repo" {
		t.Errorf("sbom.Name: got %q, want %q", sbom.Name, "my-repo")
	}
	if sbom.Env.GithubOrg != "MyProject" || sbom.Env.GithubRepo != "my-repo" {
		t.Errorf("attribution: got %q/%q", sbom.Env.GithubOrg, sbom.Env.GithubRepo)
	}
}

// A description is API-supplied free text printed straight to a terminal, so a
// newline in it must not be able to forge an extra report line.
func TestMalwareReportsSanitisesInformationalDescription(t *testing.T) {
	s := ossbom.New(ossbom.Environment{})
	s.AddVulnerability(ossbom.Vulnerability{
		ID:          "Z",
		Purl:        "pkg:npm/removed@0.0.1-security",
		Description: "removed from NPM\nError: pkg:npm/other@1.0.0 contains malware\x1b[31m",
		Severity:    "Info",
	})

	summary, hasMalware := MalwareReports(s, severity.FailingFloor)
	informational := summary.Informational
	if hasMalware {
		t.Fatal("an informational finding must not fail the scan")
	}
	if len(informational) != 1 {
		t.Fatalf("informational = %d, want 1", len(informational))
	}
	if strings.ContainsAny(informational[0], "\n\r\x1b") {
		t.Errorf("control characters survived into the report line: %q", informational[0])
	}
}

// At the Info floor an informational finding fails, which is what
// --fail-on-informational asks for.
func TestMalwareReportsAtInfoFloor(t *testing.T) {
	s := ossbom.New(ossbom.Environment{})
	s.AddVulnerability(ossbom.Vulnerability{ID: "Z", Purl: "pkg:npm/removed@0.0.1-security", Severity: "Info"})

	summary, hasMalware := MalwareReports(s, severity.Info)
	if !hasMalware {
		t.Error("hasMalware = false at the Info floor, want true")
	}
	if len(summary.Failing) != 1 {
		t.Errorf("failing = %d, want 1", len(summary.Failing))
	}
	if len(summary.Informational) != 0 {
		t.Errorf("informational = %d, want 0", len(summary.Informational))
	}
}
