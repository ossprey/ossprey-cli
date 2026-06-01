package scan

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
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
			sbom, err := Run(context.Background(), Options{Path: fixture(t, tt.fixture)})
			if err != nil {
				t.Fatalf("Run returned error: %v", err)
			}

			if got := len(sbom.Components); got < tt.minComponents {
				t.Errorf("component count: got %d, want >= %d", got, tt.minComponents)
			}

			// Project/Name drive the dashboard scan label; must be the scanned
			// directory's base name, not the host machine name.
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ossbom.New(ossbom.Environment{})
			for _, v := range tt.vulns {
				s.AddVulnerability(v)
			}
			reports, has := MalwareReports(s)
			if has != tt.wantHas {
				t.Errorf("has: got %v, want %v", has, tt.wantHas)
			}
			if len(reports) != tt.wantNReport {
				t.Fatalf("reports: got %d, want %d", len(reports), tt.wantNReport)
			}
			if tt.wantMatch != "" && reports[0] != tt.wantMatch {
				t.Errorf("report[0]: got %q, want %q", reports[0], tt.wantMatch)
			}
		})
	}
}

func TestSplitPurl(t *testing.T) {
	tests := []struct {
		purl        string
		wantName    string
		wantVersion string
	}{
		{"pkg:pypi/requests@2.31.0", "requests", "2.31.0"},
		{"pkg:npm/lodash@4.17.21", "lodash", "4.17.21"},
		{"requests@2.31.0", "requests", "2.31.0"},
		{"requests", "requests", ""},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			name, version := splitPurl(tt.purl)
			if name != tt.wantName || version != tt.wantVersion {
				t.Errorf("splitPurl(%q) = (%q, %q), want (%q, %q)",
					tt.purl, name, version, tt.wantName, tt.wantVersion)
			}
		})
	}
}
