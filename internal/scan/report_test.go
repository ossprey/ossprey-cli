package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

func TestNewReportClean(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "proj", Path: "/tmp/proj"})
	s.AddComponent(ossbom.Component{Name: "requests", Version: "2.31.0", Type: "pypi"})

	r := NewReport(s)
	if r.Verdict != VerdictClean {
		t.Errorf("verdict: got %q, want %q", r.Verdict, VerdictClean)
	}
	if r.Components != 1 {
		t.Errorf("components: got %d, want 1", r.Components)
	}
	if r.Project != "proj" || r.Path != "/tmp/proj" {
		t.Errorf("project/path: got %q/%q", r.Project, r.Path)
	}
	// Non-nil so `jq '.findings | length'` works on a clean scan.
	if r.Findings == nil {
		t.Error("findings: got nil, want empty slice")
	}
	if r.Skipped != nil {
		t.Errorf("skipped: got %+v, want nil", r.Skipped)
	}
}

func TestNewReportMalware(t *testing.T) {
	s := ossbom.New(ossbom.Environment{})
	s.AddComponent(ossbom.Component{Name: "@scope/pkg", Version: "1.2.3", Type: "npm"})
	s.AddVulnerability(ossbom.NewMalwareVulnerability(
		"OSSPREY-1", "pkg:npm/@scope/pkg@1.2.3", "steals tokens"))

	r := NewReport(s)
	if r.Verdict != VerdictMalware {
		t.Fatalf("verdict: got %q, want %q", r.Verdict, VerdictMalware)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings: got %d, want 1", len(r.Findings))
	}
	f := r.Findings[0]
	want := Finding{
		Purl:        "pkg:npm/@scope/pkg@1.2.3",
		Ecosystem:   "npm",
		Name:        "@scope/pkg",
		Version:     "1.2.3",
		ID:          "OSSPREY-1",
		Type:        "Malware",
		Description: "steals tokens",
		Reference:   "Unknown",
	}
	if f != want {
		t.Errorf("finding:\n got %+v\nwant %+v", f, want)
	}
}

func TestSkippedReportIsNeitherCleanNorMalware(t *testing.T) {
	s := ossbom.New(ossbom.Environment{})
	s.AddComponent(ossbom.Component{Name: "requests", Version: "2.31.0", Type: "pypi"})

	r := SkippedReport(s, "monthly quota exhausted", "2026-09-01T00:00:00Z")
	if r.Verdict != VerdictSkipped {
		t.Errorf("verdict: got %q, want %q", r.Verdict, VerdictSkipped)
	}
	if r.Skipped == nil || r.Skipped.Message != "monthly quota exhausted" ||
		r.Skipped.ResetAt != "2026-09-01T00:00:00Z" {
		t.Errorf("skipped: got %+v", r.Skipped)
	}
	if r.Components != 1 {
		t.Errorf("components: got %d, want 1", r.Components)
	}
}

func TestWriteReportRoundTrip(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "proj"})
	s.AddComponent(ossbom.Component{Name: "lodash", Version: "4.17.21", Type: "npm"})
	s.AddVulnerability(ossbom.NewMalwareVulnerability("X", "pkg:npm/lodash@4.17.21", "bad"))

	// A nested path exercises the parent-directory creation the action relies
	// on when it points --report at a fresh temp dir.
	path := filepath.Join(t.TempDir(), "nested", "report.json")
	if err := WriteReport(path, NewReport(s)); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var got Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if got.Verdict != VerdictMalware || len(got.Findings) != 1 {
		t.Errorf("round trip: got %+v", got)
	}
	if got.Findings[0].Name != "lodash" {
		t.Errorf("finding name: got %q, want lodash", got.Findings[0].Name)
	}
}

func TestNewReportInformationalVerdict(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "p"})
	s.AddVulnerability(ossbom.Vulnerability{
		ID:          "Z",
		Purl:        "pkg:npm/removed@0.0.1-security",
		Description: "removed from NPM",
		Severity:    "Info",
	})

	r := NewReport(s)
	if r.Verdict != VerdictInformational {
		t.Errorf("verdict = %q, want %q", r.Verdict, VerdictInformational)
	}
	// findings holds only what fails, so a consumer counting it to say
	// "N malicious packages" stays correct.
	if len(r.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(r.Findings))
	}
	if len(r.Informational) != 1 {
		t.Fatalf("informational = %d, want 1", len(r.Informational))
	}
	if r.Informational[0].Severity != "Info" {
		t.Errorf("severity = %q, want Info", r.Informational[0].Severity)
	}
}

// The count a consumer renders as "N malicious packages" must not include an
// informational finding found in the same scan.
func TestNewReportSplitsMixedFindings(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "p"})
	s.AddVulnerability(ossbom.Vulnerability{ID: "Z", Purl: "pkg:npm/removed@0.0.1-security", Severity: "Info"})
	s.AddVulnerability(ossbom.Vulnerability{ID: "X", Purl: "pkg:pypi/evil@1.0.0", Severity: "Critical"})

	r := NewReport(s)
	if r.Verdict != VerdictMalware {
		t.Errorf("verdict = %q, want %q", r.Verdict, VerdictMalware)
	}
	if len(r.Findings) != 1 || r.Findings[0].Name != "evil" {
		t.Fatalf("findings = %+v, want just evil", r.Findings)
	}
	if len(r.Informational) != 1 || r.Informational[0].Name != "removed" {
		t.Fatalf("informational = %+v, want just removed", r.Informational)
	}
}

// Omitted when empty, so a consumer that predates the field sees no change.
func TestNewReportOmitsEmptyInformational(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "p"})
	s.AddVulnerability(ossbom.Vulnerability{ID: "X", Purl: "pkg:pypi/evil@1.0.0", Severity: "Critical"})

	raw, err := json.Marshal(NewReport(s))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "informational") {
		t.Errorf("informational key present on a malware-only report: %s", raw)
	}
}

// An informational finding must not soften the verdict for a real detection
// found in the same scan.
func TestNewReportMalwareWinsOverInformational(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "p"})
	s.AddVulnerability(ossbom.Vulnerability{ID: "Z", Purl: "pkg:npm/removed@0.0.1-security", Severity: "Info"})
	s.AddVulnerability(ossbom.Vulnerability{ID: "X", Purl: "pkg:pypi/evil@1.0.0", Severity: "Critical"})

	if r := NewReport(s); r.Verdict != VerdictMalware {
		t.Errorf("verdict = %q, want %q", r.Verdict, VerdictMalware)
	}
}

// Fail closed: no severity is what an older server sends.
func TestNewReportUngradedFindingIsMalware(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "p"})
	s.AddVulnerability(ossbom.Vulnerability{ID: "X", Purl: "pkg:pypi/evil@1.0.0"})

	if r := NewReport(s); r.Verdict != VerdictMalware {
		t.Errorf("verdict = %q, want %q", r.Verdict, VerdictMalware)
	}
}

// A skipped scan checked nothing, so it stays skipped even when the SBOM it was
// built from happens to carry an informational finding.
func TestSkippedReportOverridesInformational(t *testing.T) {
	s := ossbom.New(ossbom.Environment{Project: "p"})
	s.AddVulnerability(ossbom.Vulnerability{ID: "Z", Purl: "pkg:npm/removed@0.0.1-security", Severity: "Info"})

	if r := SkippedReport(s, "quota exhausted", ""); r.Verdict != VerdictSkipped {
		t.Errorf("verdict = %q, want %q", r.Verdict, VerdictSkipped)
	}
}
