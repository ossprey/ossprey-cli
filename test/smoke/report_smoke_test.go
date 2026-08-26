//go:build smoke

package smoke

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// report mirrors internal/scan.Report — declared separately on purpose, so a
// silent rename of a JSON tag breaks this test rather than sailing through.
// The GitHub Action parses these exact keys.
type report struct {
	Verdict    string `json:"verdict"`
	Project    string `json:"project"`
	Components int    `json:"components"`
	Findings   []struct {
		Purl      string `json:"purl"`
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Version   string `json:"version"`
	} `json:"findings"`
}

func readReport(t *testing.T, path string) report {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parse report %s: %v", raw, err)
	}
	return r
}

// The report is written on a malware verdict, before the exit-1 — CI reads it
// precisely on the failing run.
func TestReportOnMalware(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	reportFile := filepath.Join(t.TempDir(), "nested", "report.json")

	cmd := exec.Command(binPath, "scan", pkgDir, "--dry-run-malicious", "--report", reportFile)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()

	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 {
		t.Fatalf("expected exit 1, got %v\nstderr: %s", err, stderr.String())
	}

	r := readReport(t, reportFile)
	if r.Verdict != "malware" {
		t.Errorf("verdict: got %q, want malware", r.Verdict)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings: got %d, want 1", len(r.Findings))
	}
	if r.Findings[0].Name == "" || r.Findings[0].Version == "" {
		t.Errorf("finding not split into name/version: %+v", r.Findings[0])
	}
	if r.Components == 0 {
		t.Error("components: got 0, want the catalogued count")
	}
	if r.Project != "python_simple_math" {
		t.Errorf("project: got %q, want python_simple_math", r.Project)
	}
}

func TestReportOnClean(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	reportFile := filepath.Join(t.TempDir(), "report.json")

	cmd := exec.Command(binPath, "scan", pkgDir, "--dry-run-safe", "--report", reportFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected exit 0, got %v\n%s", err, out)
	}

	r := readReport(t, reportFile)
	if r.Verdict != "clean" {
		t.Errorf("verdict: got %q, want clean", r.Verdict)
	}
	if len(r.Findings) != 0 {
		t.Errorf("findings: got %d, want 0", len(r.Findings))
	}
}

// --local owns stdout; pairing it with --report would promise a verdict the
// command never reaches.
func TestReportRejectedWithLocal(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	reportFile := filepath.Join(t.TempDir(), "report.json")

	cmd := exec.Command(binPath, "scan", pkgDir, "--local", "--report", reportFile)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected an error, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Errorf("expected a mutual-exclusion error, got:\n%s", out)
	}
	if _, err := os.Stat(reportFile); !os.IsNotExist(err) {
		t.Errorf("report file should not exist, stat err = %v", err)
	}
}

// --local's JSON must stay the only thing on stdout: the GitHub Action and the
// platform both parse it.
func TestLocalStdoutStaysPureJSON(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")

	cmd := exec.Command(binPath, "scan", pkgDir, "--local")
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("scan --local: %v\nstderr: %s", err, stderr.String())
	}
	var any map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout.String()), &any); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\nstdout: %s", err, stdout.String())
	}
}
