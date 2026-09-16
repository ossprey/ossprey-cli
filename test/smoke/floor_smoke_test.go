//go:build smoke

package smoke

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// floorServer answers a scan synchronously with one finding at the given grade
// and the account floor the API would have applied. floor is omitted entirely
// when empty, which is what a server predating the field looks like.
func floorServer(t *testing.T, findingSeverity, floor string) *httptest.Server {
	t.Helper()
	body := map[string]any{"vulnerabilities": []any{}}
	if findingSeverity != "" {
		body["vulnerabilities"] = []any{map[string]any{
			"id":        "OSSPREY-1",
			"purl":      "pkg:pypi/simple-math@0.0.1",
			"type":      "Malware",
			"reference": "Unknown",
			"severity":  findingSeverity,
		}}
	}
	if floor != "" {
		body["failing_severity_floor"] = floor
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal stub response: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/v1/scans" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(raw)
	}))
}

func runAgainst(t *testing.T, srv *httptest.Server, args ...string) (runResult, report) {
	t.Helper()
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	reportFile := filepath.Join(t.TempDir(), "report.json")
	full := append([]string{
		"scan", pkgDir, "--url", srv.URL, "--api-key", "test-key", "--report", reportFile,
	}, args...)

	cmd := exec.Command(binPath, full...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run ossprey: %v\nstderr: %s", err, stderr.String())
		}
		code = ee.ExitCode()
	}
	res := runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
	if _, statErr := os.Stat(reportFile); statErr != nil {
		return res, report{}
	}
	return res, readReport(t, reportFile)
}

// The whole point of the feature: the same finding passes or fails depending on
// what the account asked to be stopped by, with no flag and no new binary.
func TestServedFloorDecidesTheVerdict(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		floor    string
		args     []string
		wantCode int
		wantVerd string
	}{
		{name: "medium below a High floor", severity: "Medium", floor: "High", wantCode: 0, wantVerd: "informational"},
		{name: "high at a High floor", severity: "High", floor: "High", wantCode: 1, wantVerd: "malware"},
		{name: "info at an Info floor", severity: "Info", floor: "Info", wantCode: 1, wantVerd: "malware"},
		{name: "info at the default floor", severity: "Info", floor: "Low", wantCode: 0, wantVerd: "informational"},
		{name: "an unreadable floor is the default", severity: "Info", floor: "Banana", wantCode: 0, wantVerd: "informational"},
		{name: "an unreadable floor still fails a Low", severity: "Low", floor: "Banana", wantCode: 1, wantVerd: "malware"},
		{name: "no floor served behaves as today", severity: "Info", wantCode: 0, wantVerd: "informational"},
		{name: "nothing found at a raised floor is clean", severity: "", floor: "Critical", wantCode: 0, wantVerd: "clean"},
		{
			name: "the shorthand still lowers a raised floor", severity: "Medium", floor: "High",
			args: []string{"--fail-on-informational"}, wantCode: 1, wantVerd: "malware",
		},
		{
			name: "an override raises past the account", severity: "High", floor: "Low",
			args: []string{"--fail-on", "Critical"}, wantCode: 0, wantVerd: "informational",
		},
		{
			name: "an override raised to where the finding sits", severity: "Critical", floor: "Low",
			args: []string{"--fail-on", "Critical"}, wantCode: 1, wantVerd: "malware",
		},
		{
			name: "an override lowers past the account", severity: "Info", floor: "Critical",
			args: []string{"--fail-on", "Info"}, wantCode: 1, wantVerd: "malware",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := floorServer(t, tt.severity, tt.floor)
			defer srv.Close()

			res, r := runAgainst(t, srv, tt.args...)
			if res.exitCode != tt.wantCode {
				t.Errorf("exit code: got %d, want %d\nstdout: %s\nstderr: %s",
					res.exitCode, tt.wantCode, res.stdout, res.stderr)
			}
			if r.Verdict != tt.wantVerd {
				t.Errorf("verdict: got %q, want %q", r.Verdict, tt.wantVerd)
			}
		})
	}
}

// An ungraded finding must fail whatever the account asked for; a raised floor
// is the case where a rank-based implementation would quietly let it through.
func TestAnUngradedFindingFailsARaisedFloor(t *testing.T) {
	// Built by hand rather than through floorServer: the finding needs no
	// severity key at all, which is what every row written before grades
	// existed looks like.
	raw := `{"failing_severity_floor":"Critical","vulnerabilities":[` +
		`{"id":"OSSPREY-1","purl":"pkg:pypi/simple-math@0.0.1","type":"Malware","reference":"Unknown"}]}`
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, raw)
	}))
	defer stub.Close()

	res, r := runAgainst(t, stub)
	if res.exitCode != 1 {
		t.Errorf("exit code: got %d, want 1\nstdout: %s", res.exitCode, res.stdout)
	}
	if r.Verdict != "malware" {
		t.Errorf("verdict: got %q, want malware", r.Verdict)
	}
}

// The Azure DevOps task reads this file, not --report, so the floor has to be
// in it.
func TestOutputSBOMCarriesTheServedFloor(t *testing.T) {
	srv := floorServer(t, "Medium", "High")
	defer srv.Close()

	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	outFile := filepath.Join(t.TempDir(), "sbom.json")
	cmd := exec.Command(binPath, "scan", pkgDir, "--url", srv.URL, "--api-key", "k", "-o", outFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected exit 0, got %v\n%s", err, out)
	}

	raw, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var sbom struct {
		FailingSeverityFloor string `json:"failing_severity_floor"`
	}
	if err := json.Unmarshal(raw, &sbom); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	if sbom.FailingSeverityFloor != "High" {
		t.Errorf("floor: got %q, want High\n%s", sbom.FailingSeverityFloor, raw)
	}
}

// --local never reaches the API, so it has no floor to report and must not
// invent one.
func TestLocalSBOMCarriesNoFloor(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	out, err := exec.Command(binPath, "scan", pkgDir, "--local").Output()
	if err != nil {
		t.Fatalf("scan --local: %v", err)
	}
	if strings.Contains(string(out), "failing_severity_floor") {
		t.Errorf("--local output carried a floor:\n%s", out)
	}
}

// A typo costs a second, not a full catalogue and submit.
func TestFailOnRejectsANonSeverity(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	cmd := exec.Command(binPath, "scan", pkgDir, "--fail-on", "Bananas", "--dry-run-safe")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected an error, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "is not a severity level") {
		t.Errorf("expected a severity error, got:\n%s", out)
	}
}

// The dry runs reach their verdict with no network at all, so they keep the
// compiled-in default whatever an account is set to.
func TestDryRunsAreUnaffectedByTheFloor(t *testing.T) {
	pkgDir := filepath.Join(fixturesDir(t), "python_simple_math")
	for _, tc := range []struct {
		flag string
		want int
	}{{"--dry-run-safe", 0}, {"--dry-run-malicious", 1}} {
		t.Run(tc.flag, func(t *testing.T) {
			cmd := exec.Command(binPath, "scan", pkgDir, tc.flag)
			err := cmd.Run()
			code := 0
			if err != nil {
				ee, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatalf("run: %v", err)
				}
				code = ee.ExitCode()
			}
			if code != tc.want {
				t.Errorf("%s: exit %d, want %d", tc.flag, code, tc.want)
			}
		})
	}
}

// The documented 200: no components, no findings, no floor. It must not fail
// closed on the missing field.
func TestEmptyProjectResponseExitsZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"format":"OSSBOM","components":[],"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	res, r := runAgainst(t, srv)
	if res.exitCode != 0 {
		t.Errorf("exit code: got %d, want 0\nstdout: %s", res.exitCode, res.stdout)
	}
	if r.Verdict != "clean" {
		t.Errorf("verdict: got %q, want clean", r.Verdict)
	}
}
