package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// runScanCtx is runScan with the warning collector main builds, which is where
// unresolved manifests are recorded.
func runScanCtx(t *testing.T, dir string, extra ...string) error {
	t.Helper()
	cmd := newScanCmd()
	cmd.SetArgs(append([]string{dir}, extra...))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.ExecuteContext(warn.NewContext(context.Background(), false))
}

type coverageReport struct {
	Verdict             string    `json:"verdict"`
	Components          int       `json:"components"`
	Unscanned           int       `json:"unscanned"`
	Transitive          string    `json:"transitive"`
	UnresolvedManifests *[]string `json:"unresolved_manifests"`
}

func readCoverage(t *testing.T, path string) coverageReport {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r coverageReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return r
}

// A setup.py project is never resolved (that would run it), so its manifest
// is unresolved: the report says partial, and --require-complete fails.
func TestScanReportsAnUnresolvableManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "setup.py", "from setuptools import setup\nsetup(name='app', install_requires=['requests==2.31.0'])\n")
	report := filepath.Join(t.TempDir(), "r.json")

	if err := runScanCtx(t, dir, "--dry-run-safe", "--no-version-lookup", "--report", report); err != nil {
		t.Fatalf("scan without --require-complete must pass: %v", err)
	}
	r := readCoverage(t, report)
	if r.Transitive != "partial" || r.UnresolvedManifests == nil || len(*r.UnresolvedManifests) != 1 || (*r.UnresolvedManifests)[0] != "setup.py" {
		t.Errorf("report = %+v, want partial with [setup.py]", r)
	}
	if r.Verdict != "clean" {
		t.Errorf("verdict = %q; coverage must not change it", r.Verdict)
	}

	err := runScanCtx(t, dir, "--dry-run-safe", "--no-version-lookup", "--report", report, "--require-complete")
	if err == nil || !strings.Contains(err.Error(), "setup.py") {
		t.Fatalf("--require-complete: err = %v, want an error naming setup.py", err)
	}
	if r := readCoverage(t, report); r.Transitive != "partial" {
		t.Errorf("report not written before the failure: %+v", r)
	}
}

// A fully locked project is complete: [] rather than an absent key, and
// --require-complete passes.
func TestScanReportsCompleteCoverage(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", leftPadLock)
	report := filepath.Join(t.TempDir(), "r.json")
	if err := runScanCtx(t, dir, "--dry-run-safe", "--no-version-lookup", "--report", report, "--require-complete"); err != nil {
		t.Fatalf("scan: %v", err)
	}
	r := readCoverage(t, report)
	if r.Transitive != "complete" || r.UnresolvedManifests == nil || len(*r.UnresolvedManifests) != 0 {
		t.Errorf("report = %+v, want complete with []", r)
	}
}

// A scan the platform answered with NOT_FOUND for every package checked
// nothing: --require-complete fails it with exit 2's error, not a clean pass.
func TestRequireCompleteFailsWhenNothingWasScanned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			io.WriteString(w, `{"status":"SUCCEEDED","output":{"vulnerabilities":[],"findings":[{"purl":"pkg:npm/left-pad@1.3.0","type":"NOT_FOUND"}]}}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", leftPadLock)
	report := filepath.Join(t.TempDir(), "r.json")
	args := []string{"--url", srv.URL, "--api-key", "test-key", "--no-version-lookup", "--report", report}

	if err := runScanCtx(t, dir, args...); err != nil {
		t.Fatalf("off by default, so the scan passes: %v", err)
	}
	if r := readCoverage(t, report); r.Unscanned != 1 || r.Components != 1 || r.Transitive != "complete" {
		t.Errorf("report = %+v, want 1 of 1 unscanned", r)
	}
	err := runScanCtx(t, dir, append(args, "--require-complete")...)
	if err == nil || !strings.Contains(err.Error(), "1 of 1 package(s) not scanned") {
		t.Fatalf("--require-complete: err = %v", err)
	}
}

func TestRequireCompleteRefusesPassiveAndLocal(t *testing.T) {
	dir := t.TempDir()
	for _, flag := range []string{"--passive", "--local"} {
		if err := runScanCtx(t, dir, flag, "--require-complete"); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("%s --require-complete: err = %v", flag, err)
		}
	}
}

const leftPadLock = `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,
 "packages":{"":{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},
 "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
