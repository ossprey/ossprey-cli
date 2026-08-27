package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func runScan(t *testing.T, dir string, extra ...string) error {
	t.Helper()
	cmd := newScanCmd()
	cmd.SetArgs(append([]string{dir}, extra...))
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.Execute()
}

func TestScanSkipCIFlag(t *testing.T) {
	if err := runScan(t, "/nonexistent/definitely-not-here", "--skip-ci"); err != nil {
		t.Fatalf("scan --skip-ci: %v", err)
	}
}

func TestScanSkipCIEnv(t *testing.T) {
	t.Setenv("OSSPREY_SKIP_CI", "1")
	if err := runScan(t, "/nonexistent/definitely-not-here"); err != nil {
		t.Fatalf("scan with OSSPREY_SKIP_CI=1: %v", err)
	}
}

func TestScanCacheScanOnly_PostsWithoutPolling(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			posted = true
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			t.Error("ci-cache-scan-only must not poll the status endpoint")
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := runScan(t, dir, "--ci-cache-scan-only", "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan --ci-cache-scan-only: %v", err)
	}
	if !posted {
		t.Error("ci-cache-scan-only never posted the scan")
	}
}

func TestScanCacheScanOnly_SubmitErrorFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := runScan(t, dir, "--ci-cache-scan-only", "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("ci-cache-scan-only must not fail the build on a submit error; got %v", err)
	}
}

func TestScanFlagsMutuallyExclusive(t *testing.T) {
	if err := runScan(t, t.TempDir(), "--skip-ci", "--ci-cache-scan-only"); err == nil {
		t.Fatal("expected an error combining --skip-ci and --ci-cache-scan-only")
	}
}

// The no-verdict modes must not leave a report behind. A report file says a
// verdict was reached; --ci-cache-scan-only never fetches findings and
// --skip-ci never scans, so a "clean" report from either would tell CI that
// nothing was found when in fact nothing was looked at.
func TestScanCacheScanOnly_WritesNoReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans/status" {
			t.Error("ci-cache-scan-only must not poll the status endpoint")
		}
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	if err := runScan(t, dir, "--ci-cache-scan-only", "--report", report,
		"--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan --ci-cache-scan-only --report: %v", err)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatalf("expected no report file, stat returned %v", err)
	}
}

func TestScanSkipCI_WritesNoReport(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	if err := runScan(t, dir, "--skip-ci", "--report", report); err != nil {
		t.Fatalf("scan --skip-ci --report: %v", err)
	}
	if _, err := os.Stat(report); !os.IsNotExist(err) {
		t.Fatalf("expected no report file, stat returned %v", err)
	}
}
