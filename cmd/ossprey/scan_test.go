package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestScanPassive_PostsWithoutPolling(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			posted = true
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			t.Error("passive must not poll the status endpoint")
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := runScan(t, dir, "--passive", "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan --passive: %v", err)
	}
	if !posted {
		t.Error("passive never posted the scan")
	}
}

func TestScanPassive_SubmitErrorFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := runScan(t, dir, "--passive", "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("passive must not fail the build on a submit error; got %v", err)
	}
}

func TestScanFlagsMutuallyExclusive(t *testing.T) {
	if err := runScan(t, t.TempDir(), "--skip-ci", "--passive"); err == nil {
		t.Fatal("expected an error combining --skip-ci and --passive")
	}
	if err := runScan(t, t.TempDir(), "--skip-ci", "--monitor", validMonitorID); err == nil {
		t.Fatal("expected an error combining --skip-ci and --monitor")
	}
}

// A report file says a verdict was reached. A passive scan never fetches
// findings, so a "clean" report from one would tell CI that nothing was found
// when in fact nothing was looked at. The combination is refused outright
// rather than silently ignored, which is what the old --ci-cache-scan-only did
// and which left a stale report from an earlier run readable as this run's.
func TestScanPassive_RefusesReport(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")

	err := runScan(t, dir, "--passive", "--report", report, "--api-key", "test-key")

	if err == nil {
		t.Fatal("expected --passive --report to be refused")
	}
	if _, statErr := os.Stat(report); !os.IsNotExist(statErr) {
		t.Fatalf("expected no report file, stat returned %v", statErr)
	}
}

func TestScanPassive_RefusesLocal(t *testing.T) {
	if err := runScan(t, t.TempDir(), "--passive", "--local"); err == nil {
		t.Fatal("expected --passive --local to be refused")
	}
}

// The original CI-facing spelling still works: it is set in pipelines we do not
// control, so it must keep behaving exactly like --passive.
func TestScanCacheScanOnly_IsAnAliasForPassive(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans/status" {
			t.Error("the alias must not poll the status endpoint")
		}
		posted = true
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	if err := runScan(t, t.TempDir(), "--ci-cache-scan-only", "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan --ci-cache-scan-only: %v", err)
	}
	if !posted {
		t.Error("the alias never posted the scan")
	}
}

func TestScanPassiveEnv_PostsWithoutPolling(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans/status" {
			t.Error("OSSPREY_PASSIVE must not poll the status endpoint")
		}
		posted = true
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	t.Setenv("OSSPREY_PASSIVE", "1")
	if err := runScan(t, t.TempDir(), "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan with OSSPREY_PASSIVE=1: %v", err)
	}
	if !posted {
		t.Error("OSSPREY_PASSIVE never posted the scan")
	}
}

const validMonitorID = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// A monitor submits through its own unauthenticated route and sends no
// credential header, which is the whole reason it is safe to hand out.
func TestScanMonitor_PostsToTheIngestRouteWithNoCredential(t *testing.T) {
	var gotPath, gotAPIKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	if err := runScan(t, t.TempDir(), "--monitor", validMonitorID, "--url", srv.URL); err != nil {
		t.Fatalf("scan --monitor: %v", err)
	}

	if want := "/ingest/" + validMonitorID + "/scans"; gotPath != want {
		t.Errorf("posted to %q, want %q", gotPath, want)
	}
	if gotAPIKey != "" || gotAuth != "" {
		t.Errorf("monitor submission sent a credential: x-api-key=%q authorization=%q", gotAPIKey, gotAuth)
	}
}

// A monitor id names where the scan should land. Falling back to a stored
// credential on a typo would file it against the wrong thing and hide the typo.
func TestScanMonitor_RejectsAMalformedID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a malformed monitor id must not reach the network (path %s)", r.URL.Path)
	}))
	defer srv.Close()

	for _, id := range []string{"nope", "ospi_short", "ospi_zzzz", validMonitorID + "extra"} {
		if err := runScan(t, t.TempDir(), "--monitor", id, "--url", srv.URL); err == nil {
			t.Errorf("monitor id %q was accepted", id)
		}
	}
}

// Passive mode runs in front of other people's work, so it must not turn a
// cataloguing failure into an exit code somebody has to chase.
func TestScanPassive_ExitsZeroOnACataloguingFailure(t *testing.T) {
	if err := runScan(t, "/nonexistent/definitely-not-here", "--passive", "--api-key", "k"); err != nil {
		t.Fatalf("passive must exit 0 on a bad path; got %v", err)
	}
}

// A monitor turns the malware gate off and files the scan under whoever owns
// the id. When OSSPREY_MONITOR_ID was set by someone else -- a shared runner, a
// workflow env: block -- that is a silent takeover, so it is never silent.
func TestScanMonitorFromEnvWarnsThatBlockingIsOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	t.Setenv("OSSPREY_MONITOR_ID", validMonitorID)
	stderr := captureStderr(t, func() {
		if err := runScan(t, t.TempDir(), "--url", srv.URL); err != nil {
			t.Fatalf("scan: %v", err)
		}
	})

	if !strings.Contains(stderr, "will NOT fail this scan") {
		t.Errorf("no warning that blocking is disabled:\n%s", stderr)
	}
	if !strings.Contains(stderr, "OSSPREY_MONITOR_ID") {
		t.Errorf("warning did not name where the monitor came from:\n%s", stderr)
	}
	if strings.Contains(stderr, validMonitorID) {
		t.Errorf("the full monitor id was written to stderr:\n%s", stderr)
	}
}

func TestScanMonitorFlagWarnsToo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	stderr := captureStderr(t, func() {
		if err := runScan(t, t.TempDir(), "--monitor", validMonitorID, "--url", srv.URL); err != nil {
			t.Fatalf("scan: %v", err)
		}
	})

	if !strings.Contains(stderr, "--monitor") {
		t.Errorf("warning did not name the flag as the source:\n%s", stderr)
	}
}

// captureStderr swaps os.Stderr for a pipe; the warning is written there
// directly rather than through the cobra command's writer.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	os.Stderr = orig
	w.Close()
	out := <-done
	r.Close()
	return out
}
