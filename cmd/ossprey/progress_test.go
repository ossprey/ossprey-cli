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

// captureProgress swaps the indicator's writer for a buffer. A bytes.Buffer is
// not a terminal, so progress.Start takes its plain-line branch and the test
// reads one stable line instead of a redrawn animation.
func captureProgress(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := progressOut
	progressOut = &buf
	t.Cleanup(func() { progressOut = old })
	return &buf
}

// scanAPI serves a scan that submits and then polls clean, which is the only
// path that waits long enough to need an indicator.
func scanAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runCheck drives the check command the way runScan drives scan: cobra's own
// streams are discarded, so what a test observes is only what the command chose
// to write to a real destination of its own.
func runCheck(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newCheckCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.Execute()
}

// The wait for a verdict is the longest silent stretch of `ossprey check`, and
// an unannounced multi-second pause is indistinguishable from a hang.
func TestCheckAnnouncesTheWaitForAVerdict(t *testing.T) {
	buf := captureProgress(t)
	srv := scanAPI(t)

	if err := runCheck(t, "-e", "npm", "lodash@4.17.21", "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("check: %v", err)
	}

	if got, want := buf.String(), "ossprey: scan in progress, checking 1 package...\n"; got != want {
		t.Errorf("progress output = %q, want %q", got, want)
	}
}

// A dry run reaches its verdict locally and returns immediately, so there is no
// wait to announce — and announcing one would claim a submission that never
// happened.
func TestCheckDryRunAnnouncesNothing(t *testing.T) {
	buf := captureProgress(t)

	if err := runCheck(t, "-e", "npm", "lodash@4.17.21", "--dry-run-safe"); err != nil {
		t.Fatalf("check --dry-run-safe: %v", err)
	}

	if got := buf.String(); got != "" {
		t.Errorf("a dry run should announce nothing, got %q", got)
	}
}

// The same wait as check's, reached the other way: `scan` catalogs a directory
// first, so the count comes from the SBOM rather than from the command line.
func TestScanAnnouncesTheWaitForAVerdict(t *testing.T) {
	buf := captureProgress(t)
	srv := scanAPI(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runScan(t, dir, "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Contains, not HasPrefix: cataloguing is announced first, and what this
	// test pins is that the wait for a verdict is announced at all.
	if got := buf.String(); !strings.Contains(got, "ossprey: scan in progress, checking ") {
		t.Errorf("progress output = %q, want a scan-in-progress announcement", got)
	}
}

// Cataloguing is the first long silence of a scan and, where ranges have to be
// resolved through uv or npm, the longest one — so it is announced before the
// wait for a verdict rather than left as a silent pause on an empty terminal.
func TestScanAnnouncesCataloguing(t *testing.T) {
	buf := captureProgress(t)
	srv := scanAPI(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runScan(t, dir, "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan: %v", err)
	}

	if got, want := buf.String(), "ossprey: cataloguing dependencies...\n"; !strings.HasPrefix(got, want) {
		t.Errorf("progress output = %q, want it to start with %q", got, want)
	}
}

// Passive submits and returns without polling, but the submission itself is the
// same silent network round trip, so it is announced too — in its own words,
// since nothing is being checked for a verdict.
func TestScanPassiveAnnouncesTheSubmission(t *testing.T) {
	buf := captureProgress(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans/status" {
			t.Error("passive must not poll the status endpoint")
		}
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	if err := runScan(t, t.TempDir(), "--passive", "--url", srv.URL, "--api-key", "test-key"); err != nil {
		t.Fatalf("scan --passive: %v", err)
	}

	// The submission's own wording is what matters here; the cataloguing line
	// that precedes it has its own test.
	if got, want := buf.String(), "ossprey: submitting scan...\n"; !strings.HasSuffix(got, want) {
		t.Errorf("progress output = %q, want it to end with %q", got, want)
	}
}

// --local owns stdout for the OSSBOM and returns before any submission, so
// there is nothing to wait for and nothing may be printed.
func TestScanLocalAnnouncesNothing(t *testing.T) {
	buf := captureProgress(t)

	oldStdout := os.Stdout
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	os.Stdout = devNull
	t.Cleanup(func() { os.Stdout = oldStdout; devNull.Close() })

	if err := runScan(t, t.TempDir(), "--local"); err != nil {
		t.Fatalf("scan --local: %v", err)
	}

	if got := buf.String(); got != "" {
		t.Errorf("--local should announce nothing, got %q", got)
	}
}

// init's third step is a scan, and it is the first thing a new user watches
// this tool do, so both of its waits are announced the same way `ossprey scan`
// announces them.
func TestInitFirstScanAnnouncesBothWaits(t *testing.T) {
	buf := captureProgress(t)
	srv := scanAPI(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := runFirstScan(t.Context(), dir, srv.URL, "test-key"); err != nil {
		t.Fatalf("runFirstScan: %v", err)
	}

	got := buf.String()
	if !strings.HasPrefix(got, "ossprey: cataloguing dependencies...\n") {
		t.Errorf("progress output = %q, want it to start with the cataloguing announcement", got)
	}
	if !strings.Contains(got, "ossprey: scan in progress, checking ") {
		t.Errorf("progress output = %q, want a scan-in-progress announcement", got)
	}
}
