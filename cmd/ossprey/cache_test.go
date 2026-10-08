package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const cleanScanBody = `{"vulnerabilities":[]}`

// countingAPI answers every scan submission the same way and counts them.
func countingAPI(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/scans/status") {
			t.Errorf("unexpected status poll")
			return
		}
		posts.Add(1)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &posts
}

// isolatedCache points the cache at a fresh dir and returns its scans/ path.
func isolatedCache(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("OSSPREY_CACHE_DIR", root)
	t.Setenv("OSSPREY_SCAN_CACHE_TTL", "")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	return filepath.Join(root, "scans")
}

// pythonProject is a one-requirement project: catalogued by syft alone, no
// resolver and no registry involved, so the test is about the cache.
func pythonProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type cachedReport struct {
	Verdict          string `json:"verdict"`
	Cached           bool   `json:"cached"`
	CachedAgeSeconds *int   `json:"cached_age_seconds"`
}

func readCachedReport(t *testing.T, path string) cachedReport {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r cachedReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("parse report %s: %v", raw, err)
	}
	return r
}

// captureStdout swaps os.Stdout for a pipe: the verdict and the passive
// "Scan submitted" line are written there directly.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = orig
	w.Close()
	out := <-done
	r.Close()
	return out
}

func TestScan_SecondIdenticalScanIsServedFromCacheAndReported(t *testing.T) {
	isolatedCache(t)
	srv, posts := countingAPI(t, http.StatusOK, cleanScanBody)
	dir := pythonProject(t)
	reports := t.TempDir()

	run := func(name string, extra ...string) cachedReport {
		t.Helper()
		report := filepath.Join(reports, name+".json")
		args := append([]string{"--url", srv.URL, "--api-key", "test-key", "--no-version-lookup", "--report", report}, extra...)
		captureStdout(t, func() {
			if err := runScan(t, dir, args...); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		return readCachedReport(t, report)
	}

	first := run("first")
	if first.Cached || first.CachedAgeSeconds != nil {
		t.Errorf("first scan reported as cached: %+v", first)
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("first scan made %d requests", got)
	}

	second := run("second")
	if got := posts.Load(); got != 1 {
		t.Errorf("second identical scan reached the API (%d requests)", got)
	}
	if !second.Cached || second.CachedAgeSeconds == nil || *second.CachedAgeSeconds < 0 {
		t.Errorf("second scan not reported as cached: %+v", second)
	}
	if second.Verdict != "clean" {
		t.Errorf("second verdict = %q, want clean", second.Verdict)
	}

	third := run("third", "--no-cache")
	if got := posts.Load(); got != 2 {
		t.Errorf("--no-cache did not reach the API (%d requests)", got)
	}
	if third.Cached {
		t.Errorf("--no-cache scan reported as cached: %+v", third)
	}
}

// The passive stdout line claims a submission happened. On a deduplicated
// post nothing was submitted, so it must stay quiet.
func TestScanPassive_SecondIdenticalPostIsNotSentAndNotAnnounced(t *testing.T) {
	isolatedCache(t)
	srv, posts := countingAPI(t, http.StatusAccepted, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	dir := pythonProject(t)

	run := func() string {
		return captureStdout(t, func() {
			if err := runScan(t, dir, "--passive", "--url", srv.URL, "--api-key", "test-key", "--no-version-lookup"); err != nil {
				t.Fatalf("scan --passive: %v", err)
			}
		})
	}

	if out := run(); !strings.Contains(out, "Scan submitted") {
		t.Errorf("first passive scan did not announce the submission: %q", out)
	}
	out := run()
	if got := posts.Load(); got != 1 {
		t.Errorf("second identical passive scan reached the API (%d requests)", got)
	}
	if strings.Contains(out, "Scan submitted") {
		t.Errorf("a deduplicated post claimed a submission: %q", out)
	}
}

// Dry runs and --local never talk to the API, so they must not leave a cache
// entry that a later real scan could read. (--dry-run-malicious is covered by
// the smoke tests: in-process it would os.Exit(1) the test binary.)
func TestScanDryRunAndLocalNeverTouchTheCache(t *testing.T) {
	scans := isolatedCache(t)
	dir := pythonProject(t)
	for _, flag := range []string{"--dry-run-safe", "--local"} {
		captureStdout(t, func() {
			if err := runScan(t, dir, flag, "--no-version-lookup"); err != nil {
				t.Fatalf("scan %s: %v", flag, err)
			}
		})
	}
	if _, err := os.Stat(scans); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a dry run or --local created the cache dir (stat err %v)", err)
	}
}

// init's scan exists to prove the credential it just minted works, and it
// tells the user to look for the scan in the dashboard. A replayed verdict
// does neither, so init always asks the API — and still stores the result,
// so the user's next `ossprey scan` reuses it.
func TestInitFirstScanAlwaysGoesLive(t *testing.T) {
	isolatedCache(t)
	srv, posts := countingAPI(t, http.StatusOK, cleanScanBody)
	dir := pythonProject(t)

	for i := 0; i < 2; i++ {
		captureStdout(t, func() {
			if err := runFirstScan(context.Background(), dir, srv.URL, "ospy_same_key_each_run"); err != nil {
				t.Fatalf("run %d: %v", i+1, err)
			}
		})
	}
	if got := posts.Load(); got != 2 {
		t.Errorf("init's scan was served from the cache (%d requests, want 2)", got)
	}
}

func TestCheck_SecondIdenticalCheckIsServedFromCache(t *testing.T) {
	isolatedCache(t)
	srv, posts := countingAPI(t, http.StatusOK, cleanScanBody)
	reports := t.TempDir()

	run := func(name string, extra ...string) cachedReport {
		t.Helper()
		report := filepath.Join(reports, name+".json")
		cmd := newCheckCmd()
		cmd.SetArgs(append([]string{"-e", "npm", "left-pad@1.3.0", "--url", srv.URL, "--api-key", "test-key", "--report", report}, extra...))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		captureStdout(t, func() {
			if err := cmd.Execute(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		return readCachedReport(t, report)
	}

	if r := run("first"); r.Cached {
		t.Errorf("first check reported as cached: %+v", r)
	}
	second := run("second")
	if got := posts.Load(); got != 1 {
		t.Errorf("second identical check reached the API (%d requests)", got)
	}
	if !second.Cached {
		t.Errorf("second check not reported as cached: %+v", second)
	}
	run("third", "--no-cache")
	if got := posts.Load(); got != 2 {
		t.Errorf("check --no-cache did not reach the API (%d requests)", got)
	}
}
