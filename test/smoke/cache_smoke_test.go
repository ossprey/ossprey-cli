//go:build smoke

package smoke

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// countingStub answers every submission as a clean, finished scan (200 with
// an empty verdict, which both the blocking and the passive path accept) and
// counts how many arrived.
func countingStub(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/scans/status") {
			t.Errorf("unexpected status poll on %s", r.URL.Path)
			return
		}
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &posts
}

// runRawEnv is runRaw with extra environment for the binary.
func runRawEnv(t *testing.T, env []string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run ossprey: %v\nstderr: %s", err, stderr.String())
		}
		code = ee.ExitCode()
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

// cacheEnv gives one test its own cache and config dir, with the default TTL.
func cacheEnv(t *testing.T) []string {
	t.Helper()
	return []string{
		"OSSPREY_CACHE_DIR=" + t.TempDir(),
		"OSSPREY_CONFIG_DIR=" + t.TempDir(),
		"OSSPREY_SCAN_CACHE_TTL=",
		"OSSPREY_PASSIVE=",
		"OSSPREY_MONITOR_ID=",
	}
}

// The second identical scan never reaches the API: its clean verdict is
// replayed locally, said so on stderr, and marked in the report.
func TestCacheSecondIdenticalScanIsServedLocally(t *testing.T) {
	srv, posts := countingStub(t)
	env := cacheEnv(t)
	pkgDir := filepath.Join(fixturesDir(t), "npm_simple_math")
	reports := t.TempDir()

	scan := func(name string, extra ...string) (runResult, report) {
		t.Helper()
		file := filepath.Join(reports, name+".json")
		args := append([]string{"scan", pkgDir, "--url", srv.URL, "--api-key", "test-key",
			"--no-version-lookup", "--report", file}, extra...)
		res := runRawEnv(t, env, args...)
		if res.exitCode != 0 {
			t.Fatalf("%s: exit %d\nstdout: %s\nstderr: %s", name, res.exitCode, res.stdout, res.stderr)
		}
		return res, readReport(t, file)
	}

	first, r1 := scan("first")
	if got := posts.Load(); got != 1 {
		t.Fatalf("first scan made %d requests, want 1\nstderr: %s", got, first.stderr)
	}
	if r1.Cached || r1.CachedAgeSeconds != nil {
		t.Errorf("first report claims a cached verdict: cached=%v age=%v", r1.Cached, r1.CachedAgeSeconds)
	}

	second, r2 := scan("second")
	if got := posts.Load(); got != 1 {
		t.Errorf("second identical scan reached the API (%d requests)", got)
	}
	assertContains(t, second.stderr, "clean result reused from a scan")
	assertContains(t, second.stdout, "No malware found")
	if !r2.Cached || r2.CachedAgeSeconds == nil || *r2.CachedAgeSeconds < 0 {
		t.Errorf("second report not marked cached: cached=%v age=%v", r2.Cached, r2.CachedAgeSeconds)
	}
	if r2.Verdict != "clean" || r2.Components != r1.Components {
		t.Errorf("cached report differs from the live one: %+v vs %+v", r2, r1)
	}

	third, r3 := scan("third", "--no-cache")
	if got := posts.Load(); got != 2 {
		t.Errorf("--no-cache did not reach the API (%d requests)", got)
	}
	if strings.Contains(third.stderr, "reused") || r3.Cached {
		t.Errorf("--no-cache run reported a reused verdict\nstderr: %s", third.stderr)
	}
}

// A passive scan of an SBOM already sent within the TTL is not sent again,
// and the "Scan submitted" line stays off stdout because nothing was.
func TestCacheSecondPassiveScanIsNotSent(t *testing.T) {
	srv, posts := countingStub(t)
	env := cacheEnv(t)
	pkgDir := filepath.Join(fixturesDir(t), "npm_simple_math")

	passive := func() runResult {
		t.Helper()
		res := runRawEnv(t, env, "scan", pkgDir, "--passive", "--url", srv.URL,
			"--api-key", "test-key", "--no-version-lookup")
		if res.exitCode != 0 {
			t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
		}
		return res
	}

	first := passive()
	assertContains(t, first.stdout, "Scan submitted")
	if got := posts.Load(); got != 1 {
		t.Fatalf("first passive scan made %d requests, want 1", got)
	}

	second := passive()
	if got := posts.Load(); got != 1 {
		t.Errorf("second identical passive scan reached the API (%d requests)", got)
	}
	if strings.Contains(second.stdout, "Scan submitted") {
		t.Errorf("a deduplicated post claimed a submission:\n%s", second.stdout)
	}
	assertContains(t, second.stderr, "identical scan already sent")
}

// OSSPREY_SCAN_CACHE_TTL=0 turns the cache off for reads and writes alike.
func TestCacheDisabledByTTL(t *testing.T) {
	srv, posts := countingStub(t)
	env := append(cacheEnv(t), "OSSPREY_SCAN_CACHE_TTL=0")
	pkgDir := filepath.Join(fixturesDir(t), "npm_simple_math")

	for i := 0; i < 2; i++ {
		res := runRawEnv(t, env, "scan", pkgDir, "--url", srv.URL, "--api-key", "test-key", "--no-version-lookup")
		if res.exitCode != 0 {
			t.Fatalf("exit %d\nstderr: %s", res.exitCode, res.stderr)
		}
		if strings.Contains(res.stderr, "reused") {
			t.Errorf("run %d reused a verdict with the cache off:\n%s", i+1, res.stderr)
		}
	}
	if got := posts.Load(); got != 2 {
		t.Errorf("with the cache off, %d requests were made, want 2", got)
	}
}
