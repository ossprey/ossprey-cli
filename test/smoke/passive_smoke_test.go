//go:build smoke

package smoke

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const smokeMonitorID = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// stubAPI accepts a scan submission and records how it arrived.
type recordedRequest struct {
	path    string
	apiKey  string
	authHdr string
}

func stubAPI(t *testing.T, got *recordedRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/scans/status") {
			t.Errorf("a passive scan must not poll the status endpoint (path %s)", r.URL.Path)
		}
		got.path = r.URL.Path
		got.apiKey = r.Header.Get("x-api-key")
		got.authHdr = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"sbom_id": "sb1", "scan_id": "sc1"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runRaw invokes the built binary with exactly these arguments. The shared
// runOssprey helper prepends "scan <dir> --dry-run-safe", which would skip the
// API call these tests exist to observe.
func runRaw(t *testing.T, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
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

func npmProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	manifest := `{"name":"smoke","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A monitor submits over its own unauthenticated route. That it sends no
// credential is the whole reason the id is safe to hand out, so the real binary
// is what proves it.
func TestPassiveMonitorSubmitsWithNoCredential(t *testing.T) {
	var got recordedRequest
	srv := stubAPI(t, &got)
	dir := npmProject(t)

	res := runRaw(t, "scan", dir, "--monitor", smokeMonitorID,
		"--url", srv.URL, "--no-version-lookup")

	if res.exitCode != 0 {
		t.Fatalf("exit %d, want 0\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if want := "/ingest/" + smokeMonitorID + "/scans"; got.path != want {
		t.Errorf("posted to %q, want %q", got.path, want)
	}
	if got.apiKey != "" || got.authHdr != "" {
		t.Errorf("monitor submission carried a credential: x-api-key=%q authorization=%q", got.apiKey, got.authHdr)
	}
}

func TestPassiveScanExitsZeroAndPostsOnce(t *testing.T) {
	var got recordedRequest
	srv := stubAPI(t, &got)
	dir := npmProject(t)

	res := runRaw(t, "scan", dir, "--passive", "--url", srv.URL,
		"--api-key", "test-key", "--no-version-lookup")

	if res.exitCode != 0 {
		t.Fatalf("exit %d, want 0\nstderr: %s", res.exitCode, res.stderr)
	}
	if got.path != "/public/v1/scans" {
		t.Errorf("posted to %q, want /public/v1/scans", got.path)
	}
}

// A typo in a monitor id must be an error the user sees. Passive mode's
// fail-open would otherwise swallow it and report a scan that went nowhere.
func TestPassiveMonitorRejectsAMalformedID(t *testing.T) {
	dir := npmProject(t)

	res := runRaw(t, "scan", dir, "--monitor", "not-a-token", "--url", "http://127.0.0.1:1")

	if res.exitCode == 0 {
		t.Fatalf("a malformed monitor id was accepted\nstdout: %s", res.stdout)
	}
	if !strings.Contains(res.stderr, "invalid monitor id") {
		t.Errorf("stderr did not explain the bad id: %s", res.stderr)
	}
}
