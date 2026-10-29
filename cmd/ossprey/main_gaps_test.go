package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/update"
)

// --- helpers ---------------------------------------------------------------

// captureStdout swaps os.Stdout for a pipe; most verdict lines are printed
// there directly rather than through cobra's writer.
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
	defer func() {
		os.Stdout = orig
	}()
	fn()
	os.Stdout = orig
	w.Close()
	out := <-done
	r.Close()
	return out
}

// isolateConfig points every config read (credentials, trust) at an empty
// directory and clears the credential and mode env vars a developer may have.
func isolateConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	for _, k := range []string{
		"OSSPREY_API_KEY", "API_KEY", "OSSPREY_PASSIVE", "OSSPREY_CI_CACHE_SCAN_ONLY",
		"OSSPREY_MONITOR_ID", "OSSPREY_SKIP_CI", "OSSPREY_VERBOSE",
		"OSSPREY_TRUSTED_REGISTRIES", "OSSPREY_TRUSTED_NPM_SCOPES",
	} {
		t.Setenv(k, "")
	}
	return dir
}

// npmProject writes a lockfile-pinned npm project, which catalogues offline
// (no resolver runs when a lockfile is committed) to exactly one component.
func npmProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"package.json": `{"name":"fx","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`,
		"package-lock.json": `{"name":"fx","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{` +
			`"":{"name":"fx","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},` +
			`"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const leftPadPurl = "pkg:npm/left-pad@1.3.0"

// recordingAPI answers a submit with 200 and a MiniBOM body (the branch
// Validate returns without polling), flagging malware when set. It records the
// path and credential headers of every request.
type recordingAPI struct {
	*httptest.Server
	mu      sync.Mutex
	paths   []string
	apiKeys []string
	auths   []string
}

func newRecordingAPI(t *testing.T, malware string) *recordingAPI {
	t.Helper()
	a := &recordingAPI{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.paths = append(a.paths, r.URL.Path)
		a.apiKeys = append(a.apiKeys, r.Header.Get("x-api-key"))
		a.auths = append(a.auths, r.Header.Get("Authorization"))
		a.mu.Unlock()
		resp := map[string]any{"components": []any{}, "vulnerabilities": []any{}}
		if malware != "" {
			resp["vulnerabilities"] = []map[string]string{{
				"id": "OSSPREY-TEST-0001", "purl": malware, "type": "Malware", "reference": "https://ossprey.com/test",
			}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *recordingAPI) requests() (paths, apiKeys, auths []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.paths...), append([]string(nil), a.apiKeys...), append([]string(nil), a.auths...)
}

// unreachableAPI fails the test if anything reaches it.
func unreachableAPI(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// --- exit codes, through the real main() in a subprocess ---------------------

const mainHelperEnv = "OSSPREY_TEST_MAIN_ARGS"

// TestMainHelperProcess is not a test: runMain re-executes the test binary into
// it so main()'s os.Exit calls can be observed.
func TestMainHelperProcess(t *testing.T) {
	raw := os.Getenv(mainHelperEnv)
	if raw == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		fmt.Fprintln(os.Stderr, "bad helper args:", err)
		os.Exit(99)
	}
	updateNoticeFn = func(context.Context, update.NoticeOptions) error { return nil }
	os.Args = append([]string{"ossprey"}, args...)
	main()
	os.Exit(0)
}

type mainResult struct {
	code           int
	stdout, stderr string
}

func runMain(t *testing.T, dir string, env []string, args ...string) mainResult {
	t.Helper()
	raw, _ := json.Marshal(args)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainHelperProcess$")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"OSSPREY_CONFIG_DIR="+t.TempDir(),
		"OSSPREY_API_KEY=", "API_KEY=", "OSSPREY_PASSIVE=", "OSSPREY_CI_CACHE_SCAN_ONLY=",
		"OSSPREY_MONITOR_ID=", "OSSPREY_SKIP_CI=", "OSSPREY_VERBOSE=", "OSSPREY_API_URL=",
		"OSSPREY_TRUSTED_REGISTRIES=", "OSSPREY_TRUSTED_NPM_SCOPES=", "NO_COLOR=1",
	)
	cmd.Env = append(cmd.Env, env...)
	cmd.Env = append(cmd.Env, mainHelperEnv+"="+string(raw))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := mainResult{stdout: stdout.String(), stderr: stderr.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.code = ee.ExitCode()
	default:
		t.Fatalf("run helper: %v", err)
	}
	return res
}

// Exit 1 means malware and nothing else; 2 is any error. A network or auth
// failure that exits 1 reads as a detection in CI.
func TestMainExitCodes(t *testing.T) {
	project := npmProject(t)
	clean := newRecordingAPI(t, "")
	infected := newRecordingAPI(t, leftPadPurl)
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"message":"Unauthorized"}`)
	}))
	t.Cleanup(denied.Close)

	cases := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"dry-run malicious", []string{"scan", project, "--dry-run-malicious"}, 1, "Error: WARNING:", ""},
		{"dry-run safe", []string{"scan", project, "--dry-run-safe"}, 0, "No malware found", ""},
		{"clean verdict", []string{"scan", project, "--url", clean.URL, "--api-key", "k"}, 0, "No malware found", ""},
		{"malware verdict", []string{"scan", project, "--url", infected.URL, "--api-key", "k"}, 1, "left-pad:1.3.0 contains malware", ""},
		{"missing path is an error, not malware", []string{"scan", filepath.Join(project, "nope"), "--dry-run-safe"}, 2, "", "error:"},
		{"auth failure is an error, not malware", []string{"scan", project, "--url", denied.URL, "--api-key", "bad"}, 2, "", "error:"},
		{"check dry-run malicious", []string{"check", "-e", "npm", "left-pad@1.3.0", "--dry-run-malicious"}, 1, "Error: WARNING:", ""},
		{"check without ecosystem", []string{"check", "left-pad@1.3.0"}, 2, "", "--eco-system is required"},
		{"check malware verdict", []string{"check", "-e", "npm", "left-pad@1.3.0", "--url", infected.URL, "--api-key", "k"}, 1, "contains malware", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runMain(t, t.TempDir(), nil, tc.args...)
			if res.code != tc.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", res.code, tc.wantCode, res.stdout, res.stderr)
			}
			if tc.wantStdout != "" && !strings.Contains(res.stdout, tc.wantStdout) {
				t.Errorf("stdout missing %q:\n%s", tc.wantStdout, res.stdout)
			}
			if tc.wantStderr != "" && !strings.Contains(res.stderr, tc.wantStderr) {
				t.Errorf("stderr missing %q:\n%s", tc.wantStderr, res.stderr)
			}
		})
	}
}

// The report is written before os.Exit(1): a malware run is the one CI most
// needs it on.
func TestMainMalwareReportWrittenBeforeExit(t *testing.T) {
	infected := newRecordingAPI(t, leftPadPurl)
	report := filepath.Join(t.TempDir(), "report.json")

	res := runMain(t, t.TempDir(), nil, "scan", npmProject(t), "--url", infected.URL, "--api-key", "k", "--report", report)
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1\n%s%s", res.code, res.stdout, res.stderr)
	}
	r := readReport(t, report)
	if r.Verdict != scan.VerdictMalware || len(r.Findings) != 1 || r.Findings[0].Name != "left-pad" {
		t.Errorf("report = %+v, want a malware verdict naming left-pad", r)
	}
}

// A monitor id from the environment is validated before passive mode's
// fail-open can turn a typo into a warning on a scan that went nowhere.
func TestMainBadMonitorIDFromEnvFailsEvenWhenPassive(t *testing.T) {
	url := unreachableAPI(t)
	res := runMain(t, t.TempDir(), []string{"OSSPREY_PASSIVE=1", "OSSPREY_MONITOR_ID=ospi_TYPO"},
		"scan", npmProject(t), "--url", url)
	if res.code != 2 {
		t.Fatalf("exit = %d, want 2\n%s%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "invalid monitor id") {
		t.Errorf("stderr does not explain the id:\n%s", res.stderr)
	}
	if strings.Contains(res.stderr, "TYPO") {
		t.Errorf("the id was echoed unredacted:\n%s", res.stderr)
	}
}

// A forwarder blocks with exit 1 before the real manager runs.
func TestMainForwarderBlocksWithExitOne(t *testing.T) {
	infected := newRecordingAPI(t, leftPadPurl)
	bin := fakeManagerDir(t, "npm", 0)
	res := runMain(t, t.TempDir(), []string{
		"OSSPREY_API_URL=" + infected.URL, "OSSPREY_API_KEY=k", "PATH=" + bin,
	}, "npm", "install", "left-pad@1.3.0")
	if res.code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if strings.Contains(res.stdout+res.stderr, "FAKE-MANAGER-RAN") {
		t.Error("the real manager ran after a block")
	}
	if !strings.Contains(res.stderr, "Installation blocked") {
		t.Errorf("exit 1 without the block report:\n%s", res.stderr)
	}
}

// The real manager's own exit status is passed through untouched.
func TestMainForwarderPassesTheManagersExitCodeThrough(t *testing.T) {
	bin := fakeManagerDir(t, "npm", 3)
	res := runMain(t, t.TempDir(), []string{
		"OSSPREY_API_URL=" + unreachableAPI(t), "PATH=" + bin,
	}, "npm", "run", "build")
	if res.code != 3 {
		t.Fatalf("exit = %d, want the manager's 3\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout, "FAKE-MANAGER-RAN") {
		t.Errorf("the manager did not run:\n%s", res.stdout)
	}
}

// fakeManagerDir writes a stand-in package manager that prints a marker and
// exits with code.
func fakeManagerDir(t *testing.T, name string, code int) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		body := fmt.Sprintf("@echo FAKE-MANAGER-RAN\r\n@exit /b %d\r\n", code)
		if err := os.WriteFile(filepath.Join(dir, name+".cmd"), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	body := fmt.Sprintf("#!/bin/sh\necho FAKE-MANAGER-RAN\nexit %d\n", code)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// --- forwardResult / printSkipped (in-process branches) ---------------------

func TestForwardResultQuotaSkipIsSuccess(t *testing.T) {
	skipped := &client.ErrSkipped{Message: "Scan skipped due to quota exhaustion.", ResetAt: "2026-11-01T00:00:00Z"}
	var err error
	out := captureStdout(t, func() { err = forwardResult(fmt.Errorf("check: %w", skipped)) })
	if err != nil {
		t.Fatalf("a quota skip must exit 0, got %v", err)
	}
	want := "Ossprey scan skipped: Scan skipped due to quota exhaustion. Quota resets at 2026-11-01T00:00:00Z.\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestForwardResultOtherErrorsPropagate(t *testing.T) {
	if err := forwardResult(nil); err != nil {
		t.Errorf("nil -> %v", err)
	}
	boom := errors.New("registry exploded")
	if err := forwardResult(boom); !errors.Is(err, boom) {
		t.Errorf("a platform error must reach main (exit 2), got %v", err)
	}
}

func TestPrintSkippedOmitsResetWhenUnknown(t *testing.T) {
	out := captureStdout(t, func() {
		if _, ok := printSkipped(&client.ErrSkipped{Message: "nothing scannable"}); !ok {
			t.Error("printSkipped did not recognise the skip")
		}
		if _, ok := printSkipped(errors.New("other")); ok {
			t.Error("printSkipped claimed a plain error")
		}
	})
	if out != "Ossprey scan skipped: nothing scannable\n" {
		t.Errorf("stdout = %q", out)
	}
}

// --- quota skip through scan/check ------------------------------------------

func skippingAPI(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			io.WriteString(w, `{"status":"SKIPPED","message":"Quota exhausted.","reset_at":"2026-11-01T00:00:00Z"}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func readReport(t *testing.T, path string) scan.Report {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var r scan.Report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("decode report: %v\n%s", err, data)
	}
	return r
}

// A quota skip exits 0 so it cannot fail a build, but the report says
// "skipped", never "clean": nothing was checked.
func TestQuotaSkipExitsZeroAndReportsSkipped(t *testing.T) {
	isolateConfig(t)
	url := skippingAPI(t)

	for _, tc := range []struct {
		name string
		run  func(report string) error
	}{
		{"scan", func(report string) error {
			return runScan(t, npmProject(t), "--url", url, "--api-key", "k", "--report", report)
		}},
		{"check", func(report string) error {
			return runCheck(t, "-e", "npm", "left-pad@1.3.0", "--url", url, "--api-key", "k", "--report", report)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := filepath.Join(t.TempDir(), "report.json")
			var err error
			out := captureStdout(t, func() { err = tc.run(report) })
			if err != nil {
				t.Fatalf("a quota skip must exit 0, got %v", err)
			}
			if !strings.Contains(out, "Ossprey scan skipped: Quota exhausted. Quota resets at 2026-11-01T00:00:00Z.") {
				t.Errorf("stdout = %q", out)
			}
			if strings.Contains(out, "No malware found") {
				t.Errorf("a skipped scan claimed to be clean:\n%s", out)
			}
			r := readReport(t, report)
			if r.Verdict != scan.VerdictSkipped || r.Skipped == nil || r.Skipped.ResetAt != "2026-11-01T00:00:00Z" {
				t.Errorf("report = %+v, want verdict skipped with reset_at", r)
			}
		})
	}
}

// --- scan flag combinations --------------------------------------------------

// --local owns stdout and never reaches a verdict, so --report is refused and
// nothing is written for CI to read as clean.
func TestScanLocalRefusesReport(t *testing.T) {
	isolateConfig(t)
	report := filepath.Join(t.TempDir(), "report.json")
	err := runScan(t, npmProject(t), "--local", "--report", report)
	if err == nil || !strings.Contains(err.Error(), "--local and --report") {
		t.Fatalf("err = %v, want the --local/--report refusal", err)
	}
	if _, statErr := os.Stat(report); !os.IsNotExist(statErr) {
		t.Errorf("a refused run left a report behind: %v", statErr)
	}
}

// A monitor implies passive, so typing --monitor with --report is the same
// contradiction as --passive --report.
func TestScanMonitorFlagRefusesReport(t *testing.T) {
	isolateConfig(t)
	report := filepath.Join(t.TempDir(), "report.json")
	err := runScan(t, t.TempDir(), "--monitor", validMonitorID, "--report", report, "--url", unreachableAPI(t))
	if err == nil {
		t.Fatal("--monitor --report was accepted")
	}
}

// From the environment it is somebody else's pipeline setting: warn, write no
// report, and carry on.
func TestScanMonitorFromEnvDropsReportWithAWarning(t *testing.T) {
	isolateConfig(t)
	api := newRecordingAPI(t, "")
	t.Setenv("OSSPREY_MONITOR_ID", validMonitorID)
	report := filepath.Join(t.TempDir(), "report.json")

	stderr := captureStderr(t, func() {
		if err := runScan(t, npmProject(t), "--url", api.URL, "--report", report); err != nil {
			t.Errorf("scan: %v", err)
		}
	})
	if _, err := os.Stat(report); err == nil {
		t.Error("a passive scan wrote a report")
	}
	if !strings.Contains(stderr, "no report was written") {
		t.Errorf("no warning about the dropped report:\n%s", stderr)
	}
	paths, _, _ := api.requests()
	if len(paths) != 1 || paths[0] != "/ingest/"+validMonitorID+"/scans" {
		t.Errorf("requests = %v, want one ingest submission", paths)
	}
}

// A dry run never touches the API, even with passive set in the environment.
func TestScanDryRunNeverSubmitsEvenWhenPassive(t *testing.T) {
	isolateConfig(t)
	t.Setenv("OSSPREY_PASSIVE", "1")
	url := unreachableAPI(t)
	for _, flag := range []string{"--dry-run-safe", "--dry-run-malicious"} {
		stderr := captureStderr(t, func() {
			_ = captureStdout(t, func() {
				if err := runScan(t, npmProject(t), flag, "--url", url); err != nil {
					t.Errorf("%s: %v", flag, err)
				}
			})
		})
		if !strings.Contains(stderr, "dry run, so no scan was submitted") {
			t.Errorf("%s: no warning that passive had no effect:\n%s", flag, stderr)
		}
	}
}

// Dry runs need no key and no backend.
func TestScanDryRunSafeNeedsNoCredentials(t *testing.T) {
	isolateConfig(t)
	out := filepath.Join(t.TempDir(), "sbom.json")
	stdout := captureStdout(t, func() {
		if err := runScan(t, npmProject(t), "--dry-run-safe", "--url", unreachableAPI(t), "-o", out); err != nil {
			t.Errorf("scan --dry-run-safe: %v", err)
		}
	})
	if !strings.Contains(stdout, "No malware found") {
		t.Errorf("stdout = %q", stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("-o did not write the SBOM: %v", err)
	}
	if !strings.Contains(string(data), `"left-pad"`) {
		t.Errorf("SBOM file missing the component:\n%s", data)
	}
}

// --local writes nothing but the OSSBOM to stdout, and needs no credentials.
func TestScanLocalStdoutIsOnlyTheSBOM(t *testing.T) {
	isolateConfig(t)
	var err error
	stdout := captureStdout(t, func() { err = runScan(t, npmProject(t), "--local", "--url", unreachableAPI(t)) })
	if err != nil {
		t.Fatalf("scan --local: %v", err)
	}
	var doc map[string]any
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("stdout is not pure JSON: %v\n%s", jerr, stdout)
	}
}

// Credential order: --api-key, then a stored login, then OSSPREY_API_KEY, then
// API_KEY. Exercised through a passive submit, which needs no poll.
func TestScanCredentialResolutionOrder(t *testing.T) {
	cases := []struct {
		name       string
		flag       string
		envKey     string
		legacyKey  string
		login      bool
		wantPath   string
		wantAPIKey string
		wantBearer string
	}{
		{name: "flag beats env and login", flag: "from-flag", envKey: "from-env", login: true,
			wantPath: "/public/v1/scans", wantAPIKey: "from-flag"},
		{name: "login beats env", envKey: "from-env", legacyKey: "from-legacy", login: true,
			wantPath: "/dashboard/v1/scans", wantBearer: "Bearer stored-token"},
		{name: "OSSPREY_API_KEY beats API_KEY", envKey: "from-env", legacyKey: "from-legacy",
			wantPath: "/public/v1/scans", wantAPIKey: "from-env"},
		{name: "API_KEY alone", legacyKey: "from-legacy",
			wantPath: "/public/v1/scans", wantAPIKey: "from-legacy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			t.Setenv("OSSPREY_API_KEY", tc.envKey)
			t.Setenv("API_KEY", tc.legacyKey)
			if tc.login {
				saveLogin(t, auth.Credentials{AccessToken: "stored-token", ExpiresAt: time.Now().Add(time.Hour)})
			}
			api := newRecordingAPI(t, "")
			args := []string{"--passive", "--url", api.URL}
			if tc.flag != "" {
				args = append(args, "--api-key", tc.flag)
			}
			_ = captureStdout(t, func() {
				if err := runScan(t, npmProject(t), args...); err != nil {
					t.Errorf("scan: %v", err)
				}
			})
			paths, keys, auths := api.requests()
			if len(paths) != 1 {
				t.Fatalf("requests = %v, want 1", paths)
			}
			if paths[0] != tc.wantPath || keys[0] != tc.wantAPIKey || auths[0] != tc.wantBearer {
				t.Errorf("sent path=%q x-api-key=%q authorization=%q; want %q %q %q",
					paths[0], keys[0], auths[0], tc.wantPath, tc.wantAPIKey, tc.wantBearer)
			}
		})
	}
}

func saveLogin(t *testing.T, c auth.Credentials) {
	t.Helper()
	if err := auth.Save(&c); err != nil {
		t.Fatal(err)
	}
}

// --- git wrapper wiring --------------------------------------------------------

// Same contract as the package forwarders: a malformed monitor id is a
// configuration error, never swallowed by passive fail-open, never echoed.
func TestGitCmdRejectsAMalformedMonitorID(t *testing.T) {
	isolateConfig(t)
	t.Setenv("OSSPREY_MONITOR_ID", "ospi_TYPO")
	t.Setenv("OSSPREY_API_URL", unreachableAPI(t))
	cmd := newGitCmd()
	cmd.SetArgs([]string{"clone", "https://github.com/ossprey/example"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("a malformed OSSPREY_MONITOR_ID was accepted")
	}
	if strings.Contains(err.Error(), "TYPO") {
		t.Errorf("the id was echoed unredacted: %v", err)
	}
}

// --- update notice -----------------------------------------------------------

// Forwarders are silent by default: no "new version" notice after every
// install unless OSSPREY_VERBOSE asks; `update` itself never nags.
func TestNotifyLatestVersionRespectsQuietCommands(t *testing.T) {
	old := updateNoticeFn
	t.Cleanup(func() { updateNoticeFn = old })
	calls := 0
	updateNoticeFn = func(context.Context, update.NoticeOptions) error { calls++; return nil }

	cases := []struct {
		name    string
		cmd     *cobra.Command
		verbose string
		want    int
	}{
		{"ordinary command", &cobra.Command{Use: "scan"}, "", 1},
		{"update command", &cobra.Command{Use: "update"}, "", 0},
		{"forwarder, quiet", &cobra.Command{Use: "npm", DisableFlagParsing: true}, "", 0},
		{"forwarder, verbose", &cobra.Command{Use: "npm", DisableFlagParsing: true}, "1", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OSSPREY_VERBOSE", tc.verbose)
			calls = 0
			notifyLatestVersion(tc.cmd)
			if calls != tc.want {
				t.Errorf("notice calls = %d, want %d", calls, tc.want)
			}
		})
	}
}
