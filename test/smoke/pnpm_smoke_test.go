//go:build smoke

// End-to-end coverage for the pnpm forwarder against a *real* pnpm binary and a
// fake Ossprey API. The other forwarders are older and have been exercised by
// hand; pnpm arrived with the shim work, so it gets a test that actually runs
// installs rather than only asserting on its verb table (OSS-1566 review).
//
// Run with: go test -tags smoke -run TestPnpm -v ./test/smoke/...

package smoke

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// subprocessTimeout bounds every forwarder invocation. A broken recursion guard
// makes the shim re-enter itself forever, forking a process per hop; without a
// deadline that presents as a hung suite (and thousands of processes) instead of
// a failing test.
const subprocessTimeout = 90 * time.Second

// fakeAPI stands in for api.ossprey.com. It answers the submit POST with 200 and
// a MiniBOM-shaped body, which is the branch `client.Validate` returns directly.
type fakeAPI struct {
	*httptest.Server

	mu       sync.Mutex
	requests int
	purls    []string

	// malware, when non-empty, is returned as a malware finding against that purl.
	malware string
}

func newFakeAPI(t *testing.T, malware string) *fakeAPI {
	t.Helper()
	f := &fakeAPI{malware: malware}
	mux := http.NewServeMux()
	mux.HandleFunc("/public/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SBOM struct {
				Components []struct {
					Purl string `json:"purl"`
				} `json:"components"`
			} `json:"sbom"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		f.requests++
		for _, c := range body.SBOM.Components {
			f.purls = append(f.purls, c.Purl)
		}
		malware := f.malware
		f.mu.Unlock()

		resp := map[string]any{"components": []any{}, "vulnerabilities": []any{}}
		if malware != "" {
			resp["vulnerabilities"] = []map[string]string{{
				"id":        "OSSPREY-TEST-0001",
				"purl":      malware,
				"type":      "Malware",
				"reference": "https://ossprey.com/test",
			}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPI) stats() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests, append([]string(nil), f.purls...)
}

// pnpmBin locates a real pnpm, skipping the test when there isn't one.
func pnpmBin(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("pnpm")
	if err != nil {
		t.Skip("pnpm not installed; skipping the pnpm forwarder end-to-end test")
	}
	return path
}

// pnpmProject writes a minimal package.json (plus a "hello" script for the
// passthrough case) and returns the project directory.
func pnpmProject(t *testing.T, deps map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	manifest := map[string]any{
		"name":        "ossprey-pnpm-smoke",
		"version":     "1.0.0",
		"private":     true,
		"scripts":     map[string]string{"hello": "echo HELLO-FROM-PNPM-SCRIPT"},
		"description": "fixture",
	}
	if len(deps) > 0 {
		manifest["dependencies"] = deps
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// pnpmWorkspace writes a two-package pnpm workspace and returns its root. The
// `--filter <pkg>` form this enables is how monorepos install, and pnpm accepts
// that flag *before* the verb.
func pnpmWorkspace(t *testing.T) string {
	t.Helper()
	root := pnpmProject(t, nil)
	if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"),
		[]byte("packages:\n  - 'packages/*'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(root, "packages", "web")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"),
		[]byte(`{"name":"web","version":"1.0.0","private":true,`+
			`"scripts":{"hello":"echo HELLO-FROM-PNPM-SCRIPT"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// runForward invokes the built ossprey binary as a pnpm forwarder inside dir,
// pointed at the fake API. HOME is a scratch dir so the test never touches the
// developer's pnpm store or config.
func runForward(t *testing.T, dir, apiURL string, args ...string) runResult {
	t.Helper()
	home := t.TempDir()
	return runForwardEnv(t, dir, forwardEnv(home, apiURL, os.Getenv("PATH")), binPath, args...)
}

// forwardEnv is the environment a forwarded invocation runs under. HOME is a
// scratch dir so the test never touches the developer's pnpm store or config.
func forwardEnv(home, apiURL, path string) []string {
	return []string{
		"HOME=" + home,
		"PATH=" + path,
		"OSSPREY_API_URL=" + apiURL,
		"OSSPREY_API_KEY=test-key",
		// pnpm writes its store/state under HOME; keep it in the scratch dir.
		"PNPM_HOME=" + filepath.Join(home, ".pnpm"),
		"CI=1",
	}
}

func runForwardEnv(t *testing.T, dir string, env []string, bin string, args ...string) runResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), subprocessTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %s %v: %v\nstderr: %s", bin, args, err, stderr.String())
		}
		code = ee.ExitCode()
	}
	if ctx.Err() != nil {
		t.Fatalf("%s %v did not finish within %s — a recursion guard is probably broken\nstderr: %s",
			bin, args, subprocessTimeout, stderr.String())
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

func installed(dir, pkg string) bool {
	_, err := os.Stat(filepath.Join(dir, "node_modules", pkg))
	return err == nil
}

// TestPnpmForwardCleanInstall is the case that matters: a real `pnpm add` goes
// through the checker and then actually installs.
func TestPnpmForwardCleanInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmProject(t, nil)

	res := runForward(t, dir, api.URL, "pnpm", "add", "left-pad@1.3.0")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "no malware found, forwarding to pnpm") {
		t.Errorf("missing forward notice in stderr:\n%s", res.stderr)
	}
	if !installed(dir, "left-pad") {
		t.Error("pnpm did not install left-pad — the forward to the real pnpm failed")
	}
	if _, err := os.Stat(filepath.Join(dir, "pnpm-lock.yaml")); err != nil {
		t.Errorf("pnpm did not write a lockfile: %v", err)
	}

	reqs, purls := api.stats()
	if reqs != 1 {
		t.Errorf("expected exactly 1 API submit, got %d", reqs)
	}
	if len(purls) != 1 || purls[0] != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("wrong purl checked (pnpm must map to the npm ecosystem): %v", purls)
	}
}

// TestPnpmForwardBlocksMalware proves the block is real: non-zero exit and
// nothing installed on disk.
func TestPnpmForwardBlocksMalware(t *testing.T) {
	pnpmBin(t)

	api := newFakeAPI(t, "pkg:npm/left-pad@1.3.0")
	dir := pnpmProject(t, nil)

	res := runForward(t, dir, api.URL, "pnpm", "add", "left-pad@1.3.0")
	if res.exitCode != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "contains malware") {
		t.Errorf("no malware report in stderr:\n%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "blocked `pnpm add left-pad@1.3.0`") {
		t.Errorf("no block notice naming the pnpm command:\n%s", res.stderr)
	}
	if installed(dir, "left-pad") {
		t.Error("pnpm installed left-pad despite the malware verdict")
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); err == nil {
		t.Error("blocked install still created node_modules")
	}
}

// TestPnpmPassthroughNotAnInstall checks the non-install verbs reach pnpm
// untouched and cost no API call.
func TestPnpmPassthroughNotAnInstall(t *testing.T) {
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmProject(t, nil)

	res := runForward(t, dir, api.URL, "pnpm", "run", "hello")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stdout+res.stderr, "HELLO-FROM-PNPM-SCRIPT") {
		t.Errorf("pnpm run did not execute the script:\nstdout: %s\nstderr: %s", res.stdout, res.stderr)
	}
	if reqs, _ := api.stats(); reqs != 0 {
		t.Errorf("`pnpm run` should not call the API, got %d submits", reqs)
	}
}

// TestPnpmBareInstallScansManifest covers the OSS-1284 path for pnpm: no
// packages named, so the project manifest is scanned and its deps checked.
func TestPnpmBareInstallScansManifest(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmProject(t, map[string]string{"left-pad": "1.3.0"})

	res := runForward(t, dir, api.URL, "pnpm", "install")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "no packages named; scanning project manifest") {
		t.Errorf("bare `pnpm install` did not trigger a manifest scan:\n%s", res.stderr)
	}
	if !installed(dir, "left-pad") {
		t.Error("bare pnpm install did not install the declared dependency")
	}

	reqs, purls := api.stats()
	if reqs == 0 {
		t.Fatal("manifest scan made no API submit")
	}
	found := false
	for _, p := range purls {
		if strings.Contains(p, "left-pad") {
			found = true
		}
	}
	if !found {
		t.Errorf("scanned SBOM did not include the declared dependency: %v", purls)
	}
}

// TestPnpmBareInstallBlocksMalware makes sure the manifest-scan path can block
// too, not just report.
func TestPnpmBareInstallBlocksMalware(t *testing.T) {
	pnpmBin(t)

	api := newFakeAPI(t, "pkg:npm/left-pad@1.3.0")
	dir := pnpmProject(t, map[string]string{"left-pad": "1.3.0"})

	res := runForward(t, dir, api.URL, "pnpm", "install")
	if res.exitCode != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if installed(dir, "left-pad") {
		t.Error("blocked bare install still installed the dependency")
	}
}

// TestPnpmExitCodePropagates confirms a real pnpm failure is not swallowed into
// a success by the forwarder.
func TestPnpmExitCodePropagates(t *testing.T) {
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmProject(t, nil)

	res := runForward(t, dir, api.URL, "pnpm", "run", "no-such-script")
	if res.exitCode == 0 {
		t.Fatalf("expected pnpm's non-zero exit to propagate, got 0\nstdout: %s\nstderr: %s", res.stdout, res.stderr)
	}
}

// TestPnpmThroughShim is the configuration users actually get from
// `--override-package-managers`: a bare `pnpm` resolved off PATH to the shim,
// which must check, forward to the real pnpm, and not re-enter itself.
func TestPnpmThroughShim(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	realPnpm := pnpmBin(t)

	api := newFakeAPI(t, "")
	home := t.TempDir()
	dir := pnpmProject(t, nil)

	env := []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"OSSPREY_API_URL=" + api.URL,
		"OSSPREY_API_KEY=test-key",
		"PNPM_HOME=" + filepath.Join(home, ".pnpm"),
		"CI=1",
	}
	out, code := run(t, env, binPath, "shim", "install", "--managers", "pnpm")
	if code != 0 {
		t.Fatalf("shim install exited %d: %s", code, out)
	}
	shimDir := filepath.Join(home, ".ossprey", "shims")
	shimPath := filepath.Join(shimDir, "pnpm")
	if _, err := os.Stat(shimPath); err != nil {
		t.Fatalf("no pnpm shim written: %v", err)
	}

	// Front the shim dir on PATH, exactly as the profile block does, and invoke
	// the shim itself — the file PATH resolution would land on.
	shimPATH := shimDir + string(os.PathListSeparator) + filepath.Dir(realPnpm) +
		string(os.PathListSeparator) + os.Getenv("PATH")
	res := runForwardEnv(t, dir, forwardEnv(home, api.URL, shimPATH), shimPath, "add", "left-pad@1.3.0")
	if res.exitCode != 0 {
		t.Fatalf("pnpm through the shim exited %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	got := res.stdout + res.stderr
	if !strings.Contains(got, "no malware found, forwarding to pnpm") {
		t.Errorf("shim did not run the ossprey check:\n%s", got)
	}
	if !installed(dir, "left-pad") {
		t.Errorf("shim did not reach the real pnpm:\n%s", got)
	}
	if reqs, _ := api.stats(); reqs != 1 {
		t.Errorf("expected 1 API submit through the shim, got %d\n%s", reqs, got)
	}
	if n := strings.Count(got, "forwarding to pnpm"); n != 1 {
		t.Errorf("expected exactly one forward (no recursion), saw %d:\n%s", n, got)
	}
}

// TestPnpmWorkspaceFilterInstallIsChecked covers the workspace form, where the
// global flag comes before the verb: `pnpm --filter web add x`. This forwarded
// completely unchecked until the verb lookup learned to skip global flags.
func TestPnpmWorkspaceFilterInstallIsChecked(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "")
	root := pnpmWorkspace(t)

	res := runForward(t, root, api.URL, "pnpm", "--filter", "web", "add", "left-pad@1.3.0")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}

	reqs, purls := api.stats()
	if reqs != 1 {
		t.Fatalf("workspace install was not checked: %d API submits (want 1)", reqs)
	}
	if len(purls) != 1 || purls[0] != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("wrong purl checked: %v", purls)
	}
	if !installed(filepath.Join(root, "packages", "web"), "left-pad") {
		t.Error("pnpm did not install into the filtered workspace package")
	}
}

// TestPnpmWorkspaceFilterInstallBlocks proves the workspace form is not merely
// reported on but actually stopped.
func TestPnpmWorkspaceFilterInstallBlocks(t *testing.T) {
	pnpmBin(t)

	api := newFakeAPI(t, "pkg:npm/left-pad@1.3.0")
	root := pnpmWorkspace(t)

	res := runForward(t, root, api.URL, "pnpm", "--filter", "web", "add", "left-pad@1.3.0")
	if res.exitCode != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if installed(filepath.Join(root, "packages", "web"), "left-pad") {
		t.Error("blocked workspace install still installed the package")
	}
}

// TestPnpmWorkspaceRunStillPassesThrough is the guard against over-correcting:
// skipping global flags must not turn `pnpm --filter web run build` into an
// install, nor make `pnpm run add` an install of a package named "add".
func TestPnpmWorkspaceRunStillPassesThrough(t *testing.T) {
	pnpmBin(t)

	api := newFakeAPI(t, "")
	root := pnpmWorkspace(t)

	res := runForward(t, root, api.URL, "pnpm", "--filter", "web", "run", "hello")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if reqs, _ := api.stats(); reqs != 0 {
		t.Errorf("`pnpm --filter web run hello` should not be checked, got %d submits", reqs)
	}
}

// TestPnpmRunAutoInstallsUnchecked pins a KNOWN GAP rather than a guarantee.
//
// Unlike `npm run`, `pnpm run` installs the project's declared dependencies as a
// side effect when node_modules is missing — so packages reach the machine
// through a verb the forwarder deliberately passes through, and they are never
// checked. Closing it means scanning before every `pnpm run`, which puts a scan
// in front of every script invocation, so it is a product decision rather than a
// bug to quietly patch (see the PR discussion on OSS-1566).
//
// This test documents today's behaviour so the gap is tracked and so we notice
// if a future pnpm changes it. Flip the assertions when the gap is closed.
func TestPnpmRunAutoInstallsUnchecked(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmProject(t, map[string]string{"left-pad": "1.3.0"})

	res := runForward(t, dir, api.URL, "pnpm", "run", "hello")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}
	if reqs, _ := api.stats(); reqs != 0 {
		t.Errorf("`pnpm run` is a pass-through; expected 0 submits, got %d", reqs)
	}
	if !installed(dir, "left-pad") {
		t.Skip("this pnpm no longer auto-installs on `run` — the known gap may be closed; re-check the forwarder")
	}
	t.Log("KNOWN GAP: `pnpm run` installed left-pad without an Ossprey check")
}

// TestPnpmShimStripsOwnPathEntry isolates the first recursion guard: the shim
// script removes its own directory from PATH before exec'ing, so the child sees
// a PATH that cannot resolve back to the shim. Uses a stub pnpm that prints its
// PATH, and OSSPREY_SHIM_BYPASS to go straight to the exec.
func TestPnpmShimStripsOwnPathEntry(t *testing.T) {
	pnpmBin(t)

	home := t.TempDir()
	stubDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stubDir, "pnpm"),
		[]byte("#!/bin/sh\necho \"STUB-PNPM-PATH=$PATH\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	env := forwardEnv(home, "http://127.0.0.1:1", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if out, code := run(t, env, binPath, "shim", "install", "--managers", "pnpm"); code != 0 {
		t.Fatalf("shim install exited %d: %s", code, out)
	}
	shimDir := filepath.Join(home, ".ossprey", "shims")

	shimPATH := shimDir + string(os.PathListSeparator) + stubDir
	env = append(forwardEnv(home, "http://127.0.0.1:1", shimPATH), "OSSPREY_SHIM_BYPASS=1")
	res := runForwardEnv(t, t.TempDir(), env, filepath.Join(shimDir, "pnpm"), "add", "left-pad")
	if res.exitCode != 0 {
		t.Fatalf("bypassed shim exited %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}

	got := res.stdout + res.stderr
	if !strings.Contains(got, "STUB-PNPM-PATH=") {
		t.Fatalf("shim never reached the stub pnpm:\n%s", got)
	}
	childPATH := strings.TrimSpace(strings.SplitN(strings.SplitN(got, "STUB-PNPM-PATH=", 2)[1], "\n", 2)[0])
	for _, entry := range filepath.SplitList(childPATH) {
		if entry == shimDir {
			t.Errorf("shim left its own directory on the child's PATH (recursion guard broken): %s", childPATH)
		}
	}
}

// TestPnpmRefusesToExecAShim isolates the second recursion guard: even if the
// shim directory survives on PATH, ossprey itself refuses to exec any file
// carrying the shim marker rather than re-entering itself.
func TestPnpmRefusesToExecAShim(t *testing.T) {
	pnpmBin(t)

	api := newFakeAPI(t, "")
	home := t.TempDir()

	env := forwardEnv(home, api.URL, os.Getenv("PATH"))
	if out, code := run(t, env, binPath, "shim", "install", "--managers", "pnpm", "--all"); code != 0 {
		t.Fatalf("shim install exited %d: %s", code, out)
	}
	shimDir := filepath.Join(home, ".ossprey", "shims")

	// The shim is now the *only* pnpm reachable: a bare PATH with nothing else on
	// it. ossprey must error out instead of exec'ing the shim.
	env = forwardEnv(home, api.URL, shimDir)
	res := runForwardEnv(t, pnpmProject(t, nil), env, binPath, "pnpm", "add", "left-pad@1.3.0")
	if res.exitCode == 0 {
		t.Fatalf("expected a non-zero exit when only shims resolve\nstdout: %s\nstderr: %s", res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "resolves only to ossprey shims") {
		t.Errorf("expected the shim-only diagnostic, got:\n%s", res.stderr)
	}
}
