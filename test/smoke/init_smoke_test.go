//go:build smoke

package smoke

import (
	"encoding/base64"
	"encoding/json"
	"io"
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

// initEnv is a scratch environment for `ossprey init`: a project directory, a
// config dir holding a pre-seeded login (so the device flow is skipped), and a
// stub API that records what the CLI sent it.
type initEnv struct {
	projectDir string
	configDir  string
	server     *httptest.Server

	mu       sync.Mutex
	keyNames []string
	keyAuth  []string
	scanAuth []string
	// scanPurls records the components of each submitted SBOM, so a test can
	// prove init actually catalogued and sent the project's dependency rather
	// than posting an empty SBOM.
	scanPurls [][]string
	// keyStatus, when non-zero, is returned by the api-keys endpoint instead
	// of 201, to exercise the fail-open path.
	keyStatus int
}

func newInitEnv(t *testing.T, branch string) *initEnv {
	t.Helper()
	e := &initEnv{
		projectDir: t.TempDir(),
		configDir:  t.TempDir(),
	}

	// A minimal JS project so the catalog finds a component.
	manifest := `{"name":"init-smoke","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`
	if err := os.WriteFile(filepath.Join(e.projectDir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	gitInit(t, e.projectDir, branch)
	e.seedLogin(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard/v1/api-keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("api-keys: got %s, want POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)

		e.mu.Lock()
		e.keyNames = append(e.keyNames, body["name"])
		e.keyAuth = append(e.keyAuth, r.Header.Get("Authorization"))
		status := e.keyStatus
		e.mu.Unlock()

		if status != 0 {
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"message": "stub failure"})
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"id":      "key-smoke",
			"api_key": "ospy_smoke_secret",
			"name":    body["name"],
			"created": time.Now().UTC().Format(time.RFC3339),
			"expiry":  body["expiry"],
		})
	})
	mux.HandleFunc("/dashboard/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("scans: got %s, want POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			SBOM struct {
				Components []struct {
					Purl string `json:"purl"`
				} `json:"components"`
			} `json:"sbom"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Errorf("scans: undecodable body: %v", err)
		}

		purls := make([]string, 0, len(payload.SBOM.Components))
		for _, c := range payload.SBOM.Components {
			purls = append(purls, c.Purl)
		}

		e.mu.Lock()
		e.scanAuth = append(e.scanAuth, r.Header.Get("Authorization"))
		e.scanPurls = append(e.scanPurls, purls)
		e.mu.Unlock()

		// Echo the submitted MiniBOM back untouched: a clean verdict.
		var echo struct {
			SBOM json.RawMessage `json:"sbom"`
		}
		json.Unmarshal(raw, &echo)
		w.WriteHeader(http.StatusOK)
		w.Write(echo.SBOM)
	})
	e.server = httptest.NewServer(mux)
	t.Cleanup(e.server.Close)
	return e
}

func gitInit(t *testing.T, dir, branch string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	for _, args := range [][]string{
		{"init", "--initial-branch=" + branch},
		{"config", "user.email", "smoke@example.com"},
		{"config", "user.name", "smoke"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v (%s)", args, err, out)
		}
	}
}

// seedLogin writes a credentials file with a non-expired access token. The ID
// token payload is display-only (never signature-verified), so an unsigned
// hand-rolled JWT suffices.
func (e *initEnv) seedLogin(t *testing.T) {
	t.Helper()
	e.seedLoginAs(t, stubDomain, stubClientID, stubAudience)
}

// seedLoginAs writes stored credentials for an explicit tenant triple, so a test
// can vary exactly one of domain/client-id/audience and prove that field alone
// participates in the reuse decision.
func (e *initEnv) seedLoginAs(t *testing.T, domain, clientID, audience string) {
	t.Helper()
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"email":"smoke@example.com","sub":"auth0|smoke"}`))
	creds := map[string]any{
		"domain":        domain,
		"client_id":     clientID,
		"audience":      audience,
		"access_token":  "smoke-access-token",
		"refresh_token": "smoke-refresh-token",
		"id_token":      "e30." + payload + ".sig",
		"expires_at":    time.Now().Add(time.Hour).Format(time.RFC3339),
	}
	data, err := json.Marshal(creds)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.configDir, "credentials.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// stubDomain/stubAudience must match the seeded credentials: init refuses to
// reuse a login belonging to a different tenant, so passing these keeps the test
// on the stored token instead of launching a real device-flow login.
const (
	stubDomain   = "auth.example.com"
	stubClientID = "smoke-client"
	stubAudience = "https://api.example.com"
)

func (e *initEnv) run(t *testing.T, args ...string) runResult {
	t.Helper()
	full := append([]string{
		"init", e.projectDir,
		"--url", e.server.URL,
		"--auth0-domain", stubDomain,
		"--client-id", stubClientID,
		"--audience", stubAudience,
	}, args...)
	cmd := exec.Command(binPath, full...)
	cmd.Env = append(os.Environ(),
		"OSSPREY_CONFIG_DIR="+e.configDir,
		// Keep the catalog offline and deterministic.
		"OSSPREY_RESOLVE_LATEST=0",
	)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run ossprey init: %v\nstderr: %s", err, stderr.String())
		}
		code = ee.ExitCode()
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

func (e *initEnv) workflowPath() string {
	return filepath.Join(e.projectDir, ".github", "workflows", "ossprey.yml")
}

// TestInitFullFlow is the headline assertion: one command reuses the stored
// login, creates an API key with bearer auth, writes the workflow, and submits
// a real scan — all four steps, against a real HTTP server.
func TestInitFullFlow(t *testing.T) {
	e := newInitEnv(t, "trunk")
	res := e.run(t)

	if res.exitCode != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}

	// Step 1: the stored login was reused, not re-prompted.
	assertContains(t, res.stdout, "Already logged in as smoke@example.com")

	// Step 2: a key was created and its secret printed exactly once.
	assertContains(t, res.stdout, "ospy_smoke_secret")
	assertContains(t, res.stdout, "OSSPREY_API_KEY")
	if got := strings.Count(res.stdout, "ospy_smoke_secret"); got != 1 {
		t.Errorf("key secret printed %d times, want 1", got)
	}

	e.mu.Lock()
	keyNames, keyAuth, scanAuth, scanPurls := e.keyNames, e.keyAuth, e.scanAuth, e.scanPurls
	e.mu.Unlock()

	if len(keyNames) != 1 {
		t.Fatalf("api-keys called %d times, want 1 (%v)", len(keyNames), keyNames)
	}
	if !strings.HasPrefix(keyNames[0], "ci-") {
		t.Errorf("generated key name %q missing ci- prefix", keyNames[0])
	}
	if keyAuth[0] != "Bearer smoke-access-token" {
		t.Errorf("api-keys auth: got %q, want the stored access token", keyAuth[0])
	}

	// Step 3: the workflow exists and targets the repo's actual branch.
	wf, err := os.ReadFile(e.workflowPath())
	if err != nil {
		t.Fatalf("workflow not written: %v", err)
	}
	for _, want := range []string{"branches: ['trunk']", "secrets.OSSPREY_API_KEY", "ossprey scan ."} {
		assertContains(t, string(wf), want)
	}
	// The workflow must never embed the secret itself.
	if strings.Contains(string(wf), "ospy_") {
		t.Error("workflow file contains a literal key value")
	}

	// Step 4: the scan really was submitted, with the same bearer token.
	if len(scanAuth) != 1 {
		t.Fatalf("scans called %d times, want 1", len(scanAuth))
	}
	if scanAuth[0] != "Bearer smoke-access-token" {
		t.Errorf("scans auth: got %q", scanAuth[0])
	}
	// Not just "a scan happened" — the project's declared dependency must
	// actually be in the submitted SBOM, or init could post an empty one and
	// still print "No malware found".
	if len(scanPurls) != 1 {
		t.Fatalf("recorded %d submitted SBOMs, want 1", len(scanPurls))
	}
	var foundLeftPad bool
	for _, purl := range scanPurls[0] {
		if strings.Contains(purl, "left-pad") {
			foundLeftPad = true
		}
	}
	if !foundLeftPad {
		t.Errorf("submitted SBOM does not contain left-pad: %v", scanPurls[0])
	}
	assertContains(t, res.stdout, "No malware found")
}

// TestInitIsRerunnable checks the idempotency promise: a second run leaves an
// existing workflow file untouched and still completes cleanly.
func TestInitIsRerunnable(t *testing.T) {
	e := newInitEnv(t, "main")
	if res := e.run(t); res.exitCode != 0 {
		t.Fatalf("first run: exit %d\n%s%s", res.exitCode, res.stdout, res.stderr)
	}

	sentinel := "# hand-edited\n"
	if err := os.WriteFile(e.workflowPath(), []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}

	res := e.run(t)
	if res.exitCode != 0 {
		t.Fatalf("second run: exit %d\n%s%s", res.exitCode, res.stdout, res.stderr)
	}
	assertContains(t, res.stdout, "already exists; left untouched")

	got, err := os.ReadFile(e.workflowPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != sentinel {
		t.Errorf("re-run overwrote the hand-edited workflow: %q", got)
	}
}

// TestInitKeyFailureIsNonFatal pins the fail-open decision: if the API refuses
// to mint a key, init still writes the workflow and runs the scan, because the
// scan is the value the user came for.
func TestInitKeyFailureIsNonFatal(t *testing.T) {
	e := newInitEnv(t, "main")
	e.mu.Lock()
	e.keyStatus = http.StatusForbidden
	e.mu.Unlock()

	res := e.run(t)
	if res.exitCode != 0 {
		t.Fatalf("exit %d, want 0 (key failure must not abort)\nstdout: %s\nstderr: %s",
			res.exitCode, res.stdout, res.stderr)
	}
	assertContains(t, res.stderr, "could not create an API key")
	if _, err := os.Stat(e.workflowPath()); err != nil {
		t.Errorf("workflow not written after key failure: %v", err)
	}
	assertContains(t, res.stdout, "No malware found")

	e.mu.Lock()
	scans := len(e.scanAuth)
	e.mu.Unlock()
	if scans != 1 {
		t.Errorf("scan submitted %d times, want 1", scans)
	}
}

// TestInitSkipFlags checks --no-workflow / --no-scan suppress exactly their own
// steps and nothing else.
func TestInitSkipFlags(t *testing.T) {
	e := newInitEnv(t, "main")
	res := e.run(t, "--no-workflow", "--no-scan", "--key-name", "smoke-key")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\n%s%s", res.exitCode, res.stdout, res.stderr)
	}

	if _, err := os.Stat(e.workflowPath()); !os.IsNotExist(err) {
		t.Errorf("--no-workflow still wrote a workflow file (err=%v)", err)
	}

	e.mu.Lock()
	keyNames, scans := e.keyNames, len(e.scanAuth)
	e.mu.Unlock()

	if scans != 0 {
		t.Errorf("--no-scan still submitted %d scans", scans)
	}
	if len(keyNames) != 1 || keyNames[0] != "smoke-key" {
		t.Errorf("--key-name not honoured: %v", keyNames)
	}
}

// TestInitWorkflowOnlyNeedsNoCredentials pins the offline path: with both the
// key and the scan skipped there is nothing to authenticate, so `init` must
// write the workflow without a login. An empty config dir and an unreachable
// Auth0 domain prove no login was attempted.
func TestInitWorkflowOnlyNeedsNoCredentials(t *testing.T) {
	e := newInitEnv(t, "main")
	emptyCfg := t.TempDir() // no credentials.json

	cmd := exec.Command(binPath, "init", e.projectDir,
		"--no-key", "--no-scan",
		"--url", e.server.URL,
		"--auth0-domain", "127.0.0.1:9")
	cmd.Env = append(os.Environ(), "OSSPREY_CONFIG_DIR="+emptyCfg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("want success with no credentials, got %v:\n%s", err, out)
	}
	if !strings.Contains(string(out), "Skipping login") {
		t.Errorf("expected the login step to be skipped:\n%s", out)
	}
	if _, err := os.Stat(e.workflowPath()); err != nil {
		t.Errorf("workflow not written: %v", err)
	}
}

// TestInitRefusesForeignTenantLogin pins the tenant check: a login stored for
// one Auth0 tenant must not be reused when the flags name another. Pointing at a
// closed port proves a fresh device flow was attempted (and that no key was
// minted with the wrong token) without contacting a real Auth0.
// Each case varies exactly ONE of domain / client-id / audience, with the other
// two identical on both sides. That isolation is the point: a check that compared
// only the domain would still pass a case that changed domain *and* audience
// together, so the audience and client-id cases would prove nothing. The command
// always targets the closed port 127.0.0.1:9, so a fresh device-flow attempt
// fails visibly instead of reaching a real Auth0.
func TestInitRefusesForeignTenantLogin(t *testing.T) {
	const unreachable = "127.0.0.1:9"

	cases := []struct {
		field                     string
		storedDomain              string
		storedClientID            string
		storedAudience            string
		argDomain                 string
		argClientID               string
		argAudience               string
		wantDeviceFlowInterrupted bool
	}{
		{
			field:        "domain",
			storedDomain: "auth.stored.example.com", storedClientID: stubClientID, storedAudience: stubAudience,
			argDomain: unreachable, argClientID: stubClientID, argAudience: stubAudience,
			wantDeviceFlowInterrupted: true,
		},
		{
			field:        "client id",
			storedDomain: unreachable, storedClientID: "stored-app", storedAudience: stubAudience,
			argDomain: unreachable, argClientID: "a-different-app", argAudience: stubAudience,
			wantDeviceFlowInterrupted: true,
		},
		{
			field:        "audience",
			storedDomain: unreachable, storedClientID: stubClientID, storedAudience: "https://api.stored.example.com",
			argDomain: unreachable, argClientID: stubClientID, argAudience: "https://api.other.example.com",
			wantDeviceFlowInterrupted: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			e := newInitEnv(t, "main")
			e.seedLoginAs(t, tc.storedDomain, tc.storedClientID, tc.storedAudience)

			cmd := exec.Command(binPath, "init", e.projectDir,
				"--url", e.server.URL,
				"--auth0-domain", tc.argDomain,
				"--client-id", tc.argClientID,
				"--audience", tc.argAudience)
			cmd.Env = append(os.Environ(), "OSSPREY_CONFIG_DIR="+e.configDir)
			out, err := cmd.CombinedOutput()

			if err == nil {
				t.Fatalf("%s mismatch: want failure, got success:\n%s", tc.field, out)
			}
			if !strings.Contains(string(out), "Stored login is for") {
				t.Errorf("%s mismatch: no explanation in output:\n%s", tc.field, out)
			}
			if tc.wantDeviceFlowInterrupted && !strings.Contains(string(out), "device code") {
				t.Errorf("%s mismatch: expected a fresh device-flow attempt:\n%s", tc.field, out)
			}

			e.mu.Lock()
			keys, scans := len(e.keyNames), len(e.scanAuth)
			e.mu.Unlock()
			if keys != 0 || scans != 0 {
				t.Errorf("%s mismatch: used the stored token anyway (%d keys, %d scans)",
					tc.field, keys, scans)
			}
		})
	}
}

// TestInitRejectsMissingPath fails before touching the network when the project
// path does not exist.
func TestInitRejectsMissingPath(t *testing.T) {
	e := newInitEnv(t, "main")
	missing := filepath.Join(e.projectDir, "nope")

	cmd := exec.Command(binPath, "init", missing, "--url", e.server.URL,
		"--auth0-domain", stubDomain, "--client-id", stubClientID,
		"--audience", stubAudience)
	cmd.Env = append(os.Environ(), "OSSPREY_CONFIG_DIR="+e.configDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("want failure for a missing path, got success: %s", out)
	}
	if !strings.Contains(string(out), "project path") {
		t.Errorf("unhelpful error for missing path: %s", out)
	}

	e.mu.Lock()
	calls, scans := len(e.keyNames), len(e.scanAuth)
	e.mu.Unlock()
	if calls != 0 {
		t.Errorf("created %d keys despite an invalid path", calls)
	}
	if scans != 0 {
		t.Errorf("submitted %d scans despite an invalid path", scans)
	}
}
