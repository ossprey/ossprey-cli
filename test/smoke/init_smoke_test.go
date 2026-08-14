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
	// scanAuth records how each scan authenticated. An API-key client sends
	// x-api-key to /public/v1; a bearer client sends Authorization to
	// /dashboard/v1 — so this distinguishes "scanned with the new key" from
	// "scanned with the login", which is the whole point of step 3.
	scanAuth  []string
	scanMount []string
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
	// Both scan mounts are served: /public/v1 is where an API-key client goes,
	// /dashboard/v1 where a bearer (login) client goes. Registering both means a
	// test can assert which credential init actually used instead of failing with
	// an unhelpful 404.
	scanHandler := func(w http.ResponseWriter, r *http.Request) {
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

		// Record whichever credential arrived, tagged so a test can tell them
		// apart: an API key comes as x-api-key, a login as a bearer token.
		cred := "none"
		if k := r.Header.Get("x-api-key"); k != "" {
			cred = "api-key:" + k
		} else if a := r.Header.Get("Authorization"); a != "" {
			cred = a
		}
		mount := "/dashboard/v1"
		if strings.HasPrefix(r.URL.Path, "/public/v1") {
			mount = "/public/v1"
		}

		e.mu.Lock()
		e.scanAuth = append(e.scanAuth, cred)
		e.scanMount = append(e.scanMount, mount)
		e.scanPurls = append(e.scanPurls, purls)
		e.mu.Unlock()

		// Echo the submitted MiniBOM back untouched: a clean verdict.
		var echo struct {
			SBOM json.RawMessage `json:"sbom"`
		}
		json.Unmarshal(raw, &echo)
		w.WriteHeader(http.StatusOK)
		w.Write(echo.SBOM)
	}
	mux.HandleFunc("/public/v1/scans", scanHandler)
	mux.HandleFunc("/dashboard/v1/scans", scanHandler)

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

// TestInitFullFlow is the headline assertion: one command reuses the stored
// login, mints an API key with that login, then scans using the key it just
// created — all three steps, against a real HTTP server.
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
	keyNames, keyAuth := e.keyNames, e.keyAuth
	scanAuth, scanMount, scanPurls := e.scanAuth, e.scanMount, e.scanPurls
	e.mu.Unlock()

	if len(keyNames) != 1 {
		t.Fatalf("api-keys called %d times, want 1 (%v)", len(keyNames), keyNames)
	}
	if !strings.HasPrefix(keyNames[0], "ci-") {
		t.Errorf("generated key name %q missing ci- prefix", keyNames[0])
	}
	// Key creation must use the login: an API key cannot mint an API key.
	if keyAuth[0] != "Bearer smoke-access-token" {
		t.Errorf("api-keys auth: got %q, want the stored access token", keyAuth[0])
	}

	// Step 3: the scan must authenticate with the key just created, not the
	// login. That is what makes a clean scan proof the key actually works.
	if len(scanAuth) != 1 {
		t.Fatalf("scans called %d times, want 1", len(scanAuth))
	}
	if scanAuth[0] != "api-key:ospy_smoke_secret" {
		t.Errorf("scan credential: got %q, want the new API key", scanAuth[0])
	}
	if scanMount[0] != "/public/v1" {
		t.Errorf("scan mount: got %q, want /public/v1 (the API-key route)", scanMount[0])
	}
	assertContains(t, res.stdout, "Scanning with your new API key")

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

	// The workflow-file step is gone: init must not write into the project.
	if _, err := os.Stat(filepath.Join(e.projectDir, ".github")); !os.IsNotExist(err) {
		t.Errorf("init created .github in the project (err=%v); it should not write files", err)
	}
}

// TestInitIsRerunnable checks the re-run promise: a second run reuses the login,
// completes cleanly, and mints a second key (deliberately — keys are shown once,
// so re-running is how you get a replacement).
func TestInitIsRerunnable(t *testing.T) {
	e := newInitEnv(t, "main")
	if res := e.run(t); res.exitCode != 0 {
		t.Fatalf("first run: exit %d\n%s%s", res.exitCode, res.stdout, res.stderr)
	}

	res := e.run(t)
	if res.exitCode != 0 {
		t.Fatalf("second run: exit %d\n%s%s", res.exitCode, res.stdout, res.stderr)
	}
	assertContains(t, res.stdout, "Already logged in as smoke@example.com")

	e.mu.Lock()
	keyNames, scans := e.keyNames, len(e.scanAuth)
	e.mu.Unlock()

	if len(keyNames) != 2 {
		t.Fatalf("want 2 keys across 2 runs, got %d (%v)", len(keyNames), keyNames)
	}
	if keyNames[0] == keyNames[1] {
		t.Errorf("both runs used the same key name %q; names must be fresh", keyNames[0])
	}
	if scans != 2 {
		t.Errorf("want 2 scans across 2 runs, got %d", scans)
	}
}

// TestInitKeyFailureIsNonFatal pins the fail-open decision: if the API refuses
// to mint a key, init still runs the scan — falling back to the login, since
// there is no key to scan with — because the scan is the value the user came for.
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
	assertContains(t, res.stdout, "No malware found")

	e.mu.Lock()
	scanAuth, scanMount := e.scanAuth, e.scanMount
	e.mu.Unlock()

	if len(scanAuth) != 1 {
		t.Fatalf("scan submitted %d times, want 1", len(scanAuth))
	}
	// No key exists, so the scan must fall back to the stored login.
	if scanAuth[0] != "Bearer smoke-access-token" {
		t.Errorf("scan credential: got %q, want the stored login as fallback", scanAuth[0])
	}
	if scanMount[0] != "/dashboard/v1" {
		t.Errorf("scan mount: got %q, want /dashboard/v1 (the bearer route)", scanMount[0])
	}
}

// TestInitSkipFlags checks --no-scan suppresses exactly its own step, and that
// --key-name is honoured.
func TestInitSkipFlags(t *testing.T) {
	e := newInitEnv(t, "main")
	res := e.run(t, "--no-scan", "--key-name", "smoke-key")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\n%s%s", res.exitCode, res.stdout, res.stderr)
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

// TestInitNoKeyScansWithLogin checks --no-key still scans, using the login.
func TestInitNoKeyScansWithLogin(t *testing.T) {
	e := newInitEnv(t, "main")
	res := e.run(t, "--no-key")
	if res.exitCode != 0 {
		t.Fatalf("exit %d\n%s%s", res.exitCode, res.stdout, res.stderr)
	}

	e.mu.Lock()
	keys, scanAuth := len(e.keyNames), e.scanAuth
	e.mu.Unlock()

	if keys != 0 {
		t.Errorf("--no-key still created %d keys", keys)
	}
	if len(scanAuth) != 1 {
		t.Fatalf("want 1 scan, got %d", len(scanAuth))
	}
	if scanAuth[0] != "Bearer smoke-access-token" {
		t.Errorf("scan credential: got %q, want the stored login", scanAuth[0])
	}
	assertContains(t, res.stdout, "No malware found")
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
