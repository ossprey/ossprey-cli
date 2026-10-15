package main

import (
	"bytes"
	"encoding/base64"
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
	"time"

	"github.com/ossprey/ossprey-cli/internal/auth"
)

// idToken builds an unsigned JWT whose claims carry email; Identity() decodes
// it for display only.
func idToken(email string) string {
	claims, _ := json.Marshal(map[string]string{"email": email})
	return "x." + base64.RawURLEncoding.EncodeToString(claims) + ".y"
}

// noBrowser empties PATH so openBrowser cannot launch anything during a test.
func noBrowser(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// fakeAuth0 serves the device-flow endpoints, approving on the first poll.
type fakeAuth0 struct {
	*httptest.Server
	deviceCalls atomic.Int32
}

func newFakeAuth0(t *testing.T, email string, verifyComplete bool) *fakeAuth0 {
	t.Helper()
	f := &fakeAuth0{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device/code":
			f.deviceCalls.Add(1)
			dc := map[string]any{
				"device_code": "dev-123", "user_code": "ABCD-EFGH",
				"verification_uri": "https://example.test/activate", "expires_in": 600, "interval": 1,
			}
			if verifyComplete {
				dc["verification_uri_complete"] = "https://example.test/activate?user_code=ABCD-EFGH"
			}
			_ = json.NewEncoder(w).Encode(dc)
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "fresh-token", "refresh_token": "r1", "id_token": idToken(email), "expires_in": 3600,
			})
		default:
			t.Errorf("unexpected auth path %s", r.URL.Path)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAuth0) config(domain string) auth.Config {
	return auth.Config{Domain: domain, ClientID: "app", Audience: "https://api.test", BaseURL: f.URL, PollInterval: time.Millisecond}
}

// --- runDeviceLogin / ensureLogin -------------------------------------------

func TestRunDeviceLoginPrintsCodeAndStoresTheLogin(t *testing.T) {
	isolateConfig(t)
	noBrowser(t)
	f := newFakeAuth0(t, "dev@example.com", false)

	var out bytes.Buffer
	creds, err := runDeviceLogin(t.Context(), &out, f.config("auth.test"))
	if err != nil {
		t.Fatalf("runDeviceLogin: %v", err)
	}
	got := out.String()
	for _, want := range []string{"ABCD-EFGH", "https://example.test/activate", "Open this URL in a browser"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q:\n%s", want, got)
		}
	}
	stored, err := auth.Load()
	if err != nil {
		t.Fatalf("login was not stored: %v", err)
	}
	if stored.AccessToken != creds.AccessToken || stored.Domain != "auth.test" || stored.ClientID != "app" {
		t.Errorf("stored = %+v", stored)
	}
}

// A valid login for the same tenant is reused with no network round trip.
func TestEnsureLoginReusesAMatchingLogin(t *testing.T) {
	isolateConfig(t)
	saveLogin(t, auth.Credentials{
		Domain: "auth.test", ClientID: "app", Audience: "https://api.test",
		AccessToken: "stored-token", IDToken: idToken("me@example.com"), ExpiresAt: time.Now().Add(time.Hour),
	})
	f := newFakeAuth0(t, "other@example.com", true)

	var out bytes.Buffer
	token, err := ensureLogin(t.Context(), &out, f.config("auth.test"))
	if err != nil {
		t.Fatal(err)
	}
	if token != "stored-token" {
		t.Errorf("token = %q, want the stored one", token)
	}
	if !strings.Contains(out.String(), "Already logged in as me@example.com.") {
		t.Errorf("out = %q", out.String())
	}
	if f.deviceCalls.Load() != 0 {
		t.Error("a matching login still started the device flow")
	}
}

// A login for another tenant is never reused, and the message names both
// tenants. All prompts go to out, never to stdout, so --key-stdout stays a
// clean pipe even when a login is needed.
func TestEnsureLoginForeignTenantLogsInAgainOnTheGivenWriter(t *testing.T) {
	isolateConfig(t)
	noBrowser(t)
	saveLogin(t, auth.Credentials{
		Domain: "auth.prod", ClientID: "prod-app", Audience: "https://api.prod",
		AccessToken: "prod-token", ExpiresAt: time.Now().Add(time.Hour),
	})
	f := newFakeAuth0(t, "qa@example.com", true)

	var out bytes.Buffer
	var token string
	var err error
	stdout := captureStdout(t, func() {
		token, err = ensureLogin(t.Context(), &out, f.config("auth.qa"))
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "fresh-token" {
		t.Errorf("token = %q: the foreign tenant's token was reused", token)
	}
	if stdout != "" {
		t.Errorf("login prompts leaked onto stdout: %q", stdout)
	}
	got := out.String()
	for _, want := range []string{
		"different Ossprey tenant (auth.prod, audience https://api.prod, client prod-app)",
		"this run targets auth.qa, audience https://api.test, client app",
		"https://example.test/activate?user_code=ABCD-EFGH",
		"Logged in as qa@example.com.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("out missing %q:\n%s", want, got)
		}
	}
	if stored, _ := auth.Load(); stored == nil || stored.Domain != "auth.qa" {
		t.Errorf("stored login not replaced: %+v", stored)
	}
}

// An expired login that cannot refresh falls through to a fresh device flow
// rather than telling the user to run another command.
func TestEnsureLoginUnrefreshableLoginStartsAFreshOne(t *testing.T) {
	isolateConfig(t)
	noBrowser(t)
	saveLogin(t, auth.Credentials{
		Domain: "auth.test", ClientID: "app", Audience: "https://api.test",
		AccessToken: "old", ExpiresAt: time.Now().Add(-time.Hour),
	})
	f := newFakeAuth0(t, "me@example.com", true)

	var out bytes.Buffer
	token, err := ensureLogin(t.Context(), &out, f.config("auth.test"))
	if err != nil {
		t.Fatal(err)
	}
	if token != "fresh-token" {
		t.Errorf("token = %q", token)
	}
	if !strings.Contains(out.String(), "could not be refreshed") {
		t.Errorf("out = %q", out.String())
	}
}

func TestDescribeTenant(t *testing.T) {
	if got := describeTenant("", "", ""); got != "unknown" {
		t.Errorf("all empty: %q", got)
	}
	if got := describeTenant("auth.x", "", "aud"); got != "auth.x, audience aud" {
		t.Errorf("no client id: %q", got)
	}
}

// --- whoami / logout ----------------------------------------------------------

func runAuthCmd(t *testing.T, name string) (string, error) {
	t.Helper()
	root := newRootCmd()
	root.PersistentPostRun = nil // no update notice
	root.SetArgs([]string{name})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	var err error
	out := captureStdout(t, func() { err = root.Execute() })
	return out, err
}

func TestWhoami(t *testing.T) {
	future := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	cases := []struct {
		name  string
		creds *auth.Credentials
		want  []string
		err   string
	}{
		{name: "not logged in", err: "not logged in: run `ossprey login`"},
		{name: "valid", creds: &auth.Credentials{Domain: "auth.test", AccessToken: "t", IDToken: idToken("me@example.com"), ExpiresAt: future},
			want: []string{"Logged in as me@example.com (auth.test)", "expires at " + future.Format(time.RFC3339)}},
		{name: "expired, refreshable", creds: &auth.Credentials{Domain: "auth.test", AccessToken: "t", RefreshToken: "r", ExpiresAt: time.Now().Add(-time.Hour)},
			want: []string{"(unknown identity)", "will refresh automatically"}},
		{name: "expired, not refreshable", creds: &auth.Credentials{Domain: "auth.test", AccessToken: "t", ExpiresAt: time.Now().Add(-time.Hour)},
			want: []string{"run `ossprey login` again"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			if tc.creds != nil {
				saveLogin(t, *tc.creds)
			}
			out, err := runAuthCmd(t, "whoami")
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%s", w, out)
				}
			}
		})
	}
}

// logout removes the stored login and is idempotent.
func TestLogoutRemovesTheLoginAndIsIdempotent(t *testing.T) {
	dir := isolateConfig(t)
	saveLogin(t, auth.Credentials{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)})

	for i := 0; i < 2; i++ {
		out, err := runAuthCmd(t, "logout")
		if err != nil {
			t.Fatalf("logout #%d: %v", i+1, err)
		}
		if out != "Logged out\n" {
			t.Errorf("logout #%d output = %q", i+1, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials.json")); !os.IsNotExist(err) {
		t.Errorf("credentials still present: %v", err)
	}
	if _, err := auth.Load(); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Errorf("after logout Load = %v", err)
	}
}

// --- init output ------------------------------------------------------------

// keyAPI serves POST /dashboard/v1/api-keys and records whether it was hit.
func keyAPI(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dashboard/v1/api-keys" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		hits.Add(1)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id": "k1", "api_key": "ospy_SECRET_VALUE", "name": body["name"], "expiry": body["expiry"],
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func storedDefaultLogin(t *testing.T) {
	t.Helper()
	for _, k := range []string{"OSSPREY_AUTH0_DOMAIN", "OSSPREY_AUTH0_CLIENT_ID", "OSSPREY_AUTH0_AUDIENCE"} {
		t.Setenv(k, "")
	}
	saveLogin(t, auth.Credentials{
		Domain: auth.DefaultDomain, ClientID: auth.DefaultClientID, Audience: auth.DefaultAudience,
		AccessToken: "stored-token", ExpiresAt: time.Now().Add(time.Hour),
	})
}

func runInit(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newInitCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

// The key is printed exactly once with the handling advice, and next steps
// point at CI only when there is a key to put there.
func TestInitPrintsTheKeyOnceAndNextSteps(t *testing.T) {
	isolateConfig(t)
	storedDefaultLogin(t)
	var hits atomic.Int32
	url := keyAPI(t, &hits)

	var stdout string
	var err error
	_ = captureStderr(t, func() { stdout, _, err = runInit(t, t.TempDir(), "--no-scan", "--url", url, "--key-name", "ci-test") })
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(stdout, "ospy_SECRET_VALUE"); n != 1 {
		t.Errorf("key printed %d times, want once:\n%s", n, stdout)
	}
	for _, want := range []string{
		`Created API key "ci-test"`,
		"cannot be retrieved later",
		"OSSPREY_API_KEY",
		"[3/3] Skipping scan (--no-scan)",
		"Next steps:",
		"Add `ossprey scan .` to your CI",
		"ossprey shim install",
		"ossprey precommit install",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("key endpoint hit %d times, want 1", hits.Load())
	}
}

func TestInitNoKeyCreatesNoKeyAndOmitsTheCIStep(t *testing.T) {
	isolateConfig(t)
	storedDefaultLogin(t)

	stdout, _, err := runInit(t, t.TempDir(), "--no-key", "--no-scan", "--url", unreachableAPI(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Skipping API key creation (--no-key)") {
		t.Errorf("stdout = %s", stdout)
	}
	if strings.Contains(stdout, "Add `ossprey scan .` to your CI") {
		t.Errorf("CI step offered with no key:\n%s", stdout)
	}
}

// --key-stdout: stdout carries the bare key and nothing else.
func TestInitKeyStdoutKeepsStdoutToTheKey(t *testing.T) {
	isolateConfig(t)
	storedDefaultLogin(t)
	var hits atomic.Int32
	url := keyAPI(t, &hits)

	var stdout, stderr string
	var err error
	_ = captureStderr(t, func() { stdout, stderr, err = runInit(t, t.TempDir(), "--key-stdout", "--url", url) })
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "ospy_SECRET_VALUE\n" {
		t.Errorf("stdout = %q, want only the key", stdout)
	}
	if !strings.Contains(stderr, "[3/3] Skipping scan (--key-stdout") || !strings.Contains(stderr, "written to stdout") {
		t.Errorf("stderr = %s", stderr)
	}
}

func TestInitRejectsAMissingPathBeforeLoggingIn(t *testing.T) {
	isolateConfig(t)
	_, _, err := runInit(t, filepath.Join(t.TempDir(), "nope"), "--no-scan", "--url", unreachableAPI(t))
	if err == nil || !strings.Contains(err.Error(), "project path") {
		t.Fatalf("err = %v", err)
	}
}
