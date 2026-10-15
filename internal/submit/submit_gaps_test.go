package submit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
)

const testMonitorID = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// isolate clears every credential source so a test sees only what it sets.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("OSSPREY_API_KEY", "")
	t.Setenv("API_KEY", "")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
}

func storeLogin(t *testing.T) {
	t.Helper()
	if err := auth.Save(&auth.Credentials{AccessToken: "at-stored", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

// A quota skip must reach the caller as a *client.ErrSkipped so main can exit 0
// instead of failing the build. The only route to SKIPPED is the status poll,
// which costs one default poll interval here (submit has no backoff seam).
func TestValidate_SkippedFlowsBackUnwrapped(t *testing.T) {
	if testing.Short() {
		t.Skip("waits one real poll interval")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			io.WriteString(w, `{"status":"SKIPPED","message":"quota gone","reset_at":"2026-11-01T00:00:00Z"}`)
		}
	}))
	defer srv.Close()

	sbom := newSBOM()
	err := Validate(context.Background(), sbom, srv.URL, "test-key")
	var skipped *client.ErrSkipped
	if !errors.As(err, &skipped) {
		t.Fatalf("err: got %T %v, want *client.ErrSkipped", err, err)
	}
	if skipped.ResetAt != "2026-11-01T00:00:00Z" {
		t.Errorf("ResetAt: got %q", skipped.ResetAt)
	}
	if len(sbom.Vulnerabilities) != 0 {
		t.Errorf("a skipped scan applied %d vulnerabilities", len(sbom.Vulnerabilities))
	}
}

// A monitor id wins over every other credential: falling back would file the
// scan under the wrong account and hide a typo.
func TestNewSubmitClient_MonitorWinsOutright(t *testing.T) {
	isolate(t)
	t.Setenv("OSSPREY_API_KEY", "env-key")
	storeLogin(t)

	c, err := NewSubmitClient(context.Background(), "https://api.test", "flag-key", testMonitorID)
	if err != nil {
		t.Fatalf("NewSubmitClient: %v", err)
	}
	if c.IngestToken != testMonitorID || c.APIKey != "" || c.BearerToken != "" {
		t.Errorf("client: ingest=%q apikey=%q bearer=%q, want the monitor id alone", c.IngestToken, c.APIKey, c.BearerToken)
	}
}

func TestNewSubmitClient_BadMonitorDoesNotFallBack(t *testing.T) {
	isolate(t)
	t.Setenv("OSSPREY_API_KEY", "env-key")
	storeLogin(t)

	for _, id := range []string{"ospi_typo", testMonitorID + "\n", strings.ToUpper(testMonitorID)} {
		c, err := NewSubmitClient(context.Background(), "https://api.test", "flag-key", id)
		if err == nil {
			t.Errorf("monitor %q: got a client (ingest=%q apikey=%q bearer=%q), want an error", id, c.IngestToken, c.APIKey, c.BearerToken)
		}
	}
}

func TestNewSubmitClient_NoMonitorUsesTheCredentialChain(t *testing.T) {
	isolate(t)
	c, err := NewSubmitClient(context.Background(), "https://api.test", "flag-key", "")
	if err != nil {
		t.Fatalf("NewSubmitClient: %v", err)
	}
	if c.APIKey != "flag-key" || c.IngestToken != "" {
		t.Errorf("client: apikey=%q ingest=%q, want the flag key", c.APIKey, c.IngestToken)
	}
}

// Post with a monitor id works on a machine with no login and no key, and sends
// no credential header at all.
func TestPost_MonitorUsesIngestRouteWithNoCredential(t *testing.T) {
	isolate(t)
	var path, key, authz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, key, authz = r.URL.Path, r.Header.Get("x-api-key"), r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	if err := Post(context.Background(), newSBOM(), srv.URL, "", testMonitorID); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if want := "/ingest/" + testMonitorID + "/scans"; path != want {
		t.Errorf("path: got %q, want %q", path, want)
	}
	if key != "" || authz != "" {
		t.Errorf("credential sent: x-api-key=%q authorization=%q", key, authz)
	}
}

// With no login, OSSPREY_API_KEY beats API_KEY, and API_KEY alone still works.
func TestNewClient_EnvKeyOrder(t *testing.T) {
	tests := []struct {
		ossprey, generic, want string
	}{
		{"specific", "generic", "specific"},
		{"", "generic", "generic"},
	}
	for _, tt := range tests {
		isolate(t)
		t.Setenv("OSSPREY_API_KEY", tt.ossprey)
		t.Setenv("API_KEY", tt.generic)
		c, err := NewClient(context.Background(), "https://api.test", "")
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if c.APIKey != tt.want || c.BearerToken != "" {
			t.Errorf("OSSPREY_API_KEY=%q API_KEY=%q: apikey=%q bearer=%q, want %q", tt.ossprey, tt.generic, c.APIKey, c.BearerToken, tt.want)
		}
	}
}

// A stored login that cannot be read is reported as such when no key can stand
// in, rather than as "not logged in" -- and an env key still rescues the scan.
func TestNewClient_UnreadableLogin(t *testing.T) {
	isolate(t)
	path, err := auth.Path()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = NewClient(context.Background(), "https://api.test", "")
	if err == nil || !strings.Contains(err.Error(), "stored login") {
		t.Fatalf("err: got %v, want one naming the stored login", err)
	}

	t.Setenv("API_KEY", "env-key")
	c, err := NewClient(context.Background(), "https://api.test", "")
	if err != nil {
		t.Fatalf("NewClient with env key: %v", err)
	}
	if c.APIKey != "env-key" {
		t.Errorf("apikey: got %q, want env-key", c.APIKey)
	}
}

// The --api-key flag is used verbatim and never consults the stored login,
// so a broken login file cannot fail a run that named its key.
func TestNewClient_FlagKeyIgnoresBrokenLogin(t *testing.T) {
	isolate(t)
	path, _ := auth.Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(context.Background(), "https://api.test", "flag-key")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.APIKey != "flag-key" {
		t.Errorf("apikey: got %q, want flag-key", c.APIKey)
	}
}

// A 401 under the stored login names the login as what to fix, not the key.
func TestValidate_RejectedLoginNamesTheLogin(t *testing.T) {
	isolate(t)
	t.Setenv("OSSPREY_API_KEY", "env-key")
	storeLogin(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := Validate(context.Background(), newSBOM(), srv.URL, "")
	if err == nil || !strings.Contains(err.Error(), "login rejected") {
		t.Fatalf("err: got %v, want the login message", err)
	}
}
