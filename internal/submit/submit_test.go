package submit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// newSBOM builds a minimal SBOM with one component for submission tests.
func newSBOM() *ossbom.SBOM {
	s := ossbom.New(ossbom.Environment{})
	s.AddComponent(ossbom.Component{Name: "requests", Version: "2.31.0", Type: "pypi"})
	return s
}

func TestValidate_AppliesVulnerabilities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/v1/scans" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("missing/wrong x-api-key: %q", r.Header.Get("x-api-key"))
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[{"id":"V1","purl":"pkg:pypi/requests@2.31.0","type":"Malware","reference":"X"}]}`)
	}))
	defer srv.Close()

	sbom := newSBOM()
	if err := Validate(context.Background(), sbom, srv.URL, "test-key"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(sbom.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities: got %d, want 1", len(sbom.Vulnerabilities))
	}
	if sbom.Vulnerabilities[0].ID != "V1" {
		t.Errorf("vuln id: got %q, want V1", sbom.Vulnerabilities[0].ID)
	}
}

func TestValidate_NoVulnerabilities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	sbom := newSBOM()
	if err := Validate(context.Background(), sbom, srv.URL, "test-key"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(sbom.Vulnerabilities) != 0 {
		t.Errorf("vulnerabilities: got %d, want 0", len(sbom.Vulnerabilities))
	}
}

func TestValidate_APIKeyFromEnv(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	// empty apiKey arg and no stored login -> falls back to OSSPREY_API_KEY
	t.Setenv("OSSPREY_API_KEY", "env-key")
	t.Setenv("API_KEY", "")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())

	if err := Validate(context.Background(), newSBOM(), srv.URL, ""); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if gotKey != "env-key" {
		t.Errorf("x-api-key: got %q, want env-key", gotKey)
	}
}

func TestValidate_StoredLoginBeatsEnvKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dashboard/v1/scans" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer at-stored" {
			t.Errorf("Authorization: got %q, want Bearer at-stored", got)
		}
		if got := r.Header.Get("x-api-key"); got != "" {
			t.Errorf("unexpected x-api-key header: %q", got)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	// Both an env API key and a stored login present -> the JWT login wins.
	t.Setenv("OSSPREY_API_KEY", "env-key")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	if err := auth.Save(&auth.Credentials{
		AccessToken: "at-stored",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := Validate(context.Background(), newSBOM(), srv.URL, ""); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_EnvKeyFallbackWhenLoginBroken(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	// Stored login is expired with no refresh token (unrefreshable), but an
	// env key exists -> fall back to the key instead of failing the scan.
	t.Setenv("OSSPREY_API_KEY", "env-key")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	if err := auth.Save(&auth.Credentials{
		AccessToken: "at-stale",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := Validate(context.Background(), newSBOM(), srv.URL, ""); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if gotKey != "env-key" {
		t.Errorf("x-api-key: got %q, want env-key", gotKey)
	}
}

func TestValidate_NoCredentials(t *testing.T) {
	// no apiKey arg, no env vars and no stored login -> rejected with a hint
	// before any request. OSSPREY_CONFIG_DIR isolates the test from any real
	// login on the developer's machine.
	t.Setenv("OSSPREY_API_KEY", "")
	t.Setenv("API_KEY", "")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())

	err := Validate(context.Background(), newSBOM(), "https://api.test", "")
	if err == nil {
		t.Fatal("expected error when no credentials are available")
	}
	if !strings.Contains(err.Error(), "ossprey login") {
		t.Errorf("error should hint at `ossprey login`: %v", err)
	}
}

func TestValidate_StoredLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dashboard/v1/scans" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer at-stored" {
			t.Errorf("Authorization: got %q, want Bearer at-stored", got)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	t.Setenv("OSSPREY_API_KEY", "")
	t.Setenv("API_KEY", "")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	if err := auth.Save(&auth.Credentials{
		AccessToken: "at-stored",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := Validate(context.Background(), newSBOM(), srv.URL, ""); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_APIKeyBeatsStoredLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/v1/scans" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "flag-key" {
			t.Errorf("x-api-key: got %q, want flag-key", got)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	if err := auth.Save(&auth.Credentials{
		AccessToken: "at-stored",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := Validate(context.Background(), newSBOM(), srv.URL, "flag-key"); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"message":"boom"}`)
	}))
	defer srv.Close()

	sbom := newSBOM()
	if err := Validate(context.Background(), sbom, srv.URL, "test-key"); err == nil {
		t.Fatal("expected error on 500 response")
	}
	if len(sbom.Vulnerabilities) != 0 {
		t.Errorf("no vulns should be applied on error, got %d", len(sbom.Vulnerabilities))
	}
}

func TestPost_SubmitsWithoutPolling(t *testing.T) {
	var posted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			posted = true
			if r.Header.Get("x-api-key") != "test-key" {
				t.Errorf("missing/wrong x-api-key: %q", r.Header.Get("x-api-key"))
			}
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			t.Error("Post must not poll the status endpoint")
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	sbom := newSBOM()
	if err := Post(context.Background(), sbom, srv.URL, "test-key"); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if !posted {
		t.Error("Post never hit the scans endpoint")
	}
	if len(sbom.Vulnerabilities) != 0 {
		t.Errorf("Post must not apply a verdict; got %d vulnerabilities", len(sbom.Vulnerabilities))
	}
}

func TestPost_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if err := Post(context.Background(), newSBOM(), srv.URL, "test-key"); err == nil {
		t.Fatal("expected error, got nil")
	}
}
