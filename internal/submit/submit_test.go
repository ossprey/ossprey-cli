package submit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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

	// empty apiKey arg -> falls back to OSSPREY_API_KEY env var
	t.Setenv("OSSPREY_API_KEY", "env-key")
	t.Setenv("API_KEY", "")

	if err := Validate(context.Background(), newSBOM(), srv.URL, ""); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if gotKey != "env-key" {
		t.Errorf("x-api-key: got %q, want env-key", gotKey)
	}
}

func TestValidate_MissingKey(t *testing.T) {
	// no apiKey arg and no env vars -> client.New rejects before any request
	t.Setenv("OSSPREY_API_KEY", "")
	t.Setenv("API_KEY", "")

	if err := Validate(context.Background(), newSBOM(), "https://api.test", ""); err == nil {
		t.Fatal("expected error when API key is absent")
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
