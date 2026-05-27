package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		key     string
		wantErr bool
		wantURL string
	}{
		{name: "missing key", url: "https://api.test", key: "", wantErr: true},
		{name: "ok with explicit url", url: "https://api.test", key: "k", wantURL: "https://api.test"},
		{name: "default url when empty", url: "", key: "k", wantURL: "https://api.ossprey.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(tt.url, tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err: got %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if c.BaseURL != tt.wantURL {
				t.Errorf("BaseURL: got %q, want %q", c.BaseURL, tt.wantURL)
			}
			if c.APIKey != tt.key {
				t.Errorf("APIKey: got %q, want %q", c.APIKey, tt.key)
			}
		})
	}
}

// testClient returns a Client wired to the given httptest.Server, with the
// polling backoff shortened so the suite runs in milliseconds.
func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(srv.URL, "test-key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.HTTP = srv.Client()
	c.HTTP.Timeout = 5 * time.Second
	c.PollBackoff = func(int) time.Duration { return time.Millisecond }
	return c
}

func TestValidate_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/v1/scans" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "test-key" {
			t.Errorf("missing/wrong x-api-key header: %q", r.Header.Get("x-api-key"))
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[{"id":"V1","purl":"pkg:pypi/foo@1","type":"Malware","reference":"X"}]}`)
	}))
	defer srv.Close()

	c := testClient(t, srv)
	raw, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(string(raw), `"id":"V1"`) {
		t.Errorf("response body missing expected vuln: %s", raw)
	}
}

func TestValidate_202_Polling(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			n := hits.Add(1)
			if n < 2 {
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, `{"status":"RUNNING"}`)
				return
			}
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := testClient(t, srv)
	// Don't actually sleep i*i seconds in tests — swap HTTP client for the
	// real one anyway and let the timeout drive it. The default backoff loop
	// schedules first poll at 1s; we live with that small wait.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := c.Validate(ctx, ossbom.MiniBOM{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(string(raw), `"vulnerabilities"`) {
		t.Errorf("output body missing vulnerabilities key: %s", raw)
	}
	if got := hits.Load(); got < 2 {
		t.Errorf("expected >=2 status polls, got %d", got)
	}
}

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		wantErrIs error
		wantMatch string
	}{
		{
			name: "rate limited 429",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantMatch: "rate limit",
		},
		{
			name: "server error 500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"message":"boom"}`)
			},
			wantMatch: "status 500",
		},
		{
			name:      "skipped on status poll",
			handler:   skippedScanHandler(),
			wantMatch: "scan skipped",
		},
		{
			name:      "failed on status poll",
			handler:   failedScanHandler(),
			wantMatch: "scan blew up",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			c := testClient(t, srv)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err := c.Validate(ctx, ossbom.MiniBOM{})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantMatch != "" && !strings.Contains(err.Error(), tt.wantMatch) {
				t.Errorf("err: got %q, want substring %q", err.Error(), tt.wantMatch)
			}
		})
	}
}

func TestValidate_Skipped_TypedError(t *testing.T) {
	srv := httptest.NewServer(skippedScanHandler())
	defer srv.Close()

	c := testClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.Validate(ctx, ossbom.MiniBOM{})
	if err == nil {
		t.Fatal("expected error")
	}
	var skipped *ErrSkipped
	if !errors.As(err, &skipped) {
		t.Fatalf("expected ErrSkipped, got %T: %v", err, err)
	}
	if skipped.Message != "quota gone" {
		t.Errorf("Message: got %q, want %q", skipped.Message, "quota gone")
	}
	if skipped.ResetAt != "2026-05-27T00:00:00Z" {
		t.Errorf("ResetAt: got %q, want %q", skipped.ResetAt, "2026-05-27T00:00:00Z")
	}
}

func skippedScanHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"status":"SKIPPED","message":"quota gone","reset_at":"2026-05-27T00:00:00Z"}`)
		}
	}
}

func failedScanHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"status":"FAILED","message":"scan blew up"}`)
		}
	}
}
