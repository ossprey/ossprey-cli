package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/monitor"
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

func TestNewBearer(t *testing.T) {
	if _, err := NewBearer("https://api.test", ""); err == nil {
		t.Error("expected error for empty token")
	}
	c, err := NewBearer("", "tok")
	if err != nil {
		t.Fatalf("NewBearer: %v", err)
	}
	if c.BaseURL != "https://api.ossprey.com" {
		t.Errorf("BaseURL: got %q", c.BaseURL)
	}
	if c.BearerToken != "tok" {
		t.Errorf("BearerToken: got %q", c.BearerToken)
	}
}

// TestValidate_Bearer checks that a bearer-token client hits the JWT-authorized
// /dashboard/v1 mount with an Authorization header (and no x-api-key), for both
// the submit and status-poll requests.
func TestValidate_Bearer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization: got %q, want Bearer tok", got)
		}
		if got := r.Header.Get("x-api-key"); got != "" {
			t.Errorf("unexpected x-api-key header: %q", got)
		}
		switch r.URL.Path {
		case "/dashboard/v1/scans":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/dashboard/v1/scans/status":
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c, err := NewBearer(srv.URL, "tok")
	if err != nil {
		t.Fatalf("NewBearer: %v", err)
	}
	c.HTTP = srv.Client()
	c.PollBackoff = func(int) time.Duration { return time.Millisecond }

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := c.Validate(ctx, ossbom.MiniBOM{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(string(raw), `"vulnerabilities"`) {
		t.Errorf("output body missing vulnerabilities key: %s", raw)
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

func TestSubmit_202_DoesNotPoll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public/v1/scans":
			if r.Header.Get("x-api-key") != "test-key" {
				t.Errorf("missing/wrong x-api-key header: %q", r.Header.Get("x-api-key"))
			}
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
		case "/public/v1/scans/status":
			t.Error("Submit must not poll the status endpoint")
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	c := testClient(t, srv)
	if err := c.Submit(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
}

func TestSubmit_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	if err := testClient(t, srv).Submit(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
}

func TestSubmit_Errors(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantMatch string
	}{
		{"rate limited 429", http.StatusTooManyRequests, "rate limit"},
		{"server error 500", http.StatusInternalServerError, "status 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			err := testClient(t, srv).Submit(context.Background(), ossbom.MiniBOM{})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantMatch) {
				t.Errorf("err: got %q, want substring %q", err.Error(), tt.wantMatch)
			}
		})
	}
}

const testIngestToken = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNewIngestRejectsAMalformedToken(t *testing.T) {
	// The token lands in a URL path, so a value carrying a slash or a query
	// character would silently retarget the request at another route.
	for _, token := range []string{
		"", "nope", "ospi_short",
		testIngestToken + "/../../dashboard/v1",
		testIngestToken + "?x=1",
		"ospi_" + strings.Repeat("z", 64),
	} {
		if _, err := NewIngest("https://api.test", token); err == nil {
			t.Errorf("NewIngest accepted %q", token)
		}
	}
}

func TestIngestClientPostsToTheIngestMountWithNoCredential(t *testing.T) {
	var gotPath, gotAPIKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("x-api-key")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
	defer srv.Close()

	c, err := NewIngest(srv.URL, testIngestToken)
	if err != nil {
		t.Fatalf("NewIngest: %v", err)
	}
	if err := c.Submit(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if want := "/ingest/" + testIngestToken + "/scans"; gotPath != want {
		t.Errorf("posted to %q, want %q", gotPath, want)
	}
	// An empty x-api-key would read as a malformed key rather than as no
	// credential, which is why authenticate returns early for this mode.
	if gotAPIKey != "" || gotAuth != "" {
		t.Errorf("ingest client sent a credential: x-api-key=%q authorization=%q", gotAPIKey, gotAuth)
	}
}

// A monitor id is submit-only. Refusing here means the caller gets a clear
// error instead of a 404 from a status route that was never meant to exist.
func TestIngestClientRefusesValidate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("Validate must not reach the network for an ingest client (path %s)", r.URL.Path)
	}))
	defer srv.Close()

	c, err := NewIngest(srv.URL, testIngestToken)
	if err != nil {
		t.Fatalf("NewIngest: %v", err)
	}
	if _, err := c.Validate(context.Background(), ossbom.MiniBOM{}); !errors.Is(err, ErrIngestSubmitOnly) {
		t.Fatalf("Validate() error = %v, want ErrIngestSubmitOnly", err)
	}
}

// The token is the whole credential and it travels in the URL path, so every
// *url.Error carries it -- into terminal scrollback and CI logs, on every
// install a proxy, DNS or TLS failure touches.
func TestIngestTransportErrorDoesNotCarryTheToken(t *testing.T) {
	// A port nothing listens on: a refused connection is the common case.
	c, err := NewIngest("http://127.0.0.1:1", testIngestToken)
	if err != nil {
		t.Fatalf("NewIngest: %v", err)
	}

	postErr := c.Submit(context.Background(), ossbom.MiniBOM{})

	if postErr == nil {
		t.Fatal("Post to a closed port returned no error")
	}
	if strings.Contains(postErr.Error(), testIngestToken) {
		t.Errorf("the monitor id reached an error message: %v", postErr)
	}
	if !strings.Contains(postErr.Error(), monitor.Prefix) {
		t.Errorf("the error names no monitor at all, so it cannot be debugged: %v", postErr)
	}
}

// testRetryClient is testClient with the submit backoff shortened too, so the
// retry tests never spend a real half-second asleep.
func testRetryClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c := testClient(t, srv)
	c.RetryBackoff = func(int) time.Duration { return time.Millisecond }
	return c
}

// TestPostScan_RetriesTransient checks that a gateway failure and a dropped
// connection are both retried rather than failing the scan with the same exit
// code as a malware detection.
func TestPostScan_RetriesTransient(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1) == 1 {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, `{"vulnerabilities":[]}`)
			}))
			defer srv.Close()

			c := testRetryClient(t, srv)
			if _, err := c.Validate(context.Background(), ossbom.MiniBOM{}); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if got := hits.Load(); got != 2 {
				t.Errorf("attempts: got %d, want 2", got)
			}
		})
	}
}

// TestPostScan_RetrySendsBodyAgain pins that the retried request carries the
// SBOM: bytes.NewReader is consumed by the first attempt, so a reader built
// once outside the loop would POST an empty body on every retry.
func TestPostScan_RetrySendsBodyAgain(t *testing.T) {
	var hits atomic.Int32
	var second string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		second = string(body)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	if _, err := c.Validate(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(second, `"sbom"`) {
		t.Errorf("retry body: got %q, want the sbom payload", second)
	}
}

// TestPostScan_RetryGivesUp checks the attempt budget is bounded and the last
// error survives.
func TestPostScan_RetryGivesUp(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	_, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "status 502") {
		t.Errorf("err: got %q, want the 502 to survive", err)
	}
	if got := hits.Load(); got != maxSubmitAttempts {
		t.Errorf("attempts: got %d, want %d", got, maxSubmitAttempts)
	}
}

// TestPostScan_DoesNotRetryDefiniteAnswers pins the fail-fast half: a 4xx, a
// 429 and a 500 are answers about the request, not blips, so repeating them
// only delays the same failure (and a 500 risks a duplicate scan on quota).
func TestPostScan_DoesNotRetryDefiniteAnswers(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(status)
			}))
			defer srv.Close()

			c := testRetryClient(t, srv)
			if _, err := c.Validate(context.Background(), ossbom.MiniBOM{}); err == nil {
				t.Fatal("expected error")
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("attempts: got %d, want 1", got)
			}
		})
	}
}

// TestPostScan_RetryRespectsContext checks a cancelled scan is not held alive
// by the backoff.
func TestPostScan_RetryRespectsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := testClient(t, srv)
	// Cancel from inside the backoff, not before the first request: cancelling
	// up front makes the very first Do fail and postScan never reaches the
	// sleep this test is about.
	c.RetryBackoff = func(int) time.Duration {
		cancel()
		return time.Hour
	}

	done := make(chan error, 1)
	go func() {
		_, err := c.Validate(ctx, ossbom.MiniBOM{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Validate slept past context cancellation")
	}
}

// TestAuthError checks 401 and 403 become an actionable message rather than a
// raw JSON body, on both the submit and the status poll, and that the wording
// names the credential the client actually used.
func TestAuthError(t *testing.T) {
	tests := []struct {
		name   string
		build  func(t *testing.T, url string) *Client
		want   string
		status int
	}{
		{
			name:   "api key 401",
			build:  func(t *testing.T, u string) *Client { return mustNew(t, u, "bad-key") },
			want:   "OSSPREY_API_KEY",
			status: http.StatusUnauthorized,
		},
		{
			name:   "api key 403",
			build:  func(t *testing.T, u string) *Client { return mustNew(t, u, "bad-key") },
			want:   "API key rejected (status 403)",
			status: http.StatusForbidden,
		},
		{
			name:   "bearer 401",
			build:  func(t *testing.T, u string) *Client { return mustNewBearer(t, u, "stale") },
			want:   "ossprey login",
			status: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				io.WriteString(w, `{"message":"Unauthorized","request_id":"abc"}`)
			}))
			defer srv.Close()

			c := tt.build(t, srv.URL)
			_, err := c.Validate(context.Background(), ossbom.MiniBOM{})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err: got %q, want substring %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "request_id") {
				t.Errorf("raw body leaked into the message: %q", err)
			}
		})
	}
}

func TestSkipMessage(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			// The API nests the reason under output, which is why the CLI used
			// to blame quota for every skipped scan.
			"nothing scannable",
			`{"skipped":true,"reason":"no_scannable_components","error_message":"No supported package ecosystems found in this SBOM. Skipped: 2 cargo. Supported ecosystems: pypi, npm."}`,
			"Scan skipped: nothing in this project is in an ecosystem Ossprey scans",
		},
		{
			"quota, which stores no message",
			`{"skipped":true,"reason":"usage_limit_exceeded"}`,
			"Scan skipped due to quota exhaustion",
		},
		{"no output at all", ``, "Scan skipped due to quota exhaustion"},
		{"unrecognised reason", `{"reason":"something_new"}`, "Scan skipped due to quota exhaustion"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := skipMessage([]byte(tt.output))
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			// The API's own text enumerates the ecosystems it skipped. That is
			// the platform's business, not something to print over a build.
			if strings.Contains(got, "cargo") || strings.Contains(got, "Supported ecosystems") {
				t.Errorf("the API's ecosystem list leaked into CLI output: %q", got)
			}
		})
	}
}

// TestAuthError_OnStatusPoll covers a key revoked between the submit and the
// poll: the poll must not retry it as if it were transient.
func TestAuthError_OnStatusPoll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	_, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err == nil || !strings.Contains(err.Error(), "API key rejected") {
		t.Fatalf("err: got %v, want the API key message", err)
	}
}

// TestPoll_TolerAtesTransientFailures checks a blip mid-poll costs a poll, not
// the verdict, and that the tolerance is bounded.
func TestPoll_ToleratesTransientFailures(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
			return
		}
		if hits.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	raw, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(string(raw), `"vulnerabilities"`) {
		t.Errorf("output: %s", raw)
	}
}

func TestPoll_GivesUpAfterRepeatedTransientFailures(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
			return
		}
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	_, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err == nil || !strings.Contains(err.Error(), "status poll failed (503)") {
		t.Fatalf("err: got %v, want the 503 to survive", err)
	}
	if got := hits.Load(); got != maxTransientPolls {
		t.Errorf("polls: got %d, want %d", got, maxTransientPolls)
	}
}

// TestPoll_AttemptBudget pins that maxPollAttempts polls actually happen. The
// loop used to stop at maxPollAttempts-1, so the documented 300 was really 299.
func TestPoll_AttemptBudget(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
			return
		}
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"status":"RUNNING"}`)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	c.PollBackoff = func(int) time.Duration { return 0 }
	_, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err == nil || !strings.Contains(err.Error(), "took too long") {
		t.Fatalf("err: got %v, want the poll ceiling", err)
	}
	if got := hits.Load(); got != maxPollAttempts {
		t.Errorf("polls: got %d, want %d", got, maxPollAttempts)
	}
}

func mustNew(t *testing.T, baseURL, key string) *Client {
	t.Helper()
	c, err := New(baseURL, key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.PollBackoff = func(int) time.Duration { return time.Millisecond }
	c.RetryBackoff = func(int) time.Duration { return time.Millisecond }
	return c
}

func mustNewBearer(t *testing.T, baseURL, token string) *Client {
	t.Helper()
	c, err := NewBearer(baseURL, token)
	if err != nil {
		t.Fatalf("NewBearer: %v", err)
	}
	c.PollBackoff = func(int) time.Duration { return time.Millisecond }
	c.RetryBackoff = func(int) time.Duration { return time.Millisecond }
	return c
}

// TestPostScan_RetriesTransportError covers the other half of "transient": the
// connection dropping before any status arrives, which is what a flaky network
// in CI actually looks like.
func TestPostScan_RetriesTransportError(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	if _, err := c.Validate(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("attempts: got %d, want 2", got)
	}
}

// truncatedBodyHandler writes a Content-Length it does not satisfy and then
// drops the connection, so the client's io.ReadAll fails partway through a
// 200. Needed because httptest cannot otherwise produce a half-read response.
func truncatedBodyHandler(t *testing.T) func(http.ResponseWriter) {
	t.Helper()
	return truncatedStatusHandler(t, http.StatusOK)
}

func truncatedStatusHandler(t *testing.T, status int) func(http.ResponseWriter) {
	t.Helper()
	return func(w http.ResponseWriter) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n", status, http.StatusText(status))
		buf.WriteString(`{"status":"SUCC`)
		buf.Flush()
	}
}

// TestAuthError_SurvivesTruncatedBody pins that the status outranks the body
// read: a 401 whose body never finished arriving is still a rejected
// credential, so it must not be retried as a blip or reported as a read error.
func TestAuthError_SurvivesTruncatedBody(t *testing.T) {
	t.Run("submit", func(t *testing.T) {
		truncate := truncatedStatusHandler(t, http.StatusUnauthorized)
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			truncate(w)
		}))
		defer srv.Close()

		c := testRetryClient(t, srv)
		_, err := c.Validate(context.Background(), ossbom.MiniBOM{})
		if err == nil || !strings.Contains(err.Error(), "API key rejected") {
			t.Fatalf("err: got %v, want the API key message", err)
		}
		if got := hits.Load(); got != 1 {
			t.Errorf("attempts: got %d, want 1", got)
		}
	})

	t.Run("poll", func(t *testing.T) {
		truncate := truncatedStatusHandler(t, http.StatusForbidden)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/public/v1/scans" {
				w.WriteHeader(http.StatusAccepted)
				io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
				return
			}
			truncate(w)
		}))
		defer srv.Close()

		c := testRetryClient(t, srv)
		_, err := c.Validate(context.Background(), ossbom.MiniBOM{})
		if err == nil || !strings.Contains(err.Error(), "API key rejected (status 403)") {
			t.Fatalf("err: got %v, want the API key message", err)
		}
	})
}

// TestPoll_TruncatedBodyIsTransient pins that a status response that dies
// mid-body costs a poll rather than the verdict. Ignoring the io.ReadAll error
// turned it into a decode failure, which is a definite error the transient
// allowance deliberately does not cover.
func TestPoll_TruncatedBodyIsTransient(t *testing.T) {
	truncate := truncatedBodyHandler(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
			return
		}
		if hits.Add(1) == 1 {
			truncate(w)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	raw, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(string(raw), `"vulnerabilities"`) {
		t.Errorf("output: %s", raw)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("polls: got %d, want 2", got)
	}
}

// TestPostScan_TruncatedBodyIsRetried is the submit-side counterpart: a body
// that dies mid-read must not reach the caller as a decode error.
func TestPostScan_TruncatedBodyIsRetried(t *testing.T) {
	truncate := truncatedBodyHandler(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			truncate(w)
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	if _, err := c.Validate(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("attempts: got %d, want 2", got)
	}
}

// acceptServer captures the client-identity headers of the submission it serves.
func acceptServer(t *testing.T, gotClient, gotVersion *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotClient = r.Header.Get("X-Ossprey-Client")
		*gotVersion = r.Header.Get("X-Ossprey-Client-Version")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
	}))
}

// Which CLI release a customer runs is otherwise only answerable by asking them.
func TestSubmit_ReportsClientIdentity(t *testing.T) {
	orig := Version
	Version = "0.15.0"
	t.Cleanup(func() { Version = orig })

	var gotClient, gotVersion string
	srv := acceptServer(t, &gotClient, &gotVersion)
	defer srv.Close()

	if err := testClient(t, srv).Submit(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotVersion != "0.15.0" {
		t.Errorf("version header: got %q, want %q", gotVersion, "0.15.0")
	}
	if gotClient != "cli" {
		t.Errorf("client header: got %q, want %q", gotClient, "cli")
	}
}

// Wrappers name themselves through OSSPREY_CLIENT, so a scan can be attributed
// to the action that ran it. Anything the API would reject falls back to "cli".
func TestSubmit_ClientNameFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{"unset falls back to the cli", "", "cli"},
		{"wrapper names itself", "gh-action", "gh-action"},
		{"case is folded", "GH-Action", "gh-action"},
		{"punctuation is kept", "azdo-task_1.2", "azdo-task_1.2"},
		{"spaces fall back", "not a name", "cli"},
		{"over-long falls back", strings.Repeat("x", 33), "cli"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OSSPREY_CLIENT", tt.env)

			var gotClient, gotVersion string
			srv := acceptServer(t, &gotClient, &gotVersion)
			defer srv.Close()

			if err := testClient(t, srv).Submit(context.Background(), ossbom.MiniBOM{}); err != nil {
				t.Fatalf("Submit: %v", err)
			}
			if gotClient != tt.want {
				t.Errorf("client header: got %q, want %q", gotClient, tt.want)
			}
		})
	}
}
