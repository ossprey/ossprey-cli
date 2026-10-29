package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// A rejected credential must name where it came from, for all three kinds, and
// a monitor's message must not echo the token itself.
func TestAuthError_NamesEachCredentialKind(t *testing.T) {
	tests := []struct {
		name   string
		build  func(t *testing.T, url string) *Client
		status int
		want   string
	}{
		{
			name: "monitor 401",
			build: func(t *testing.T, u string) *Client {
				c, err := NewIngest(u, testIngestToken)
				if err != nil {
					t.Fatal(err)
				}
				c.RetryBackoff = func(int) time.Duration { return time.Millisecond }
				return c
			},
			status: http.StatusUnauthorized,
			want:   "monitor id rejected (status 401)",
		},
		{
			name: "monitor 403",
			build: func(t *testing.T, u string) *Client {
				c, err := NewIngest(u, testIngestToken)
				if err != nil {
					t.Fatal(err)
				}
				return c
			},
			status: http.StatusForbidden,
			want:   "--monitor",
		},
		{
			name:   "bearer 403",
			build:  func(t *testing.T, u string) *Client { return mustNewBearer(t, u, "stale") },
			status: http.StatusForbidden,
			want:   "login rejected (status 403)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(tt.status)
				io.WriteString(w, `{"message":"Forbidden"}`)
			}))
			defer srv.Close()

			err := tt.build(t, srv.URL).Submit(context.Background(), ossbom.MiniBOM{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err: got %v, want substring %q", err, tt.want)
			}
			if strings.Contains(err.Error(), testIngestToken) {
				t.Errorf("monitor id leaked into the error: %v", err)
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("attempts: got %d, want 1 (an auth failure is not transient)", got)
			}
		})
	}
}

// Only 502/503/504 are retried. Every other 5xx and 4xx is a definite answer;
// widening the set "for symmetry" risks duplicate scans against quota.
func TestPostScan_OnlyGatewayStatusesAreRetried(t *testing.T) {
	for _, status := range []int{
		http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity,
		http.StatusRequestEntityTooLarge,
		http.StatusNotImplemented, http.StatusHTTPVersionNotSupported,
		http.StatusInsufficientStorage, 599,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(status)
			}))
			defer srv.Close()

			if err := testRetryClient(t, srv).Submit(context.Background(), ossbom.MiniBOM{}); err == nil {
				t.Fatal("expected error")
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("attempts: got %d, want 1", got)
			}
		})
	}
}

// The backoff is asked for once per retry, numbered from 1, and never before
// the first attempt.
func TestPostScan_RetryBackoffIsAskedPerRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := testClient(t, srv)
	var mu sync.Mutex
	var asked []int
	c.RetryBackoff = func(attempt int) time.Duration {
		mu.Lock()
		asked = append(asked, attempt)
		mu.Unlock()
		return time.Millisecond
	}
	if err := c.Submit(context.Background(), ossbom.MiniBOM{}); err == nil {
		t.Fatal("expected error")
	}
	if len(asked) != maxSubmitAttempts-1 || asked[0] != 1 || asked[len(asked)-1] != maxSubmitAttempts-1 {
		t.Errorf("backoff attempts: got %v, want 1..%d", asked, maxSubmitAttempts-1)
	}
	if defaultRetryBackoff(2) <= defaultRetryBackoff(1) {
		t.Errorf("default retry backoff does not grow: %v then %v", defaultRetryBackoff(1), defaultRetryBackoff(2))
	}
}

// A request cut off by cancellation is not a blip: no retry, no backoff.
func TestPostScan_CancelledInFlightIsNotRetried(t *testing.T) {
	var hits atomic.Int32
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		arrived <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := testClient(t, srv)
	var backoffs atomic.Int32
	c.RetryBackoff = func(int) time.Duration { backoffs.Add(1); return time.Millisecond }

	done := make(chan error, 1)
	go func() { done <- c.Submit(ctx, ossbom.MiniBOM{}) }()
	<-arrived
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err: got %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Submit did not return after cancellation")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("attempts: got %d, want 1", got)
	}
	if got := backoffs.Load(); got != 0 {
		t.Errorf("backoff consulted %d times after cancellation, want 0", got)
	}
}

// pollServer accepts the submit with a 202 and answers status polls in order
// from replies (status code + body); the last reply repeats.
func pollServer(t *testing.T, replies []pollReply) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
			return
		}
		i := int(polls.Add(1)) - 1
		if i >= len(replies) {
			i = len(replies) - 1
		}
		w.WriteHeader(replies[i].status)
		io.WriteString(w, replies[i].body)
	}))
	return srv, &polls
}

type pollReply struct {
	status int
	body   string
}

// A 500 on the status poll is an answer, not a blip, exactly as on submit.
func TestPoll_NonGatewayErrorFailsImmediately(t *testing.T) {
	srv, polls := pollServer(t, []pollReply{{http.StatusInternalServerError, `boom`}})
	defer srv.Close()

	_, _, err := testRetryClient(t, srv).Validate(context.Background(), ossbom.MiniBOM{})
	if err == nil || !strings.Contains(err.Error(), "status poll failed (500)") {
		t.Fatalf("err: got %v, want the 500", err)
	}
	if got := polls.Load(); got != 1 {
		t.Errorf("polls: got %d, want 1", got)
	}
}

// The transient allowance counts consecutive failures: an answer in between
// resets it, so scattered blips across a long scan do not add up to a give-up.
func TestPoll_TransientCounterResetsOnAnAnswer(t *testing.T) {
	bad := pollReply{http.StatusBadGateway, ``}
	running := pollReply{http.StatusOK, `{"status":"RUNNING"}`}
	var replies []pollReply
	for i := 0; i < 3; i++ {
		for j := 0; j < maxTransientPolls-1; j++ {
			replies = append(replies, bad)
		}
		replies = append(replies, running)
	}
	replies = append(replies, pollReply{http.StatusOK, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`})

	srv, polls := pollServer(t, replies)
	defer srv.Close()

	if _, _, err := testRetryClient(t, srv).Validate(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := int(polls.Load()); got != len(replies) {
		t.Errorf("polls: got %d, want %d", got, len(replies))
	}
}

// A cancelled scan must not be held open by the poll wait.
func TestPoll_CancelDuringBackoffReturnsPromptly(t *testing.T) {
	srv, polls := pollServer(t, []pollReply{{http.StatusOK, `{"status":"RUNNING"}`}})
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := testRetryClient(t, srv)
	c.PollBackoff = func(attempt int) time.Duration {
		if attempt > 1 {
			cancel()
			return time.Hour
		}
		return 0
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := c.Validate(ctx, ossbom.MiniBOM{})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err: got %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Validate slept through cancellation in the poll backoff")
	}
	if got := polls.Load(); got != 1 {
		t.Errorf("polls: got %d, want 1", got)
	}
}

func TestPoll_StatusOutcomes(t *testing.T) {
	tests := []struct {
		name      string
		replies   []pollReply
		wantErr   string
		wantSkip  string
		wantPolls int32
	}{
		{
			name:      "queued and pending keep polling",
			replies:   []pollReply{{200, `{"status":"QUEUED"}`}, {200, `{"status":"PENDING"}`}, {200, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`}},
			wantPolls: 3,
		},
		{
			name:      "succeeded without output is an error, not a clean verdict",
			replies:   []pollReply{{200, `{"status":"SUCCEEDED"}`}},
			wantErr:   "returned no SBOM",
			wantPolls: 1,
		},
		{
			name:      "failed with no message",
			replies:   []pollReply{{200, `{"status":"FAILED"}`}},
			wantErr:   "Scan failed",
			wantPolls: 1,
		},
		{
			name:      "unknown status is an error",
			replies:   []pollReply{{200, `{"status":"EXPLODED"}`}},
			wantErr:   `unknown scan status: "EXPLODED"`,
			wantPolls: 1,
		},
		{
			name:      "malformed status body",
			replies:   []pollReply{{200, `not json`}},
			wantErr:   "decode status body",
			wantPolls: 1,
		},
		{
			name:      "skipped with no message reads the nested reason",
			replies:   []pollReply{{200, `{"status":"SKIPPED","output":{"reason":"no_scannable_components"}}`}},
			wantSkip:  "Scan skipped: nothing in this project is in an ecosystem Ossprey scans",
			wantPolls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, polls := pollServer(t, tt.replies)
			defer srv.Close()

			_, _, err := testRetryClient(t, srv).Validate(context.Background(), ossbom.MiniBOM{})
			switch {
			case tt.wantSkip != "":
				var skipped *ErrSkipped
				if !errors.As(err, &skipped) {
					t.Fatalf("err: got %T %v, want *ErrSkipped", err, err)
				}
				if skipped.Message != tt.wantSkip {
					t.Errorf("skip message: got %q, want %q", skipped.Message, tt.wantSkip)
				}
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err: got %v, want substring %q", err, tt.wantErr)
				}
				var skipped *ErrSkipped
				if errors.As(err, &skipped) {
					t.Errorf("a failure must not read as a skip: %v", err)
				}
			default:
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
			}
			if got := polls.Load(); got != tt.wantPolls {
				t.Errorf("polls: got %d, want %d", got, tt.wantPolls)
			}
		})
	}
}

// The poll names the scan it asks about and carries the same credential as the
// submit.
func TestPoll_SendsScanIDsAndCredential(t *testing.T) {
	var query, key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb-42","scan_id":"sc-7"}`)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("poll method: got %s, want GET", r.Method)
		}
		query, key = r.URL.RawQuery, r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"status":"SUCCEEDED","output":{"vulnerabilities":[]}}`)
	}))
	defer srv.Close()

	if _, _, err := testRetryClient(t, srv).Validate(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !strings.Contains(query, "sbom_id=sb-42") || !strings.Contains(query, "scan_id=sc-7") {
		t.Errorf("poll query: got %q, want both ids", query)
	}
	if key != "test-key" {
		t.Errorf("poll x-api-key: got %q, want test-key", key)
	}
}

// OSSPREY_API_KEY wins over the generic API_KEY, which is only a fallback.
func TestAPIKeyFromEnvOrder(t *testing.T) {
	tests := []struct {
		ossprey, generic, want string
	}{
		{"", "", ""},
		{"specific", "", "specific"},
		{"", "generic", "generic"},
		{"specific", "generic", "specific"},
	}
	for _, tt := range tests {
		t.Setenv("OSSPREY_API_KEY", tt.ossprey)
		t.Setenv("API_KEY", tt.generic)
		if got := APIKeyFromEnv(); got != tt.want {
			t.Errorf("OSSPREY_API_KEY=%q API_KEY=%q: got %q, want %q", tt.ossprey, tt.generic, got, tt.want)
		}
	}
}

// An ingest client's poll-free Submit still retries a gateway blip, and every
// attempt goes to the ingest mount with no credential header.
func TestIngestSubmitRetriesOnTheIngestMount(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/ingest/" + testIngestToken + "/scans"; r.URL.Path != want {
			t.Errorf("path: got %q, want %q", r.URL.Path, want)
		}
		if r.Header.Get("x-api-key") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("credential header sent on attempt %d", hits.Load()+1)
		}
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	c, err := NewIngest(srv.URL, testIngestToken)
	if err != nil {
		t.Fatal(err)
	}
	c.RetryBackoff = func(int) time.Duration { return time.Millisecond }
	if err := c.Submit(context.Background(), ossbom.MiniBOM{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("attempts: got %d, want 2", got)
	}
}
