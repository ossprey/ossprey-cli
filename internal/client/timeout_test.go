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

func runningServer(t *testing.T, polls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/scans" {
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"sbom_id":"sb1","scan_id":"sc1"}`)
			return
		}
		polls.Add(1)
		io.WriteString(w, `{"status":"RUNNING"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerdictTimeout_NamesTheScanAndHowToRecover(t *testing.T) {
	var polls atomic.Int32
	c := testRetryClient(t, runningServer(t, &polls))
	c.PollBackoff = func(int) time.Duration { return 0 }
	c.VerdictTimeout = 4 * pollInterval

	_, _, err := c.Validate(context.Background(), ossbom.MiniBOM{})

	var te *ErrVerdictTimeout
	if !errors.As(err, &te) {
		t.Fatalf("err: got %v, want *ErrVerdictTimeout", err)
	}
	if te.ScanID != "sc1" || te.LastStatus != "RUNNING" {
		t.Errorf("got scan %q status %q", te.ScanID, te.LastStatus)
	}
	if got := polls.Load(); got != 4 {
		t.Errorf("polls: got %d, want 4", got)
	}
	for _, want := range []string{"took too long", `"sc1"`, "still running", dashboardURL, VerdictTimeoutEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}
}

func TestVerdictTimeoutFromEnv(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want time.Duration
	}{
		{"", defaultVerdictTimeout},
		{"30m", 30 * time.Minute},
		{"junk", defaultVerdictTimeout},
		{"-1m", defaultVerdictTimeout},
	} {
		t.Setenv(VerdictTimeoutEnv, tc.val)
		if got := newClient("").VerdictTimeout; got != tc.want {
			t.Errorf("%q: got %s, want %s", tc.val, got, tc.want)
		}
	}
}

func TestSubmitTimeoutIsExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	c := testRetryClient(t, srv)
	c.HTTP.Timeout = 20 * time.Millisecond
	_, _, err := c.Validate(context.Background(), ossbom.MiniBOM{})
	if err == nil || !strings.Contains(err.Error(), "timed out submitting the scan") {
		t.Fatalf("err: got %v, want a named submit timeout", err)
	}
}

func TestVerdictTimeout_IsElapsedTimeNotPollCount(t *testing.T) {
	var polls atomic.Int32
	c := testRetryClient(t, runningServer(t, &polls))
	c.PollBackoff = func(int) time.Duration { return time.Hour }
	c.VerdictTimeout = 50 * time.Millisecond

	start := time.Now()
	_, _, err := c.Validate(context.Background(), ossbom.MiniBOM{})

	var te *ErrVerdictTimeout
	if !errors.As(err, &te) {
		t.Fatalf("err: got %v, want *ErrVerdictTimeout", err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("waited %s past a 50ms verdict timeout", waited)
	}
}

func TestVerdictTimeout_CallerCancelIsNotATimeout(t *testing.T) {
	var polls atomic.Int32
	c := testRetryClient(t, runningServer(t, &polls))
	c.PollBackoff = func(int) time.Duration { return time.Hour }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := c.Validate(ctx, ossbom.MiniBOM{})

	var te *ErrVerdictTimeout
	if errors.As(err, &te) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err: got %v, want context.Canceled", err)
	}
}

func TestVerdictTimeout_ScanIDIsQuoted(t *testing.T) {
	err := &ErrVerdictTimeout{ScanID: "x\nerror: forged", Waited: time.Second}
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("raw newline in %q", err.Error())
	}
}
