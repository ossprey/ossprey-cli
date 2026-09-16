package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ossprey/ossprey-cli/internal/monitor"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

const pollInterval = 3 * time.Second

// 300 polls at pollInterval gives a ~15 minute ceiling, above the platform's 850s budget.
const maxPollAttempts = 300

// retryInterval is the wait before the first submit retry; the second waits
// twice as long. Kept short deliberately: this covers a dropped connection or a
// load balancer blipping, not an outage, and a scan sits in front of a
// developer's install.
const retryInterval = 500 * time.Millisecond

// maxSubmitAttempts is one submit plus two retries. A blip usually clears on
// the first retry, and more attempts would trade a rare save against seconds
// added to every genuinely-down run.
const maxSubmitAttempts = 3

// maxTransientPolls is how many consecutive transient status-poll failures are
// tolerated before the scan is given up on. Bounded rather than unlimited: an
// API that is simply down would otherwise hold the caller for the full poll
// ceiling with nothing to show.
const maxTransientPolls = 3

// defaultBaseURL is used when New is called without an explicit URL.
const defaultBaseURL = "https://api.ossprey.com"

// APIKeyFromEnv returns the first non-empty value of OSSPREY_API_KEY then
// API_KEY. Returns "" if neither is set.
func APIKeyFromEnv() string {
	for _, v := range []string{"OSSPREY_API_KEY", "API_KEY"} {
		if k := os.Getenv(v); k != "" {
			return k
		}
	}
	return ""
}

// Client speaks to the Ossprey scans API. Mirrors ossprey/ossprey.py from v1.
// Exactly one credential field is set, and it picks both the route mount and the
// auth header:
//
//	APIKey      -> /public/v1     , x-api-key
//	BearerToken -> /dashboard/v1  , Authorization: Bearer  (from `ossprey login`)
//	IngestToken -> /ingest/<token>, no header at all
//
// All three are served by the same backend. The ingest mount is submit-only: it
// has no status endpoint, so Validate refuses an ingest client rather than
// polling a route that does not exist.
type Client struct {
	BaseURL     string
	APIKey      string
	BearerToken string
	IngestToken string
	HTTP        *http.Client

	// PollBackoff returns the wait before poll `attempt`. Overridden in tests.
	PollBackoff func(attempt int) time.Duration

	// RetryBackoff returns the wait before submit retry `attempt`. Overridden
	// in tests, for the same reason PollBackoff is: nothing in the suite should
	// spend real seconds asleep.
	RetryBackoff func(attempt int) time.Duration
}

// New constructs an API-key Client; baseURL defaults to https://api.ossprey.com.
func New(baseURL, apiKey string) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("API key is required")
	}
	c := newClient(baseURL)
	c.APIKey = apiKey
	return c, nil
}

// NewBearer constructs a Client authenticating with an Auth0 access token.
func NewBearer(baseURL, token string) (*Client, error) {
	if token == "" {
		return nil, errors.New("access token is required")
	}
	c := newClient(baseURL)
	c.BearerToken = token
	return c, nil
}

// NewIngest constructs a submit-only Client for a monitor's ingest token.
//
// The token is validated here rather than at the call site because it lands in
// a URL path: a value carrying a slash or a query character would silently
// retarget the request at a different route.
func NewIngest(baseURL, token string) (*Client, error) {
	if !monitor.ValidToken(token) {
		return nil, fmt.Errorf("invalid monitor id: expected %s followed by 64 hex characters", monitor.Prefix)
	}
	c := newClient(baseURL)
	c.IngestToken = token
	return c, nil
}

func newClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		BaseURL:      baseURL,
		HTTP:         &http.Client{Timeout: 60 * time.Second},
		PollBackoff:  defaultPollBackoff,
		RetryBackoff: defaultRetryBackoff,
	}
}

// mount returns the API route prefix matching the auth method.
func (c *Client) mount() string {
	switch {
	case c.IngestToken != "":
		return "/ingest/" + c.IngestToken
	case c.BearerToken != "":
		return "/dashboard/v1"
	default:
		return "/public/v1"
	}
}

// authenticate sets the auth header matching the client's credential.
//
// An ingest client sends none: its credential is the path. Returning early
// matters -- falling through would send an empty x-api-key header, which reads
// as a malformed API key rather than as no credential at all.
func (c *Client) authenticate(req *http.Request) {
	switch {
	case c.IngestToken != "":
		return
	case c.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	default:
		req.Header.Set("x-api-key", c.APIKey)
	}
}

func defaultPollBackoff(int) time.Duration {
	return pollInterval
}

func defaultRetryBackoff(attempt int) time.Duration {
	return time.Duration(attempt) * retryInterval
}

// retryable reports whether an HTTP status is worth sending the request again.
//
// Only the gateway family qualifies. A 4xx is a real answer -- a bad key, a
// malformed SBOM -- and repeating it just delays the same failure; a 500 is the
// backend having already accepted and processed the request, so a retry risks a
// duplicate scan against the user's quota for no better odds.
func retryable(status int) bool {
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// sleepOrDone waits for d unless ctx ends first, in which case it returns the
// context's error. Retries must never outlive a cancelled scan: a plain
// time.Sleep here would keep a Ctrl-C'd or timed-out run alive for the backoff.
func sleepOrDone(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// authError turns a 401/403 into something a user can act on. The raw body is
// a JSON blob naming no fix, and the credential could have come from any of
// three places (see submit.NewClient), so the message names all of them.
func (c *Client) authError(status int) error {
	switch {
	case c.IngestToken != "":
		return fmt.Errorf("monitor id rejected (status %d): check the id passed to --monitor", status)
	case c.BearerToken != "":
		return fmt.Errorf("login rejected (status %d): your session is no longer valid, run `ossprey login` to sign in again", status)
	default:
		return fmt.Errorf("API key rejected (status %d): check OSSPREY_API_KEY (or --api-key), or run `ossprey login`", status)
	}
}

type submitResponse struct {
	SBOMID string `json:"sbom_id"`
	ScanID string `json:"scan_id"`
}

type statusResponse struct {
	Status  string          `json:"status"`
	Output  json.RawMessage `json:"output"`
	Message string          `json:"message"`
	ResetAt string          `json:"reset_at"`
}

// ErrIngestSubmitOnly is returned when a verdict is asked of a monitor id.
// A monitor submits scans and reads nothing back; results are viewed in the
// dashboard.
var ErrIngestSubmitOnly = errors.New("a monitor id can submit scans but cannot fetch a verdict; results appear in the Ossprey dashboard")

// ErrSkipped indicates the scan was skipped (quota exhausted).
type ErrSkipped struct {
	Message string
	ResetAt string
}

func (e *ErrSkipped) Error() string { return "scan skipped: " + e.Message }

// Validate submits the MiniBOM and returns the result OSSBOM payload (the API
// echoes a MiniBOM with vulnerabilities populated). Callers decode into a
// MiniBOM, then re-hydrate.
func (c *Client) Validate(ctx context.Context, mb ossbom.MiniBOM) (json.RawMessage, error) {
	// The ingest mount deliberately has no status endpoint: a monitor id is a
	// submit-only credential. Refuse here so the caller gets this instead of a
	// 404 from a route that was never meant to exist.
	if c.IngestToken != "" {
		return nil, ErrIngestSubmitOnly
	}
	status, respBody, err := c.postScan(ctx, mb)
	if err != nil {
		return nil, err
	}
	if status == http.StatusOK {
		return respBody, nil
	}
	var sr submitResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, fmt.Errorf("decode 202 body: %w", err)
	}
	return c.waitForCompletion(ctx, sr.SBOMID, sr.ScanID)
}

func (c *Client) Submit(ctx context.Context, mb ossbom.MiniBOM) error {
	_, _, err := c.postScan(ctx, mb)
	return err
}

// redact strips the ingest token from an error before it can be printed.
//
// The token is the whole credential and it travels in the URL path, so every
// *url.Error Go builds for a refused connection, a DNS failure or a TLS problem
// carries it in full -- into terminal scrollback and CI logs, on every install.
// The wrapper keeps errors.As and errors.Is working on what it replaced.
func (c *Client) redact(err error) error {
	if err == nil || c.IngestToken == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), c.IngestToken, monitor.Redact(c.IngestToken))
	if msg == err.Error() {
		return err
	}
	return &redactedError{err: err, msg: msg}
}

type redactedError struct {
	err error
	msg string
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

func (c *Client) postScan(ctx context.Context, mb ossbom.MiniBOM) (int, []byte, error) {
	body, err := json.Marshal(map[string]any{"sbom": mb})
	if err != nil {
		return 0, nil, fmt.Errorf("marshal sbom: %w", err)
	}

	endpoint, err := url.JoinPath(c.BaseURL, c.mount(), "scans")
	if err != nil {
		return 0, nil, fmt.Errorf("build url: %w", c.redact(err))
	}

	backoff := c.RetryBackoff
	if backoff == nil {
		backoff = defaultRetryBackoff
	}

	// A single dropped connection used to fail the whole scan with exit 1 --
	// the same exit code as "malware found", so a network blip in CI read as a
	// detection. Retry the transport and gateway failures that say nothing
	// about the SBOM; everything else is an answer and is returned as one.
	var lastErr error
	for attempt := 1; attempt <= maxSubmitAttempts; attempt++ {
		if attempt > 1 {
			if err := sleepOrDone(ctx, backoff(attempt-1)); err != nil {
				return 0, nil, err
			}
		}

		// The reader is rebuilt per attempt: bytes.NewReader is consumed by the
		// first Do, so a retry reusing it would POST an empty body.
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		c.authenticate(req)

		status, respBody, err := c.doSubmit(req)
		if err != nil {
			// A cancelled or expired context is not transient: retrying would
			// only fail the same way, once per remaining attempt.
			if ctx.Err() != nil {
				return 0, nil, err
			}
			lastErr = err
			continue
		}

		switch {
		case status == http.StatusOK || status == http.StatusAccepted:
			return status, respBody, nil
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			return 0, nil, c.authError(status)
		case status == http.StatusTooManyRequests:
			return 0, nil, errors.New("rate limit exceeded")
		case retryable(status):
			lastErr = fmt.Errorf("submit failed (status %d): %s", status, truncate(string(respBody), 500))
		default:
			return 0, nil, fmt.Errorf("submit failed (status %d): %s", status, truncate(string(respBody), 500))
		}
	}

	return 0, nil, lastErr
}

// doSubmit sends one attempt and reads its body. Split out so the retry loop
// above can defer nothing and still close every response body it opens.
func (c *Client) doSubmit(req *http.Request) (int, []byte, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("submit: %w", c.redact(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

func (c *Client) waitForCompletion(ctx context.Context, sbomID, scanID string) (json.RawMessage, error) {
	endpoint, err := url.JoinPath(c.BaseURL, c.mount(), "scans/status")
	if err != nil {
		return nil, fmt.Errorf("build status url: %w", err)
	}

	backoff := c.PollBackoff
	if backoff == nil {
		backoff = defaultPollBackoff
	}

	// Consecutive transient failures, reset by any answer the API does give.
	var transient int
	var lastErr error

	for i := 1; i <= maxPollAttempts; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff(i)):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		c.authenticate(req)
		q := req.URL.Query()
		q.Set("sbom_id", sbomID)
		q.Set("scan_id", scanID)
		req.URL.RawQuery = q.Encode()

		// The poll gets the same tolerance as the submit, but spends the
		// existing attempt budget rather than adding sleeps of its own: it is
		// already a loop with a wait in it. The scan is running server-side
		// either way, so a blip here should cost a poll, not the verdict.
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("poll status: %w", err)
			}
			lastErr = fmt.Errorf("poll status: %w", err)
			if transient++; transient >= maxTransientPolls {
				return nil, lastErr
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, c.authError(resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			err := fmt.Errorf("status poll failed (%d): %s", resp.StatusCode, truncate(string(body), 500))
			if !retryable(resp.StatusCode) {
				return nil, err
			}
			lastErr = err
			if transient++; transient >= maxTransientPolls {
				return nil, lastErr
			}
			continue
		}
		transient = 0

		var sr statusResponse
		if err := json.Unmarshal(body, &sr); err != nil {
			return nil, fmt.Errorf("decode status body: %w", err)
		}

		switch sr.Status {
		case "SUCCEEDED":
			if len(sr.Output) == 0 {
				return nil, errors.New("scan succeeded but returned no SBOM")
			}
			return sr.Output, nil
		case "SKIPPED":
			msg := sr.Message
			if msg == "" {
				msg = "Scan skipped due to quota exhaustion"
			}
			return nil, &ErrSkipped{Message: msg, ResetAt: sr.ResetAt}
		case "FAILED":
			msg := sr.Message
			if msg == "" {
				msg = "Scan failed"
			}
			return nil, errors.New(msg)
		case "RUNNING", "QUEUED", "PENDING":
			continue
		default:
			return nil, fmt.Errorf("unknown scan status: %q", sr.Status)
		}
	}

	return nil, errors.New("scan took too long to complete")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
