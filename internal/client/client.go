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
	"time"

	"github.com/ossprey/ossprey-cli/internal/monitor"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

const pollInterval = 3 * time.Second

// 300 polls at pollInterval gives a ~15 minute ceiling, above the platform's 850s budget.
const maxPollAttempts = 300

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
	if !ValidIngestToken(token) {
		return nil, fmt.Errorf("invalid monitor id: expected %s followed by 64 hex characters", monitor.Prefix)
	}
	c := newClient(baseURL)
	c.IngestToken = token
	return c, nil
}

// ValidIngestToken reports whether a string is shaped like an ingest token the
// service could have issued.
//
// A thin re-export of monitor.ValidToken, kept so callers already holding a
// client package do not need a second import for it.
func ValidIngestToken(token string) bool { return monitor.ValidToken(token) }

func newClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		BaseURL:     baseURL,
		HTTP:        &http.Client{Timeout: 60 * time.Second},
		PollBackoff: defaultPollBackoff,
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

func (c *Client) postScan(ctx context.Context, mb ossbom.MiniBOM) (int, []byte, error) {
	body, err := json.Marshal(map[string]any{"sbom": mb})
	if err != nil {
		return 0, nil, fmt.Errorf("marshal sbom: %w", err)
	}

	endpoint, err := url.JoinPath(c.BaseURL, c.mount(), "scans")
	if err != nil {
		return 0, nil, fmt.Errorf("build url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.authenticate(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("submit: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		return resp.StatusCode, respBody, nil
	case http.StatusTooManyRequests:
		return 0, nil, errors.New("rate limit exceeded")
	default:
		return 0, nil, fmt.Errorf("submit failed (status %d): %s", resp.StatusCode, truncate(string(respBody), 500))
	}
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

	for i := 1; i < maxPollAttempts; i++ {
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

		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("poll status: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			return nil, fmt.Errorf("status poll failed (%d): %s", resp.StatusCode, truncate(string(body), 500))
		}

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
