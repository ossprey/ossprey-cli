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
// Exactly one of APIKey or BearerToken is set: API keys go to the /public/v1
// mount as x-api-key, Auth0 JWTs (from `ossprey login`) go to the /dashboard/v1
// mount as Authorization: Bearer. Both mounts are served by the same backend.
type Client struct {
	BaseURL     string
	APIKey      string
	BearerToken string
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
	if c.BearerToken != "" {
		return "/dashboard/v1"
	}
	return "/public/v1"
}

// authenticate sets the auth header matching the client's credential.
func (c *Client) authenticate(req *http.Request) {
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
		return
	}
	req.Header.Set("x-api-key", c.APIKey)
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
