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
	"time"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Client speaks to the Ossprey scans API. Mirrors ossprey/ossprey.py from v1.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client

	// PollBackoff returns the wait between status polls for the given attempt
	// (1-indexed). Defaults to attempt*attempt seconds (matches v1). Override
	// in tests for sub-second polling.
	PollBackoff func(attempt int) time.Duration
}

// New constructs a Client; baseURL defaults to https://api.ossprey.com.
func New(baseURL, apiKey string) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("API key is required")
	}
	if baseURL == "" {
		baseURL = "https://api.ossprey.com"
	}
	return &Client{
		BaseURL:     baseURL,
		APIKey:      apiKey,
		HTTP:        &http.Client{Timeout: 60 * time.Second},
		PollBackoff: defaultPollBackoff,
	}, nil
}

func defaultPollBackoff(attempt int) time.Duration {
	return time.Duration(attempt*attempt) * time.Second
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
	body, err := json.Marshal(map[string]any{"sbom": mb})
	if err != nil {
		return nil, fmt.Errorf("marshal sbom: %w", err)
	}

	endpoint, err := url.JoinPath(c.BaseURL, "/public/v1/scans")
	if err != nil {
		return nil, fmt.Errorf("build url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submit: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return respBody, nil
	case http.StatusAccepted:
		var sr submitResponse
		if err := json.Unmarshal(respBody, &sr); err != nil {
			return nil, fmt.Errorf("decode 202 body: %w", err)
		}
		return c.waitForCompletion(ctx, sr.SBOMID, sr.ScanID)
	case http.StatusTooManyRequests:
		return nil, errors.New("rate limit exceeded")
	default:
		return nil, fmt.Errorf("submit failed (status %d): %s", resp.StatusCode, truncate(string(respBody), 500))
	}
}

func (c *Client) waitForCompletion(ctx context.Context, sbomID, scanID string) (json.RawMessage, error) {
	endpoint, err := url.JoinPath(c.BaseURL, "/public/v1/scans/status")
	if err != nil {
		return nil, fmt.Errorf("build status url: %w", err)
	}

	backoff := c.PollBackoff
	if backoff == nil {
		backoff = defaultPollBackoff
	}

	for i := 1; i < 20; i++ {
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
		req.Header.Set("x-api-key", c.APIKey)
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
