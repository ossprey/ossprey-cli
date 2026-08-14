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
)

// APIKey is the API's representation of a created key. Key holds the secret
// value and is only ever populated in the creation response — the list
// endpoint redacts it.
type APIKey struct {
	ID      string `json:"id"`
	Key     string `json:"api_key"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Expiry  string `json:"expiry"`
}

// APIError is a non-2xx response from the Ossprey API with its user-facing
// message decoded, so callers can branch on status (e.g. 409 name conflict).
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error (status %d): %s", e.StatusCode, e.Message)
}

// CreateAPIKey creates a named API key expiring at the given time. Requires a
// bearer-token client (`ossprey login`): API-key management lives on the
// dashboard mount and API keys cannot mint other API keys.
func (c *Client) CreateAPIKey(ctx context.Context, name string, expiry time.Time) (*APIKey, error) {
	if c.BearerToken == "" {
		return nil, errors.New("creating an API key requires a browser login (run `ossprey login`)")
	}

	body, err := json.Marshal(map[string]string{
		"name":   name,
		"expiry": expiry.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal api key request: %w", err)
	}

	endpoint, err := url.JoinPath(c.BaseURL, "/dashboard/v1", "api-keys")
	if err != nil {
		return nil, fmt.Errorf("build url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.authenticate(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("create api key: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, &APIError{StatusCode: resp.StatusCode, Message: apiErrorMessage(respBody)}
	}

	var key APIKey
	if err := json.Unmarshal(respBody, &key); err != nil {
		return nil, fmt.Errorf("decode api key response: %w", err)
	}
	if key.Key == "" {
		return nil, errors.New("api key response missing key")
	}
	return &key, nil
}

// apiErrorMessage extracts the "message" field from an API error envelope
// ({"status":"FAILED","error":...,"message":...}), falling back to the raw
// body.
func apiErrorMessage(body []byte) string {
	var envelope struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		if envelope.Message != "" {
			return envelope.Message
		}
		if envelope.Error != "" {
			return envelope.Error
		}
	}
	return truncate(string(body), 300)
}
