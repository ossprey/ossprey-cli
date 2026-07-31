// Package auth implements `ossprey login`: the OAuth 2.0 device-authorization
// flow (RFC 8628) against Auth0, persistent credential storage, and silent
// refresh. The resulting access token authenticates scan submissions as
// `Authorization: Bearer <token>` — no API key needed.
package auth

import (
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
)

// Defaults target the production Ossprey Auth0 tenant. Override via the
// OSSPREY_AUTH0_* env vars or the `ossprey login` flags (e.g. for QA:
// domain auth.qa.ossprey.com, audience https://api.qa.ossprey.com).
const (
	DefaultDomain   = "auth.ossprey.com"
	DefaultClientID = "IosLlMhilXmQDmGcRgDfwfoumgcLFN41"
	DefaultAudience = "https://api.ossprey.com"

	// scope requests offline_access so Auth0 issues a refresh token and the
	// login survives past the first access token's expiry.
	scope = "openid profile email offline_access"
)

// Config identifies the Auth0 tenant and API audience to authenticate against.
type Config struct {
	Domain   string
	ClientID string
	Audience string

	// BaseURL overrides "https://{Domain}" (tests). Empty in normal use.
	BaseURL string
	// PollInterval overrides the server-provided device-flow polling interval
	// (tests). Zero means honour the server.
	PollInterval time.Duration
}

// ConfigFromEnv builds a Config from OSSPREY_AUTH0_{DOMAIN,CLIENT_ID,AUDIENCE},
// falling back to the production defaults.
func ConfigFromEnv() Config {
	return Config{
		Domain:   envOr("OSSPREY_AUTH0_DOMAIN", DefaultDomain),
		ClientID: envOr("OSSPREY_AUTH0_CLIENT_ID", DefaultClientID),
		Audience: envOr("OSSPREY_AUTH0_AUDIENCE", DefaultAudience),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c Config) endpoint(path string) string {
	if c.BaseURL != "" {
		return c.BaseURL + path
	}
	return "https://" + c.Domain + path
}

// DeviceCode is Auth0's response to a device-authorization request.
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenResponse covers both the success and error shapes of /oauth/token.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// RequestDeviceCode starts the device flow, returning the code the user must
// confirm in a browser.
func (c Config) RequestDeviceCode(ctx context.Context, hc *http.Client) (*DeviceCode, error) {
	form := url.Values{
		"client_id": {c.ClientID},
		"scope":     {scope},
		"audience":  {c.Audience},
	}
	body, status, err := postForm(ctx, hc, c.endpoint("/oauth/device/code"), form)
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("request device code (status %d): %s", status, truncate(body, 300))
	}
	var dc DeviceCode
	if err := json.Unmarshal([]byte(body), &dc); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	if dc.DeviceCode == "" || dc.UserCode == "" {
		return nil, errors.New("device code response missing codes")
	}
	return &dc, nil
}

// PollToken polls /oauth/token until the user approves the login in the
// browser, then returns ready-to-store credentials. It honours the server's
// polling interval (including slow_down back-pressure) and gives up when the
// device code expires or ctx is cancelled.
func (c Config) PollToken(ctx context.Context, hc *http.Client, dc *DeviceCode) (*Credentials, error) {
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if c.PollInterval > 0 {
		interval = c.PollInterval
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)

	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {dc.DeviceCode},
		"client_id":   {c.ClientID},
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		if dc.ExpiresIn > 0 && time.Now().After(deadline) {
			return nil, errors.New("login timed out: device code expired before the login was approved")
		}

		body, status, err := postForm(ctx, hc, c.endpoint("/oauth/token"), form)
		if err != nil {
			return nil, fmt.Errorf("poll token: %w", err)
		}
		var tr tokenResponse
		if err := json.Unmarshal([]byte(body), &tr); err != nil {
			return nil, fmt.Errorf("decode token response (status %d): %w", status, err)
		}

		switch tr.Error {
		case "":
			if status != http.StatusOK || tr.AccessToken == "" {
				return nil, fmt.Errorf("token poll failed (status %d): %s", status, truncate(body, 300))
			}
			return c.credentials(tr), nil
		case "authorization_pending":
			continue
		case "slow_down":
			// RFC 8628: bump the polling interval by 5 seconds (scaled down
			// when tests override the interval).
			if c.PollInterval > 0 {
				interval += c.PollInterval
			} else {
				interval += 5 * time.Second
			}
		case "expired_token":
			return nil, errors.New("login timed out: device code expired before the login was approved")
		case "access_denied":
			return nil, errors.New("login was declined in the browser")
		default:
			return nil, fmt.Errorf("login failed: %s: %s", tr.Error, tr.ErrorDescription)
		}
	}
}

// Refresh exchanges the stored refresh token for a fresh access token. Auth0
// may rotate the refresh token; the returned credentials carry whichever
// refresh token remains valid.
func (c Config) Refresh(ctx context.Context, hc *http.Client, creds *Credentials) (*Credentials, error) {
	if creds.RefreshToken == "" {
		return nil, errors.New("login expired and no refresh token is stored: run `ossprey login` again")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.ClientID},
		"refresh_token": {creds.RefreshToken},
	}
	body, status, err := postForm(ctx, hc, c.endpoint("/oauth/token"), form)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		return nil, fmt.Errorf("decode refresh response (status %d): %w", status, err)
	}
	if status != http.StatusOK || tr.AccessToken == "" {
		return nil, fmt.Errorf("login expired and refresh failed (%s): run `ossprey login` again", strings.TrimSpace(tr.Error+" "+tr.ErrorDescription))
	}
	next := c.credentials(tr)
	if next.RefreshToken == "" {
		next.RefreshToken = creds.RefreshToken
	}
	if next.IDToken == "" {
		next.IDToken = creds.IDToken
	}
	return next, nil
}

func (c Config) credentials(tr tokenResponse) *Credentials {
	return &Credentials{
		Domain:       c.Domain,
		ClientID:     c.ClientID,
		Audience:     c.Audience,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}
}

// AccessToken returns a valid access token from the stored login, silently
// refreshing (and re-saving) it when expired. Returns ErrNotLoggedIn when no
// login is stored.
func AccessToken(ctx context.Context, hc *http.Client) (string, error) {
	creds, err := Load()
	if err != nil {
		return "", err
	}
	if creds.Valid() {
		return creds.AccessToken, nil
	}
	cfg := Config{Domain: creds.Domain, ClientID: creds.ClientID, Audience: creds.Audience}
	next, err := cfg.Refresh(ctx, hc, creds)
	if err != nil {
		return "", err
	}
	if err := Save(next); err != nil {
		return "", err
	}
	return next.AccessToken, nil
}

// postForm sends a form-encoded POST and returns the body and status. The
// caller inspects the status: Auth0 uses non-200 codes for in-band protocol
// errors (authorization_pending etc.) that are not transport failures.
func postForm(ctx context.Context, hc *http.Client, endpoint string, form url.Values) (body string, status int, err error) {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return string(b), resp.StatusCode, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
