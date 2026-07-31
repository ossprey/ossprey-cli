package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotLoggedIn is returned when no stored login exists. Callers surface it
// as "run `ossprey login`".
var ErrNotLoggedIn = errors.New("not logged in")

// expiryLeeway is how long before the recorded expiry a token is already
// treated as expired, so a token never dies mid-scan.
const expiryLeeway = 60 * time.Second

// Credentials is the persisted result of a device-flow login. Domain,
// ClientID and Audience are stored alongside the tokens so refreshes hit the
// same tenant the user logged in against, regardless of current flags/env.
type Credentials struct {
	Domain       string    `json:"domain"`
	ClientID     string    `json:"client_id"`
	Audience     string    `json:"audience"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Valid reports whether the access token exists and is not (about to be)
// expired.
func (c *Credentials) Valid() bool {
	return c != nil && c.AccessToken != "" && time.Now().Add(expiryLeeway).Before(c.ExpiresAt)
}

// Identity returns a human-readable identity ("email" falling back to "sub")
// from the ID token's claims, or "" when unavailable. The payload is decoded
// without signature verification — this is display-only, never authorization.
func (c *Credentials) Identity() string {
	parts := strings.Split(c.IDToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	if claims.Email != "" {
		return claims.Email
	}
	return claims.Sub
}

// Path returns the credentials file location: $OSSPREY_CONFIG_DIR/credentials.json
// when the env var is set (also the test seam), else <user config dir>/ossprey/credentials.json.
func Path() (string, error) {
	if dir := os.Getenv("OSSPREY_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "credentials.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(dir, "ossprey", "credentials.json"), nil
}

// Load reads the stored credentials, returning ErrNotLoggedIn when none exist.
func Load() (*Credentials, error) {
	path, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotLoggedIn
		}
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse credentials %s: %w", path, err)
	}
	if c.AccessToken == "" {
		return nil, ErrNotLoggedIn
	}
	return &c, nil
}

// Save writes the credentials with owner-only permissions.
func Save(c *Credentials) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

// Remove deletes the stored credentials. Missing credentials are not an error.
func Remove() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove credentials: %w", err)
	}
	return nil
}
