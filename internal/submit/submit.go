// Package submit holds the shared "send an SBOM to the Ossprey API and apply
// the returned vulnerabilities" flow used by both the scan and check commands.
package submit

import (
	"context"
	"errors"
	"fmt"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Validate submits the SBOM to the Ossprey API and copies the returned
// vulnerabilities onto it. Credentials resolve in order: the apiKey argument
// (--api-key flag, an explicit per-invocation choice), then the Auth0 login
// stored by `ossprey login` (refreshed silently if expired), then the
// OSSPREY_API_KEY / API_KEY environment variables. The credential decides the
// API mount: JWTs go to /dashboard/v1, API keys to /public/v1.
//
// A *client.ErrSkipped error flows back unwrapped so callers can detect a
// quota skip via errors.As and report it without failing the build.
func Validate(ctx context.Context, sbom *ossbom.SBOM, apiURL, apiKey string) error {
	c, err := NewClient(ctx, apiURL, apiKey)
	if err != nil {
		return err
	}
	raw, err := c.Validate(ctx, sbom.ToMiniBOM())
	if err != nil {
		return err
	}
	return sbom.ApplyAPIResponse(raw)
}

// Post submits the SBOM and returns as soon as the API has accepted it, without
// waiting for a verdict. This is what `--passive` and the watchdog/monitor shims
// use: results appear in the dashboard rather than gating the caller.
//
// A non-empty monitorID selects the unauthenticated ingest route and no other
// credential is consulted, so a passive monitor works on a machine with no login
// and no API key.
func Post(ctx context.Context, sbom *ossbom.SBOM, apiURL, apiKey, monitorID string) error {
	c, err := NewSubmitClient(ctx, apiURL, apiKey, monitorID)
	if err != nil {
		return err
	}
	return c.Submit(ctx, sbom.ToMiniBOM())
}

// NewSubmitClient picks the client for a submit-only send: a monitor's ingest
// token when one is given, otherwise the ordinary credential chain.
//
// The monitor id wins outright rather than falling back when it fails. A monitor
// names where the scan should land, so quietly sending it under a stored login
// instead would file it against the wrong thing and hide a typo in the id.
func NewSubmitClient(ctx context.Context, apiURL, apiKey, monitorID string) (*client.Client, error) {
	if monitorID != "" {
		return client.NewIngest(apiURL, monitorID)
	}
	return NewClient(ctx, apiURL, apiKey)
}

// NewClient picks the credential and builds the matching client. The stored
// JWT login beats environment API keys so an interactive `ossprey login` isn't
// silently shadowed by a stale key exported in the shell; env keys remain the
// fallback (and the norm in CI, where nobody is logged in). Exported so other
// authenticated commands (e.g. `ossprey precommit`) share the exact same
// resolution order as scan/check rather than reimplementing it.
func NewClient(ctx context.Context, apiURL, apiKey string) (*client.Client, error) {
	if apiKey != "" {
		return client.New(apiURL, apiKey)
	}
	token, loginErr := auth.AccessToken(ctx, nil)
	if loginErr == nil {
		return client.NewBearer(apiURL, token)
	}
	if envKey := client.APIKeyFromEnv(); envKey != "" {
		return client.New(apiURL, envKey)
	}
	if errors.Is(loginErr, auth.ErrNotLoggedIn) {
		return nil, errors.New("no credentials: run `ossprey login`, or set OSSPREY_API_KEY / --api-key")
	}
	return nil, fmt.Errorf("stored login: %w", loginErr)
}
