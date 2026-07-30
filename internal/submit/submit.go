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
// (--api-key flag), the OSSPREY_API_KEY / API_KEY environment variables, then
// the Auth0 login stored by `ossprey login` (refreshed silently if expired).
//
// A *client.ErrSkipped error flows back unwrapped so callers can detect a
// quota skip via errors.As and report it without failing the build.
func Validate(ctx context.Context, sbom *ossbom.SBOM, apiURL, apiKey string) error {
	c, err := newClient(ctx, apiURL, apiKey)
	if err != nil {
		return err
	}
	raw, err := c.Validate(ctx, sbom.ToMiniBOM())
	if err != nil {
		return err
	}
	return sbom.ApplyAPIResponse(raw)
}

// newClient picks the credential (API key beats stored login) and builds the
// matching client.
func newClient(ctx context.Context, apiURL, apiKey string) (*client.Client, error) {
	if apiKey == "" {
		apiKey = client.APIKeyFromEnv()
	}
	if apiKey != "" {
		return client.New(apiURL, apiKey)
	}
	token, err := auth.AccessToken(ctx, nil)
	if errors.Is(err, auth.ErrNotLoggedIn) {
		return nil, errors.New("no credentials: run `ossprey login`, or set OSSPREY_API_KEY / --api-key")
	}
	if err != nil {
		return nil, fmt.Errorf("stored login: %w", err)
	}
	return client.NewBearer(apiURL, token)
}
