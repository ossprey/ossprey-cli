// Package submit holds the shared "send an SBOM to the Ossprey API and apply
// the returned vulnerabilities" flow used by both the scan and check commands.
package submit

import (
	"context"

	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Validate submits the SBOM to the Ossprey API and copies the returned
// vulnerabilities onto it. The API key falls back to the OSSPREY_API_KEY /
// API_KEY environment variables when apiKey is empty.
//
// A *client.ErrSkipped error flows back unwrapped so callers can detect a
// quota skip via errors.As and report it without failing the build.
func Validate(ctx context.Context, sbom *ossbom.SBOM, apiURL, apiKey string) error {
	if apiKey == "" {
		apiKey = client.APIKeyFromEnv()
	}
	c, err := client.New(apiURL, apiKey)
	if err != nil {
		return err
	}
	raw, err := c.Validate(ctx, sbom.ToMiniBOM())
	if err != nil {
		return err
	}
	return sbom.ApplyAPIResponse(raw)
}
