// Package submit holds the shared "send an SBOM to the Ossprey API and apply
// the returned vulnerabilities" flow used by both the scan and check commands.
//
// It is also where the local scan cache (internal/scancache) is consulted:
// both seams below check it before the request and feed it after, so every
// command, forwarder and shim that submits an SBOM gets the same behaviour
// without knowing the cache exists.
package submit

import (
	"context"
	"errors"
	"fmt"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/scancache"
)

// Validate submits the SBOM to the Ossprey API and copies the returned
// vulnerabilities onto it. Credentials resolve in order: the apiKey argument
// (--api-key flag, an explicit per-invocation choice), then the Auth0 login
// stored by `ossprey login` (refreshed silently if expired), then the
// OSSPREY_API_KEY / API_KEY environment variables. The credential decides the
// API mount: JWTs go to /dashboard/v1, API keys to /public/v1.
//
// When this machine validated the identical SBOM against the same API with the
// same credential within the cache TTL and the answer was clean, that answer
// is replayed through ApplyAPIResponse and nothing is sent. Only a clean
// response is ever stored: malware, an informational finding, a quota skip,
// a failure or an error always goes live next time (OSS-2229).
//
// A *client.ErrSkipped error flows back unwrapped so callers can detect a
// quota skip via errors.As and report it without failing the build.
func Validate(ctx context.Context, sbom *ossbom.SBOM, apiURL, apiKey string) error {
	c, identity, err := resolveClient(ctx, apiURL, apiKey)
	if err != nil {
		return err
	}
	mb := sbom.ToMiniBOM()
	cache := scancache.New(ctx, scancache.KeyInput{
		Kind:       scancache.Verdict,
		APIURL:     c.BaseURL,
		Identity:   identity,
		CLIVersion: client.Version,
		BOM:        mb,
	})
	// A stored response that no longer parses is a miss, not an error: the
	// SBOM is untouched when ApplyAPIResponse fails, so the live path below
	// starts from the same place it would have without a cache.
	if raw, age, ok := cache.Get(); ok && sbom.ApplyAPIResponse(raw) == nil {
		cache.Hit(age)
		return nil
	}
	raw, err := c.Validate(ctx, mb)
	if err != nil {
		return err
	}
	if err := sbom.ApplyAPIResponse(raw); err != nil {
		return err
	}
	if scancache.Clean(raw) {
		cache.Put(raw)
	}
	return nil
}

// Post submits the SBOM and returns as soon as the API has accepted it, without
// waiting for a verdict. This is what `--passive` and the watchdog/monitor shims
// use: results appear in the dashboard rather than gating the caller.
//
// A non-empty monitorID selects the unauthenticated ingest route and no other
// credential is consulted, so a passive monitor works on a machine with no login
// and no API key.
//
// An identical SBOM already accepted from this machine, for the same API and
// credential, within the cache TTL is not sent again. The entry that records
// an acceptance carries no verdict and is a different kind from the one
// Validate reads, so a passive post can never let a blocking scan pass.
func Post(ctx context.Context, sbom *ossbom.SBOM, apiURL, apiKey, monitorID string) error {
	c, identity, err := resolveSubmitClient(ctx, apiURL, apiKey, monitorID)
	if err != nil {
		return err
	}
	mb := sbom.ToMiniBOM()
	cache := scancache.New(ctx, scancache.KeyInput{
		Kind:       scancache.Posted,
		APIURL:     c.BaseURL,
		Identity:   identity,
		CLIVersion: client.Version,
		BOM:        mb,
	})
	if _, age, ok := cache.Get(); ok {
		cache.Hit(age)
		return nil
	}
	if err := c.Submit(ctx, mb); err != nil {
		return err
	}
	cache.Put(nil)
	return nil
}

// NewSubmitClient picks the client for a submit-only send: a monitor's ingest
// token when one is given, otherwise the ordinary credential chain.
//
// The monitor id wins outright rather than falling back when it fails. A monitor
// names where the scan should land, so quietly sending it under a stored login
// instead would file it against the wrong thing and hide a typo in the id.
func NewSubmitClient(ctx context.Context, apiURL, apiKey, monitorID string) (*client.Client, error) {
	c, _, err := resolveSubmitClient(ctx, apiURL, apiKey, monitorID)
	return c, err
}

// resolveSubmitClient is NewSubmitClient plus the cache identity of the
// credential it chose: the monitor id's fingerprint, or whatever
// resolveClient reports.
func resolveSubmitClient(ctx context.Context, apiURL, apiKey, monitorID string) (*client.Client, string, error) {
	if monitorID != "" {
		c, err := client.NewIngest(apiURL, monitorID)
		if err != nil {
			return nil, "", err
		}
		return c, scancache.FingerprintMonitor(monitorID), nil
	}
	return resolveClient(ctx, apiURL, apiKey)
}

// NewClient picks the credential and builds the matching client. The stored
// JWT login beats environment API keys so an interactive `ossprey login` isn't
// silently shadowed by a stale key exported in the shell; env keys remain the
// fallback (and the norm in CI, where nobody is logged in). Exported so other
// authenticated commands (e.g. `ossprey precommit`) share the exact same
// resolution order as scan/check rather than reimplementing it.
func NewClient(ctx context.Context, apiURL, apiKey string) (*client.Client, error) {
	c, _, err := resolveClient(ctx, apiURL, apiKey)
	return c, err
}

// resolveClient is NewClient plus the cache identity of the credential it
// chose. The identity is a fingerprint, never the credential: the hash of an
// API key, or of the login's email/subject. A stored login whose ID token
// names nobody has no identity, and "" tells the cache to stand down rather
// than file every such login under the same key.
func resolveClient(ctx context.Context, apiURL, apiKey string) (*client.Client, string, error) {
	if apiKey != "" {
		c, err := client.New(apiURL, apiKey)
		if err != nil {
			return nil, "", err
		}
		return c, scancache.FingerprintAPIKey(apiKey), nil
	}
	session, loginErr := auth.Session(ctx, nil)
	if loginErr == nil {
		c, err := client.NewBearer(apiURL, session.AccessToken)
		if err != nil {
			return nil, "", err
		}
		return c, scancache.FingerprintLogin(session.Identity()), nil
	}
	if envKey := client.APIKeyFromEnv(); envKey != "" {
		c, err := client.New(apiURL, envKey)
		if err != nil {
			return nil, "", err
		}
		return c, scancache.FingerprintAPIKey(envKey), nil
	}
	if errors.Is(loginErr, auth.ErrNotLoggedIn) {
		return nil, "", errors.New("no credentials: run `ossprey login`, or set OSSPREY_API_KEY / --api-key")
	}
	return nil, "", fmt.Errorf("stored login: %w", loginErr)
}
