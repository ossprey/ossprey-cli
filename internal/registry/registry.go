// Package registry resolves the latest published version of a package from its
// upstream registry (npm registry, PyPI). Used to fill in a version when the
// user names a package without pinning one (e.g. `ossprey npm install lodash`).
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// DefaultHTTP is the client used by ResolveLatest. Overridable in tests.
var DefaultHTTP = &http.Client{Timeout: 15 * time.Second}

// Registry base URLs. Vars (not consts) so tests can point them at httptest.
var (
	npmBaseURL  = "https://registry.npmjs.org/"
	pypiBaseURL = "https://pypi.org/pypi/"
)

// ResolveLatest returns the latest version string for name in the given
// ecosystem ("npm" or "pypi").
func ResolveLatest(ctx context.Context, ecosystem, name string) (string, error) {
	switch ecosystem {
	case "npm":
		return resolveNpm(ctx, name)
	case "pypi":
		return resolvePyPI(ctx, name)
	default:
		return "", fmt.Errorf("cannot resolve latest version: unsupported ecosystem %q", ecosystem)
	}
}

// resolveNpm reads dist-tags.latest from the npm registry packument.
func resolveNpm(ctx context.Context, name string) (string, error) {
	// npm encodes a scoped name "@scope/pkg" as "@scope%2Fpkg"; url.PathEscape
	// escapes the slash and leaves the leading @ intact, which the registry accepts.
	endpoint := npmBaseURL + url.PathEscape(name)
	var body struct {
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
	}
	if err := getJSON(ctx, endpoint, &body); err != nil {
		return "", err
	}
	if body.DistTags.Latest == "" {
		return "", fmt.Errorf("npm registry returned no latest version for %q", name)
	}
	return body.DistTags.Latest, nil
}

// resolvePyPI reads info.version from the PyPI JSON API.
func resolvePyPI(ctx context.Context, name string) (string, error) {
	endpoint := pypiBaseURL + url.PathEscape(name) + "/json"
	var body struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := getJSON(ctx, endpoint, &body); err != nil {
		return "", err
	}
	if body.Info.Version == "" {
		return "", fmt.Errorf("PyPI returned no version for %q", name)
	}
	return body.Info.Version, nil
}

// ErrNotFound reports that the registry has no such package. A private or
// internal package answers this way, so callers grade it apart from an outage:
// one is expected, the other means the scan resolved almost nothing.
var ErrNotFound = errors.New("not on the public registry")

func getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := DefaultHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("registry request: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		// Not an outage: the normal answer for a private or internal package.
		return fmt.Errorf("%w (registry returned status 404)", ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry returned status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode registry response: %w", err)
	}
	return nil
}

// UnresolvedEntry grades a failed registry lookup. A 404 is the expected answer
// for a private or internal package; anything else is an outage, and the two
// must never share a count — 400 packages "not on the public registry" is
// normal for a monorepo, 400 packages behind an unreachable registry means the
// scan resolved almost nothing. outcome names the consequence, which differs
// between the scan path (submitted unversioned) and the forward path (not
// checked at all).
func UnresolvedEntry(ecosystem, name string, err error, outcome string) warn.Entry {
	if errors.Is(err, ErrNotFound) {
		return warn.Entry{
			Class: "registry-missing:" + outcome,
			One:   "1 package not on the public registry; " + outcome,
			Many:  "%d packages not on the public registry; " + outcome,
			Item:  fmt.Sprintf("%s/%s (404)", ecosystem, name),
		}
	}
	return warn.Entry{
		Class: "registry-down:" + outcome,
		One:   "1 package could not be resolved (registry unreachable); " + outcome,
		Many:  "%d packages could not be resolved (registry unreachable); " + outcome,
		Item:  fmt.Sprintf("%s/%s (%v)", ecosystem, name, err),
	}
}
