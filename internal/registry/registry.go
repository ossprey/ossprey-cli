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

	"github.com/Masterminds/semver/v3"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// DefaultHTTP is the client used by ResolveLatest. Overridable in tests.
var DefaultHTTP = &http.Client{Timeout: 15 * time.Second}

// crates.io answers 403 to a generic client, so identify ourselves (OSS-1747).
const userAgent = "ossprey-cli (+https://github.com/ossprey/ossprey-cli)"

// Registry base URLs. Vars (not consts) so tests can point them at httptest.
var (
	npmBaseURL    = "https://registry.npmjs.org/"
	pypiBaseURL   = "https://pypi.org/pypi/"
	cratesBaseURL = "https://crates.io/api/v1/crates/"
)

// CanResolve reports whether ResolveLatest knows this ecosystem, so callers do
// not carry their own copy of the list and drift from it.
func CanResolve(ecosystem string) bool {
	switch ecosystem {
	case "npm", "pypi", "cargo":
		return true
	}
	return false
}

// ResolveLatest returns the latest version string for name in the given
// ecosystem ("npm" or "pypi").
func ResolveLatest(ctx context.Context, ecosystem, name string) (string, error) {
	switch ecosystem {
	case "npm":
		return resolveNpm(ctx, name)
	case "pypi":
		return resolvePyPI(ctx, name)
	case "cargo":
		return resolveCargo(ctx, name)
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

// ErrNoMatch reports a specifier that names no published release: a range
// nothing satisfies, or a word that is neither a range nor a dist-tag. Not an
// outage and not a missing package, so callers grade it apart from both.
var ErrNoMatch = errors.New("no published version matches")

// ResolveNpmSpec returns the release npm itself would pick for name@spec: the
// version a dist-tag points at (`next`, `beta`), or the highest published
// version a range allows (`^1`, `1.x`). An empty spec means latest.
//
// Checking latest instead would pass a clean `latest` while npm runs whatever
// the tag or an older major line points at, which is exactly where a malicious
// release can sit unnoticed. As in npm, a spec that parses as a range is a
// range; only otherwise is it looked up as a tag.
func ResolveNpmSpec(ctx context.Context, name, spec string) (string, error) {
	if spec == "" {
		return resolveNpm(ctx, name)
	}
	// The abbreviated packument carries dist-tags and every version, and is a
	// fraction of the full document's size for a popular package.
	var body struct {
		DistTags map[string]string          `json:"dist-tags"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := getJSONAccept(ctx, npmBaseURL+url.PathEscape(name),
		"application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8", &body); err != nil {
		return "", err
	}
	constraint, err := semver.NewConstraint(spec)
	if err != nil {
		if v := body.DistTags[spec]; v != "" {
			return v, nil
		}
		return "", fmt.Errorf("%w %s@%s (not a range or a dist-tag)", ErrNoMatch, name, spec)
	}
	// npm-pick-manifest's order: the latest tag when the range allows it, else
	// the highest match that is not deprecated, else the highest match at all.
	if latest, err := semver.StrictNewVersion(body.DistTags["latest"]); err == nil && constraint.Check(latest) {
		return latest.Original(), nil
	}
	var best, bestDeprecated *semver.Version
	for raw, meta := range body.Versions {
		v, err := semver.StrictNewVersion(raw)
		if err != nil || !constraint.Check(v) {
			continue
		}
		var m struct {
			Deprecated any `json:"deprecated"`
		}
		_ = json.Unmarshal(meta, &m)
		deprecated := m.Deprecated != nil && m.Deprecated != false && m.Deprecated != ""
		if deprecated {
			if bestDeprecated == nil || v.GreaterThan(bestDeprecated) {
				bestDeprecated = v
			}
		} else if best == nil || v.GreaterThan(best) {
			best = v
		}
	}
	if best == nil {
		best = bestDeprecated
	}
	if best == nil {
		return "", fmt.Errorf("%w %s@%s", ErrNoMatch, name, spec)
	}
	return best.Original(), nil
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

// resolveCargo reads the crate's latest stable release. Unreached today, since
// Cargo.lock always pins and resolveVersionless skips anything versioned, but a
// hand-written SBOM can still arrive carrying a bare crate name.
func resolveCargo(ctx context.Context, name string) (string, error) {
	endpoint := cratesBaseURL + url.PathEscape(name)
	var body struct {
		Crate struct {
			MaxStableVersion string `json:"max_stable_version"`
			NewestVersion    string `json:"newest_version"`
		} `json:"crate"`
	}
	if err := getJSON(ctx, endpoint, &body); err != nil {
		return "", err
	}
	// max_stable_version is empty for a crate that has only ever pre-released.
	if v := body.Crate.MaxStableVersion; v != "" {
		return v, nil
	}
	if v := body.Crate.NewestVersion; v != "" {
		return v, nil
	}
	return "", fmt.Errorf("crates.io returned no version for %q", name)
}

func getJSON(ctx context.Context, endpoint string, out any) error {
	return getJSONAccept(ctx, endpoint, "application/json", out)
}

func getJSONAccept(ctx context.Context, endpoint, accept string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", userAgent)
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
	if errors.Is(err, ErrNoMatch) {
		return warn.Entry{
			Class: "registry-nomatch:" + outcome,
			One:   "1 package version specifier matched no published release; " + outcome,
			Many:  "%d package version specifiers matched no published release; " + outcome,
			Item:  err.Error(),
		}
	}
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
