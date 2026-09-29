// Package trust decides which packages a scan leaves out because they come
// from a source the user has declared as their own: a private registry, or an
// npm scope they control.
//
// Trusted packages are not checked and are not sent in the SBOM. That makes
// every rule here a hole in the scan by design, so the rules are narrow:
//
//   - A registry is matched on its full URL prefix, never on its host. Two
//     CodeArtifact repositories — one holding internal packages, one proxying
//     the public index — share a host and differ only in path, and trusting the
//     host would trust the proxy.
//   - Registry trust is decided from where the lockfile says a package was
//     fetched, never from its name. Anyone can publish "my-org-anything" to PyPI;
//     the case an ignore must never hide is an internal name resolved from the
//     public index (dependency confusion).
//   - No recorded source means not trusted. The package is checked as before.
//
// npm scopes are the one name-based rule, because npm makes the scope the
// thing that selects a registry: `@org:registry=` in .npmrc sends every
// `@org/*` package there and never falls back to the public registry.
//
// The policy lives on the machine (trust.json beside credentials.json) or in
// the environment, deliberately never in the scanned repository: a pull
// request that could add a registry to the trusted list could exempt its own
// dependencies from the scan.
package trust

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
)

// Policy is the set of trusted sources. The zero value trusts nothing.
type Policy struct {
	// Registries are normalised registry URL prefixes (see NormalizeRegistry).
	Registries []string `json:"registries,omitempty"`
	// NpmScopes are lower-cased npm scopes including the leading '@'.
	NpmScopes []string `json:"npm_scopes,omitempty"`
}

// Empty reports whether the policy trusts nothing, so callers can skip work.
func (p Policy) Empty() bool { return len(p.Registries) == 0 && len(p.NpmScopes) == 0 }

// TrustsRegistry reports whether a package fetched from rawURL came from a
// trusted registry. rawURL is whatever the lockfile recorded — a tarball URL,
// an index URL, a wheel URL — and it is trusted when it sits at or below one
// of the policy's registry prefixes. Anything that does not parse as an
// http(s) URL with a host is not trusted.
func (p Policy) TrustsRegistry(rawURL string) bool {
	if len(p.Registries) == 0 {
		return false
	}
	candidate, err := canonicalURL(rawURL)
	if err != nil {
		return false
	}
	for _, r := range p.Registries {
		if under(candidate, r) {
			return true
		}
	}
	return false
}

// TrustsNpmScope reports whether the npm package name is in a trusted scope.
// Unscoped names are never trusted by this rule.
func (p Policy) TrustsNpmScope(name string) bool {
	scope, ok := npmScope(name)
	if !ok {
		return false
	}
	return slices.Contains(p.NpmScopes, scope)
}

// Trusts reports whether a package is trusted: an npm package in a trusted
// scope, or one whose every recorded registry is trusted. registries holds
// the sources the catalogers recorded for it; empty entries are ignored, and
// no recorded source at all means it is not trusted by registry.
//
// Every recorded source must be trusted, not just one: the same name@version
// seen once from the internal index and once from the public one has at least
// one install that fetches it publicly, and that one needs checking.
func (p Policy) Trusts(ecosystem, name string, registries []string) bool {
	if ecosystem == "npm" && p.TrustsNpmScope(name) {
		return true
	}
	seen := false
	for _, r := range registries {
		if r == "" {
			continue
		}
		if !p.TrustsRegistry(r) {
			return false
		}
		seen = true
	}
	return seen
}

// Merge returns the union of p and other, keeping each entry once.
func (p Policy) Merge(other Policy) Policy {
	return Policy{
		Registries: union(p.Registries, other.Registries),
		NpmScopes:  union(p.NpmScopes, other.NpmScopes),
	}
}

// Without returns p minus the entries in other.
func (p Policy) Without(other Policy) Policy {
	keep := func(have, drop []string) []string {
		var out []string
		for _, v := range have {
			if !slices.Contains(drop, v) {
				out = append(out, v)
			}
		}
		return out
	}
	return Policy{
		Registries: keep(p.Registries, other.Registries),
		NpmScopes:  keep(p.NpmScopes, other.NpmScopes),
	}
}

// Parse validates user-supplied registries and scopes into a Policy, failing
// on the first entry that does not validate. For the `trust` command, where a
// typo must be an error rather than a quietly smaller policy.
func Parse(registries, scopes []string) (Policy, error) {
	var policy Policy
	for _, r := range registries {
		n, err := NormalizeRegistry(r)
		if err != nil {
			return Policy{}, err
		}
		policy.Registries = union(policy.Registries, []string{n})
	}
	for _, s := range scopes {
		n, err := NormalizeNpmScope(s)
		if err != nil {
			return Policy{}, err
		}
		policy.NpmScopes = union(policy.NpmScopes, []string{n})
	}
	return policy, nil
}

// NormalizeRegistry validates a registry URL a user wants to trust and returns
// the form it is stored and compared in: lower-case scheme and host, no
// default port, a cleaned path ending in '/', no query or fragment.
//
// Credentials in the URL are refused rather than stripped. This file is not a
// secret store, and a user pasting a tokenised URL out of their .npmrc should
// hear about it instead of finding it written to disk.
func NormalizeRegistry(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("registry %q: %w", raw, err)
	}
	if u.User != nil {
		return "", fmt.Errorf("registry %q: remove the credentials from the URL; only the address is needed", redactUser(raw))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("registry %q: a registry URL takes no query string or fragment", raw)
	}
	canon, err := canonicalURL(raw)
	if err != nil {
		return "", fmt.Errorf("registry %q: %w", raw, err)
	}
	return canon, nil
}

var npmScopePattern = regexp.MustCompile(`^@[a-z0-9][a-z0-9._~-]*$`)

// NormalizeNpmScope validates an npm scope ("@org", "org" or "@org/") and
// returns it as "@org". npm scope names are lower case.
func NormalizeNpmScope(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, "/")
	if s != "" && !strings.HasPrefix(s, "@") {
		s = "@" + s
	}
	if !npmScopePattern.MatchString(s) {
		return "", fmt.Errorf("npm scope %q: want a scope such as @my-org", raw)
	}
	return s, nil
}

// canonicalURL reduces an http(s) URL to scheme://host[:port]/clean/path/ —
// the comparison form. The path is cleaned after decoding, so a lockfile
// entry spelling "/internal/../public/" (or "%2e%2e") is compared as
// "/public/", which is where the request actually lands.
func canonicalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", errors.New("want an http:// or https:// URL")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("URL has no host")
	}
	if port := u.Port(); port != "" && !(scheme == "https" && port == "443") && !(scheme == "http" && port == "80") {
		host += ":" + port
	}
	p := path.Clean("/" + u.Path)
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	return scheme + "://" + host + p, nil
}

// under reports whether candidate is prefix or below it. Both are canonical,
// so both end in '/', which is what keeps "/internal/" from matching
// "/internal-proxy/".
func under(candidate, prefix string) bool {
	return strings.HasPrefix(candidate, prefix)
}

func npmScope(name string) (string, bool) {
	if !strings.HasPrefix(name, "@") {
		return "", false
	}
	scope, _, ok := strings.Cut(name, "/")
	if !ok || scope == "@" {
		return "", false
	}
	return strings.ToLower(scope), true
}

func union(a, b []string) []string {
	var out []string
	for _, v := range slices.Concat(a, b) {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// redactUser hides the userinfo in an error message, since it is most likely
// a token.
func redactUser(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("REDACTED")
	return u.String()
}
