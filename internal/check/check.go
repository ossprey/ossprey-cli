// Package check scans explicitly-named packages (ecosystem + name@version)
// against the Ossprey API, without needing a project directory on disk. It
// backs both the `check` command and the package-manager forwarder.
package check

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/gitenv"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/submit"
)

// Spec identifies one package to check. Ecosystem is the OSSBOM component type
// ("pypi", "npm" or "github"). Namespace is the PURL namespace — the repo owner
// for github specs, empty otherwise. Version may be empty for pypi/npm; callers
// resolve a concrete version (e.g. via internal/registry) before calling Run.
type Spec struct {
	Ecosystem string
	Namespace string // github repo owner; empty for pypi/npm
	Name      string
	Version   string
}

func (s Spec) String() string {
	if s.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s@%s", s.Ecosystem, s.Namespace, s.Name, s.Version)
	}
	return fmt.Sprintf("%s/%s@%s", s.Ecosystem, s.Name, s.Version)
}

// Options configures a check run.
type Options struct {
	Specs           []Spec
	APIURL          string
	APIKey          string
	DryRunSafe      bool // skip API; emit no vulnerabilities
	DryRunMalicious bool // skip API; inject a test vulnerability against the first spec
}

// Run builds a one-component-per-spec SBOM, submits it to the Ossprey API, and
// returns the SBOM with any vulnerabilities applied. Every Spec must have a
// non-empty Ecosystem, Name and Version.
func Run(ctx context.Context, opts Options) (*ossbom.SBOM, error) {
	if len(opts.Specs) == 0 {
		return nil, errors.New("no packages to check")
	}

	for _, s := range opts.Specs {
		if err := s.validate(); err != nil {
			return nil, err
		}
	}

	host, _ := os.Hostname() // best-effort; empty hostname is acceptable
	// Project names the scan in the dashboard. Without it the UI falls back to
	// the machine name (the host), so a package check would surface as the host
	// rather than the package(s) being checked.
	env := ossbom.Environment{
		MachineName: host,
		Project:     scanName(opts.Specs),
	}
	// A single github repo check is a "scan the repo itself" submission: set the
	// owner/repo/ref on the environment so the dashboard titles it
	// "org/repo@ref" and links to the source rather than showing a hash.
	if len(opts.Specs) == 1 && opts.Specs[0].Ecosystem == "github" {
		s := opts.Specs[0]
		env.GithubOrg = s.Namespace
		env.GithubRepo = s.Name
		env.Branch = s.Version
		env.ProductEnv = gitenv.Detect(".").ProductEnv
	}
	sbom := ossbom.New(env)
	sbom.Name = scanName(opts.Specs)

	for _, s := range opts.Specs {
		sbom.AddComponent(ossbom.Component{
			Name:      s.Name,
			Namespace: s.Namespace,
			Version:   s.Version,
			Type:      s.Ecosystem,
			Source:    []string{sourceFor(s.Ecosystem)},
		})
	}

	switch {
	case opts.DryRunMalicious:
		if err := scan.InjectTestVulnerability(sbom); err != nil {
			return nil, err
		}
	case opts.DryRunSafe:
		// no-op: leave the vulnerability list empty
	default:
		if err := submit.Validate(ctx, sbom, opts.APIURL, opts.APIKey); err != nil {
			return nil, err
		}
	}

	return sbom, nil
}

// scanName builds a human-readable label for the scan from the checked
// packages: "[namespace/]name@version" for a single spec, comma-joined for
// several. Used as both the SBOM name and env.Project so the dashboard shows the
// package(s) instead of falling back to the host machine name.
func scanName(specs []Spec) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		parts = append(parts, specLabel(s))
	}
	return strings.Join(parts, ", ")
}

// specLabel renders one spec as "owner/name@version" (github) or "name@version",
// dropping the "@version" when unpinned.
func specLabel(s Spec) string {
	name := s.Name
	if s.Namespace != "" {
		name = s.Namespace + "/" + name
	}
	if s.Version == "" {
		return name
	}
	return name + "@" + s.Version
}

// sourceFor labels where a component came from. github repos are tagged
// "github" (matching the python client); everything else came via `check`.
func sourceFor(ecosystem string) string {
	if ecosystem == "github" {
		return "github"
	}
	return "check"
}

func (s Spec) validate() error {
	if normalizeEcosystem(s.Ecosystem) == "" {
		return fmt.Errorf("unsupported ecosystem %q (want pypi, npm or github)", s.Ecosystem)
	}
	if s.Name == "" {
		return errors.New("package name is required")
	}
	if s.Ecosystem == "github" && s.Namespace == "" {
		return fmt.Errorf("github package %q is missing an owner (want owner/repo)", s.Name)
	}
	if s.Version == "" {
		return fmt.Errorf("package %q is missing a version", s.Name)
	}
	return nil
}

// normalizeEcosystem maps user-facing aliases to OSSBOM component types, or ""
// when unsupported.
func normalizeEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "pypi", "pip", "python", "pypy":
		return "pypi"
	case "npm", "node", "javascript", "js", "yarn":
		return "npm"
	case "github", "gh", "git":
		return "github"
	default:
		return ""
	}
}

// ParseSpec splits a package token ("name", "name@version", "name==version",
// "@scope/name@version") into a Spec for the given ecosystem. Version is left
// empty when the token is unpinned or uses a range specifier (>=, ~=, …); the
// caller is expected to resolve a concrete version in that case.
func ParseSpec(ecosystem, token string) (Spec, error) {
	eco := normalizeEcosystem(ecosystem)
	if eco == "" {
		return Spec{}, fmt.Errorf("unsupported ecosystem %q (want pypi or npm)", ecosystem)
	}

	if eco == "github" {
		owner, repo, ref, err := splitGitHub(token)
		if err != nil {
			return Spec{}, err
		}
		return Spec{Ecosystem: eco, Namespace: owner, Name: repo, Version: ref}, nil
	}

	var name, version string
	switch eco {
	case "npm":
		name, version = splitNpm(token)
	case "pypi":
		name, version = splitPyPI(token)
	}
	if name == "" {
		return Spec{}, fmt.Errorf("cannot parse package token %q", token)
	}
	return Spec{Ecosystem: eco, Name: name, Version: version}, nil
}

// splitGitHub parses a github repo token into (owner, repo, ref). Accepted forms:
//   - "owner/repo"                     -> ref defaults to "HEAD"
//   - "owner/repo@v1.2.3"              -> ref = v1.2.3 (branch / tag / commit)
//   - "https://github.com/owner/repo"  -> any github URL (https or ssh), ref HEAD
//   - "git@github.com:owner/repo.git"
//
// A trailing "@ref" is honored on the shorthand form only; URLs use HEAD.
func splitGitHub(token string) (owner, repo, ref string, err error) {
	token = strings.TrimSpace(token)
	ref = "HEAD"

	if strings.Contains(token, "github.com") {
		o, r, ok := gitenv.ParseRemoteURL(token)
		if !ok {
			return "", "", "", fmt.Errorf("cannot parse github url %q", token)
		}
		return o, r, ref, nil
	}

	// shorthand "owner/repo[@ref]"
	path := token
	if at := strings.LastIndex(token, "@"); at > 0 {
		if r := token[at+1:]; r != "" {
			ref = r
		}
		path = token[:at]
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	o, r, ok := strings.Cut(path, "/")
	if !ok || o == "" || r == "" || strings.Contains(r, "/") {
		return "", "", "", fmt.Errorf("cannot parse github repo %q (want owner/repo)", token)
	}
	return o, r, ref, nil
}

// splitNpm parses "name@version" / "@scope/name@version" / "name". The version
// delimiter is the last '@'; a leading '@' (scoped package) is not a delimiter.
func splitNpm(token string) (name, version string) {
	at := strings.LastIndex(token, "@")
	if at <= 0 {
		return token, ""
	}
	return token[:at], token[at+1:]
}

// splitPyPI parses a pip requirement / user-supplied pypi token:
//   - "name==version"            -> concrete version
//   - "name>=1" and other ranges -> bare name (caller resolves latest)
//   - "name@version"             -> concrete version (the `check` CLI's friendly
//     form); ignored when the part after '@' looks like a URL/VCS ref
//     (contains '/' or ':'), e.g. pip's "pkg @ git+https://…".
func splitPyPI(token string) (name, version string) {
	if i := strings.IndexAny(token, "=<>~!"); i >= 0 {
		name = token[:i]
		if rest := token[i:]; strings.HasPrefix(rest, "==") {
			version = rest[2:]
		}
		return name, version
	}
	if at := strings.LastIndex(token, "@"); at > 0 {
		if rest := token[at+1:]; rest != "" && !strings.ContainsAny(rest, "/:") {
			return token[:at], rest
		}
	}
	return token, ""
}
