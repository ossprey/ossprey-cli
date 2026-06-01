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

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/submit"
)

// Spec identifies one package to check. Ecosystem is the OSSBOM component type
// ("pypi" or "npm"). Version may be empty; callers resolve a concrete version
// (e.g. via internal/registry) before calling Run.
type Spec struct {
	Ecosystem string
	Name      string
	Version   string
}

func (s Spec) String() string { return fmt.Sprintf("%s/%s@%s", s.Ecosystem, s.Name, s.Version) }

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

	host, _ := os.Hostname() // best-effort; empty hostname is acceptable
	sbom := ossbom.New(ossbom.Environment{MachineName: host})

	for _, s := range opts.Specs {
		if err := s.validate(); err != nil {
			return nil, err
		}
		sbom.AddComponent(ossbom.Component{
			Name:    s.Name,
			Version: s.Version,
			Type:    s.Ecosystem,
			Source:  []string{"check"},
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

func (s Spec) validate() error {
	if normalizeEcosystem(s.Ecosystem) == "" {
		return fmt.Errorf("unsupported ecosystem %q (want pypi or npm)", s.Ecosystem)
	}
	if s.Name == "" {
		return errors.New("package name is required")
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
