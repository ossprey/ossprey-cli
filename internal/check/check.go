// Package check scans explicitly-named packages (ecosystem + name@version)
// against the Ossprey API, without needing a project directory on disk. It
// backs both the `check` command and the package-manager forwarder.
package check

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
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
	// Constraint is what the token asked for when it names no single release:
	// an npm range or dist-tag ("^4.17.0", "next"). A resolver uses it to pick
	// the release the manager would install. Empty for a pin or a bare name.
	Constraint string
}

func (s Spec) String() string { return fmt.Sprintf("%s/%s@%s", s.Ecosystem, s.Name, s.Version) }

// Options configures a check run.
type Options struct {
	Specs           []Spec
	APIURL          string
	APIKey          string
	DryRunSafe      bool // skip API; emit no vulnerabilities
	DryRunMalicious bool // skip API; inject a test vulnerability against the first spec
	// SubmitOnly posts the SBOM without waiting for a verdict (passive mode).
	SubmitOnly bool
	// MonitorID routes a SubmitOnly send through a monitor's ingest token
	// instead of the caller's own credential. Ignored unless SubmitOnly.
	MonitorID string
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
	sbom := ossbom.New(ossbom.Environment{
		MachineName: host,
		Project:     scanName(opts.Specs),
	})
	sbom.Name = scanName(opts.Specs)

	for _, s := range opts.Specs {
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
	case opts.SubmitOnly:
		if err := submit.Post(ctx, sbom, opts.APIURL, opts.APIKey, opts.MonitorID); err != nil {
			return nil, err
		}
	default:
		if err := submit.Validate(ctx, sbom, opts.APIURL, opts.APIKey); err != nil {
			return nil, err
		}
	}

	return sbom, nil
}

// scanName builds a human-readable label for the scan from the checked
// packages: "name@version" for a single spec, comma-joined for several. Used as
// both the SBOM name and env.Project so the dashboard shows the package(s)
// instead of falling back to the host machine name.
func scanName(specs []Spec) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.Version == "" {
			parts = append(parts, s.Name)
			continue
		}
		parts = append(parts, s.Name+"@"+s.Version)
	}
	return strings.Join(parts, ", ")
}

func (s Spec) validate() error {
	if normalizeEcosystem(s.Ecosystem) == "" {
		return fmt.Errorf("unsupported ecosystem %q (want pypi, npm or github)", s.Ecosystem)
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
	case "github":
		return "github"
	default:
		return ""
	}
}

// ParseSpec splits a package token ("name", "name@version", "name==version",
// "@scope/name@version") into a Spec for the given ecosystem. Version is set
// only when the token pins exactly one release; a range, a tag or a wildcard
// leaves it empty (npm keeps the range or tag in Constraint) and the caller
// resolves a concrete version. A token naming no registry package (a URL, a
// git or file spec) is an error.
func ParseSpec(ecosystem, token string) (Spec, error) {
	eco := normalizeEcosystem(ecosystem)
	if eco == "" {
		return Spec{}, fmt.Errorf("unsupported ecosystem %q (want pypi, npm or github)", ecosystem)
	}

	var s Spec
	ok := true
	switch eco {
	case "npm":
		s, ok = splitNpm(token)
	case "github":
		s.Name, s.Version = splitLastAt(token)
	case "pypi":
		s, ok = splitPyPI(token)
	}
	if !ok || s.Name == "" {
		return Spec{}, fmt.Errorf("cannot parse package token %q", token)
	}
	s.Ecosystem = eco
	return s, nil
}

// splitLastAt splits "name@ref" at the last '@'; a leading '@' (an npm scope)
// is not a delimiter.
func splitLastAt(token string) (name, version string) {
	at := strings.LastIndex(token, "@")
	if at <= 0 {
		return token, ""
	}
	return token[:at], token[at+1:]
}

// npmExact matches what npm-package-arg treats as one version (semver.valid
// with loose parsing): an optional "v" or "=", then major.minor.patch.
var npmExact = regexp.MustCompile(`^[=v]*\s*(\d+\.\d+\.\d+(?:-?[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)$`)

// splitNpm parses an npm package spec the way npm-package-arg does. Only an
// exact version is a pin: npm sends a range or a tag ("^4.17.0", "next",
// "1.x") to the registry to pick a release, so taking it as a version would
// check a release that does not exist. An alias ("x@npm:evil@1.0.0") installs
// its target under another name, so the target is what gets checked. ok is
// false for a spec that does not come from the registry at all (git, file,
// workspace, a GitHub shorthand).
func splitNpm(token string) (s Spec, ok bool) {
	// The first '@' after a possible scope ends the name; the rest may itself
	// contain '@' (an alias's own version).
	name, spec := token, ""
	if at := strings.Index(token, "@"); at == 0 {
		if at = strings.Index(token[1:], "@"); at >= 0 {
			name, spec = token[:at+1], token[at+2:]
		}
	} else if at > 0 {
		name, spec = token[:at], token[at+1:]
	}
	if rest, alias := strings.CutPrefix(spec, "npm:"); alias {
		return splitNpm(rest)
	}
	spec = strings.TrimSpace(spec)
	if strings.ContainsAny(spec, ":/") {
		return Spec{}, false
	}
	// An unscoped name never contains '/': "user/repo" is a GitHub shorthand.
	if !strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
		return Spec{}, false
	}
	s.Name = name
	if m := npmExact.FindStringSubmatch(spec); m != nil {
		s.Version = m[1]
	} else if spec != "" && spec != "*" && spec != "latest" {
		s.Constraint = spec
	}
	return s, true
}

// pypiName is the leading project name of a requirement (PEP 508).
var pypiName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)

// pypiExact is a plain release after poetry's / the check CLI's "name@".
var pypiExact = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.+!_-]*$`)

// splitPyPI parses a PEP 508 requirement or a user-supplied pypi token. Extras
// ("[security]") and environment markers ("; python_version>'3'") are not part
// of the name. Only an exact single-release pin is a version: "==X" without a
// wildcard, "===X", or "@X" with X a plain release (poetry's and the check
// CLI's form). Anything else — a range, "==2.*", poetry's "@^7.0", "@latest" —
// leaves it unpinned for the caller to resolve. ok is false for a direct
// reference ("pkg @ https://…", "pkg@git+…"), which no registry serves.
func splitPyPI(token string) (s Spec, ok bool) {
	req, _, _ := strings.Cut(token, ";")
	req = strings.TrimSpace(req)
	s.Name = pypiName.FindString(req)
	rest := strings.TrimSpace(req[len(s.Name):])
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end >= 0 {
			rest = strings.TrimSpace(rest[end+1:])
		}
	}
	if v, at := strings.CutPrefix(rest, "@"); at {
		v = strings.TrimSpace(v)
		if strings.ContainsAny(v, ":/") {
			return Spec{}, false
		}
		if pypiExact.MatchString(v) {
			s.Version = v
			return s, true
		}
		rest = v
	}
	rest = strings.TrimSuffix(strings.TrimPrefix(rest, "("), ")")
	for _, clause := range strings.Split(rest, ",") {
		clause = strings.TrimSpace(clause)
		if v, ok := strings.CutPrefix(clause, "==="); ok {
			s.Version = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(clause, "=="); ok && !strings.Contains(v, "*") {
			s.Version = strings.TrimSpace(v)
		}
		if s.Version != "" {
			break
		}
	}
	return s, true
}
