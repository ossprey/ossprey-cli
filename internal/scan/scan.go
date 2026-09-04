package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/packageurl-go"

	"github.com/ossprey/ossprey-cli/internal/apitext"
	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/env"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/severity"
)

type Options struct {
	Path    string
	Verbose bool
	// SkipVersionLookup disables the registry lookup that resolves unpinned
	// components to their latest published version, leaving them versionless.
	SkipVersionLookup bool
}

// ErrNoComponents is returned by InjectTestVulnerability when nothing was catalogued.
var ErrNoComponents = errors.New("no components found to inject test vulnerability")

// Run catalogues `path` and returns a populated SBOM (no vulnerabilities).
// Callers decide what to do next: dump JSON, submit to API, etc.
func Run(ctx context.Context, opts Options) (*ossbom.SBOM, error) {
	if _, err := os.Stat(opts.Path); err != nil {
		return nil, fmt.Errorf("scan path: %w", err)
	}

	pkgs, err := catalog.Catalog(ctx, opts.Path, catalog.Options{
		SkipVersionLookup: opts.SkipVersionLookup,
	})
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}

	abs, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve scan path: %w", err)
	}
	host, _ := os.Hostname() // best-effort; empty hostname is acceptable

	scanEnv := ossbom.Environment{Path: abs, MachineName: host}
	env.Overlay(&scanEnv)
	// Fallback only: an ADO agent checks out into ".../1/s", so CI names it instead.
	if scanEnv.Project == "" {
		scanEnv.Project = filepath.Base(abs)
	}
	sbom := ossbom.New(scanEnv)
	sbom.Name = scanEnv.Project

	for _, p := range pkgs {
		c := ossbom.Component{
			Name:     p.Name,
			Version:  p.Version,
			Type:     p.Type,
			Source:   p.Source,
			Location: p.Locations,
		}
		// Flag locally-defined packages (uv path/workspace sources, poetry path
		// deps) so the platform can filter them before scanning (OSS-1389). The
		// flag rides in metadata because it round-trips through the OSSBOM the
		// platform parses from `--local` output.
		if p.Local {
			c.Metadata = map[string]any{"local": true}
		}
		sbom.AddComponent(c)
	}

	return sbom, nil
}

// InjectTestVulnerability appends a fake malware finding against the first component.
// Mirrors v1 --dry-run-malicious behavior.
func InjectTestVulnerability(sbom *ossbom.SBOM) error {
	if len(sbom.Components) == 0 {
		return ErrNoComponents
	}
	c := sbom.Components[0]
	purl := fmt.Sprintf("pkg:%s/%s@%s", c.Type, c.Name, c.Version)
	sbom.AddVulnerability(ossbom.NewMalwareVulnerability(
		"TEST-2024-0001",
		purl,
		"This is a test vulnerability added in dry-run-malicious mode",
	))
	return nil
}

// MalwareSummary is the human-facing rendering of a scan's findings, split by
// whether they fail. The wording lives here rather than at the call sites so
// the verdict text and the exit decision cannot drift apart between scan,
// check, init and the install forwarder.
type MalwareSummary struct {
	// Failing is one v1-style line per finding at or above the floor.
	Failing []string
	// Informational is one line per finding below it, reported but not fatal.
	Informational []string
}

// MalwareReports renders a scanned SBOM's findings and reports whether any of
// them fail at the given floor.
//
// A finding below the floor (severity Info by default) is reported but does not
// make the scan fail; see internal/severity. A finding the API could not grade
// fails at every floor, so an older server that sends no severity behaves
// exactly as before.
func MalwareReports(sbom *ossbom.SBOM, floor severity.Level) (MalwareSummary, bool) {
	var summary MalwareSummary
	for _, v := range sbom.Vulnerabilities {
		_, name, version := parsePurl(v.Purl)
		if severity.Parse(v.Severity).FailsAt(floor) {
			summary.Failing = append(summary.Failing,
				fmt.Sprintf("WARNING: %s:%s contains malware. Remediate this immediately", name, version))
			continue
		}
		summary.Informational = append(summary.Informational,
			fmt.Sprintf("%s:%s was flagged for information only: %s",
				name, version, apitext.OneLine(v.Description)))
	}
	return summary, len(summary.Failing) > 0
}

// parsePurl splits a PURL like "pkg:pypi/foo@1.2.3" into its ecosystem, name
// and version. Any part the string doesn't carry comes back empty.
//
// The real parser does the work: it percent-decodes (an npm scope is spelled
// "%40scope" per the spec) and drops qualifiers and subpaths, which a
// hand-rolled split would leave glued to the version. Our own componentPurl
// emits neither, but the purls here come back from the API, so parsing what
// the spec allows rather than what we happen to send is the safer side.
func parsePurl(purl string) (ecosystem, name, version string) {
	if p, err := packageurl.FromString(purl); err == nil && p.Name != "" {
		name = p.Name
		if p.Namespace != "" {
			// npm scopes and the like live in the namespace; users know the
			// package as the two joined ("@scope/pkg").
			name = p.Namespace + "/" + name
		}
		return p.Type, name, p.Version
	}
	// Not a well-formed PURL. Rather than render "WARNING: : contains malware"
	// at someone, salvage a name and version from whatever came back.
	s := strings.TrimPrefix(purl, "pkg:")
	if before, after, ok := strings.Cut(s, "/"); ok {
		ecosystem, s = before, after
	}
	// An npm scope puts an '@' at the *start* of the name, so the version
	// delimiter is the last '@' — and only when it isn't that leading one.
	if i := strings.LastIndex(s, "@"); i > 0 {
		return ecosystem, s[:i], s[i+1:]
	}
	return ecosystem, s, ""
}
