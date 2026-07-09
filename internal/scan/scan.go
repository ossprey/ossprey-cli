package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

type Options struct {
	Path    string
	Verbose bool
}

// ErrNoComponents is returned by InjectTestVulnerability when nothing was catalogued.
var ErrNoComponents = errors.New("no components found to inject test vulnerability")

// Run catalogues `path` and returns a populated SBOM (no vulnerabilities).
// Callers decide what to do next: dump JSON, submit to API, etc.
func Run(ctx context.Context, opts Options) (*ossbom.SBOM, error) {
	if _, err := os.Stat(opts.Path); err != nil {
		return nil, fmt.Errorf("scan path: %w", err)
	}

	pkgs, err := catalog.Catalog(ctx, opts.Path)
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}

	abs, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve scan path: %w", err)
	}
	host, _ := os.Hostname() // best-effort; empty hostname is acceptable

	// Project names the scan in the dashboard. Without it the UI falls back to
	// the machine name (the host); use the scanned directory's base name so the
	// scan surfaces as the project rather than the host.
	project := filepath.Base(abs)
	sbom := ossbom.New(ossbom.Environment{
		Path:        abs,
		MachineName: host,
		Project:     project,
	})
	sbom.Name = project

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

// MalwareReports returns one v1-style report line per vulnerability and a boolean
// indicating whether any were found.
func MalwareReports(sbom *ossbom.SBOM) ([]string, bool) {
	if len(sbom.Vulnerabilities) == 0 {
		return nil, false
	}
	reports := make([]string, 0, len(sbom.Vulnerabilities))
	for _, v := range sbom.Vulnerabilities {
		name, version := splitPurl(v.Purl)
		reports = append(reports,
			fmt.Sprintf("WARNING: %s:%s contains malware. Remediate this immediately", name, version))
	}
	return reports, true
}

// splitPurl extracts (name, version) from a PURL string like "pkg:pypi/foo@1.2.3".
func splitPurl(purl string) (string, string) {
	s := strings.TrimPrefix(purl, "pkg:")
	if _, after, ok := strings.Cut(s, "/"); ok {
		s = after
	}
	name, version, _ := strings.Cut(s, "@")
	return name, version
}
