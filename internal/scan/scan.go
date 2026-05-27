package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

	host, _ := os.Hostname()
	abs, _ := filepath.Abs(opts.Path)

	sbom := ossbom.New(ossbom.Environment{
		Path:        abs,
		MachineName: host,
	})

	for _, p := range pkgs {
		sbom.AddComponent(ossbom.Component{
			Name:     p.Name,
			Version:  p.Version,
			Type:     p.Type,
			Source:   p.Source,
			Location: p.Locations,
		})
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
	sbom.AddVulnerability(ossbom.Vulnerability{
		ID:          "TEST-2024-0001",
		Purl:        fmt.Sprintf("pkg:%s/%s@%s", c.Type, c.Name, c.Version),
		Description: "This is a test vulnerability added in dry-run-malicious mode",
	})
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
	s := purl
	if len(s) > 4 && s[:4] == "pkg:" {
		s = s[4:]
	}
	if i := indexOf(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if i := indexOf(s, '@'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
