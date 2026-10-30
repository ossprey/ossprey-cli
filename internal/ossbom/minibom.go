package ossbom

import (
	"encoding/json"
	"maps"
	"net/url"
	"slices"
	"strings"
)

// MiniBOM = OSSBOM compressed for API submission. Each component swapped for
// `{purl, source, env, location}`. Top-level fields unchanged.
// See ossbom/converters/minibom_converter.py.

type MiniComponent struct {
	Purl     string   `json:"purl"`
	Source   []string `json:"source"`
	Env      []string `json:"env"`
	Location []string `json:"location,omitempty"`
}

type MiniBOM struct {
	Name            string          `json:"name"`
	Created         string          `json:"created"`
	Creators        []string        `json:"creators"`
	Version         string          `json:"version"`
	Format          string          `json:"format"`
	Env             Environment     `json:"env"`
	Components      []MiniComponent `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// ToMiniBOM compresses the SBOM for API submission.
func (s *SBOM) ToMiniBOM() MiniBOM {
	s.Sort()
	out := MiniBOM{
		Name:            s.Name,
		Created:         s.Created,
		Creators:        s.Creators,
		Version:         s.Version,
		Format:          s.Format,
		Env:             s.Env,
		Components:      make([]MiniComponent, 0, len(s.Components)),
		Vulnerabilities: s.Vulnerabilities,
	}
	for _, c := range s.Components {
		out.Components = append(out.Components, MiniComponent{
			Purl:     c.Purl(),
			Source:   c.Source,
			Env:      c.Env,
			Location: c.Location,
		})
	}
	return out
}

// Purl is pkg:<type>/<name>@<version>, plus any qualifiers in key order.
func (c Component) Purl() string {
	return "pkg:" + c.Type + "/" + c.Name + "@" + c.Version + c.qualifierString()
}

// qualifierString is the purl's "?k=v&..." part, empty when there are none.
func (c Component) qualifierString() string {
	var b strings.Builder
	sep := "?"
	for _, k := range slices.Sorted(maps.Keys(c.Qualifiers)) {
		if v := c.Qualifiers[k]; v != "" {
			b.WriteString(sep + k + "=" + escapeQualifier(v))
			sep = "&"
		}
	}
	return b.String()
}

// escapeQualifier percent-encodes all but alphanumerics, ".-_~" and ":", as ECMA-427 5.4 requires.
func escapeQualifier(v string) string {
	return strings.NewReplacer("%3A", ":", "+", "%20").Replace(url.QueryEscape(v))
}

// ApplyAPIResponse copies vulnerabilities and findings from a MiniBOM-shaped
// API response into this SBOM. Returns nil on parse failure with an error context.
// Findings name the components the scan did not check.
func (s *SBOM) ApplyAPIResponse(raw json.RawMessage) error {
	var resp struct {
		Vulnerabilities []Vulnerability `json:"vulnerabilities"`
		Findings        []Finding       `json:"findings"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	s.Vulnerabilities = append(s.Vulnerabilities, resp.Vulnerabilities...)
	s.Findings = append(s.Findings, resp.Findings...)
	return nil
}
