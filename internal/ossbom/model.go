package ossbom

import (
	"sort"
	"time"
)

const (
	formatTag      = "OSSBOM"
	specVersion    = "1.0"
	creatorDefault = "ossprey-cli-v2"

	defaultVulnType      = "Malware"
	defaultVulnReference = "Unknown"
)

type Environment struct {
	GithubRepo  string `json:"github_repo,omitempty"`
	GithubOrg   string `json:"github_org,omitempty"`
	Branch      string `json:"branch,omitempty"`
	MachineName string `json:"machine_name,omitempty"`
	ProductEnv  string `json:"product_env,omitempty"`
	Project     string `json:"project,omitempty"`
	Path        string `json:"path,omitempty"`
}

type Component struct {
	Name string `json:"name"`
	// Namespace is the PURL namespace segment — for github components it is the
	// repo owner (org/user), so the purl becomes pkg:github/<owner>/<name>@<ref>.
	// Empty for ecosystems that don't use it (pypi, npm).
	Namespace string         `json:"namespace,omitempty"`
	Version   string         `json:"version"`
	Type      string         `json:"type"`
	Source    []string       `json:"source"`
	Env       []string       `json:"env"`
	Location  []string       `json:"location"`
	Metadata  map[string]any `json:"metadata"`
}

type Vulnerability struct {
	ID          string `json:"id"`
	Purl        string `json:"purl"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Reference   string `json:"reference"`
}

// NewMalwareVulnerability returns a Vulnerability with sensible defaults
// (type=Malware, reference=Unknown). Use when constructing locally; the
// API path leaves these to the server.
func NewMalwareVulnerability(id, purl, description string) Vulnerability {
	return Vulnerability{
		ID:          id,
		Purl:        purl,
		Type:        defaultVulnType,
		Description: description,
		Reference:   defaultVulnReference,
	}
}

func (s *SBOM) AddVulnerability(v Vulnerability) {
	s.Vulnerabilities = append(s.Vulnerabilities, v)
}

type SBOM struct {
	Name            string          `json:"name"`
	Created         string          `json:"created"`
	Creators        []string        `json:"creators"`
	Version         string          `json:"version"`
	Format          string          `json:"format"`
	Env             Environment     `json:"env"`
	Components      []Component     `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`

	dedupe map[string]int
}

func New(env Environment) *SBOM {
	return &SBOM{
		Created:         time.Now().UTC().Format(time.RFC3339),
		Creators:        []string{creatorDefault},
		Version:         specVersion,
		Format:          formatTag,
		Env:             env,
		Components:      []Component{},
		Vulnerabilities: []Vulnerability{},
		dedupe:          map[string]int{},
	}
}

// AddComponent merges into the SBOM, deduping on PURL-ish key
// (type/namespace/name@version).
func (s *SBOM) AddComponent(c Component) {
	key := c.Type + "/" + c.Namespace + "/" + c.Name + "@" + c.Version
	if idx, ok := s.dedupe[key]; ok {
		s.Components[idx].Source = mergeUnique(s.Components[idx].Source, c.Source)
		s.Components[idx].Location = mergeUnique(s.Components[idx].Location, c.Location)
		return
	}
	s.dedupe[key] = len(s.Components)
	s.Components = append(s.Components, c)
}

func mergeUnique(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Sort components by (name, version) — matches v1 deterministic output.
func (s *SBOM) Sort() {
	sort.Slice(s.Components, func(i, j int) bool {
		if s.Components[i].Name != s.Components[j].Name {
			return s.Components[i].Name < s.Components[j].Name
		}
		return s.Components[i].Version < s.Components[j].Version
	})
}
