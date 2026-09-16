package ossbom

import "encoding/json"

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
			Purl:     componentPurl(c),
			Source:   c.Source,
			Env:      c.Env,
			Location: c.Location,
		})
	}
	return out
}

func componentPurl(c Component) string {
	return "pkg:" + c.Type + "/" + c.Name + "@" + c.Version
}

// ApplyAPIResponse copies the vulnerabilities and the account's failing
// severity floor from a MiniBOM-shaped API response into this SBOM. It is the
// one seam where the response meets the local SBOM, so anything a client needs
// from the server lands here and rides into the -o output for free.
func (s *SBOM) ApplyAPIResponse(raw json.RawMessage) error {
	var resp struct {
		Vulnerabilities      []Vulnerability `json:"vulnerabilities"`
		FailingSeverityFloor string          `json:"failing_severity_floor"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	s.Vulnerabilities = append(s.Vulnerabilities, resp.Vulnerabilities...)
	s.FailingSeverityFloor = resp.FailingSeverityFloor
	return nil
}
