package ossbom

import (
	"encoding/json"
	"testing"
)

func TestToMiniBOM(t *testing.T) {
	tests := []struct {
		name     string
		build    func() *SBOM
		wantLen  int
		wantPurl []string
	}{
		{
			name: "empty SBOM",
			build: func() *SBOM {
				return New(Environment{})
			},
			wantLen:  0,
			wantPurl: nil,
		},
		{
			name: "single component",
			build: func() *SBOM {
				s := New(Environment{Path: "/x"})
				s.AddComponent(Component{Name: "requests", Version: "2.31.0", Type: "pypi"})
				return s
			},
			wantLen:  1,
			wantPurl: []string{"pkg:pypi/requests@2.31.0"},
		},
		{
			name: "components sorted by name",
			build: func() *SBOM {
				s := New(Environment{})
				s.AddComponent(Component{Name: "zlib", Version: "1.0", Type: "pypi"})
				s.AddComponent(Component{Name: "aaa", Version: "1.0", Type: "pypi"})
				return s
			},
			wantLen:  2,
			wantPurl: []string{"pkg:pypi/aaa@1.0", "pkg:pypi/zlib@1.0"},
		},
		{
			name: "dedupes by purl key on AddComponent",
			build: func() *SBOM {
				s := New(Environment{})
				s.AddComponent(Component{Name: "requests", Version: "2.31.0", Type: "pypi", Source: []string{"a"}})
				s.AddComponent(Component{Name: "requests", Version: "2.31.0", Type: "pypi", Source: []string{"b"}})
				return s
			},
			wantLen:  1,
			wantPurl: []string{"pkg:pypi/requests@2.31.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mb := tt.build().ToMiniBOM()
			if len(mb.Components) != tt.wantLen {
				t.Fatalf("len: got %d, want %d", len(mb.Components), tt.wantLen)
			}
			for i, want := range tt.wantPurl {
				if mb.Components[i].Purl != want {
					t.Errorf("Components[%d].Purl: got %q, want %q", i, mb.Components[i].Purl, want)
				}
			}
		})
	}
}

func TestToMiniBOM_FieldShape(t *testing.T) {
	// Components must always serialize source/env as JSON arrays (not null) to
	// match v1 ossbom MiniComponent JSON shape.
	s := New(Environment{})
	s.AddComponent(Component{Name: "foo", Version: "1", Type: "pypi"})

	data, err := json.Marshal(s.ToMiniBOM())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed struct {
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Components) != 1 {
		t.Fatalf("components: got %d, want 1", len(parsed.Components))
	}
	c := parsed.Components[0]
	if _, ok := c["source"].([]any); !ok {
		t.Errorf("source: want []any, got %T", c["source"])
	}
	if _, ok := c["env"].([]any); !ok {
		t.Errorf("env: want []any, got %T", c["env"])
	}
	if _, exists := c["location"]; exists {
		t.Errorf("location should be omitted when empty, got %v", c["location"])
	}
}

func TestApplyAPIResponse(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantVulns int
		wantErr   bool
	}{
		{
			name:      "no vulnerabilities",
			raw:       `{"vulnerabilities":[]}`,
			wantVulns: 0,
		},
		{
			name:      "one vulnerability",
			raw:       `{"vulnerabilities":[{"id":"V1","purl":"pkg:pypi/foo@1.0","type":"Malware","reference":"X"}]}`,
			wantVulns: 1,
		},
		{
			name:      "malformed JSON",
			raw:       `{`,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(Environment{})
			err := s.ApplyAPIResponse(json.RawMessage(tt.raw))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err: got %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(s.Vulnerabilities) != tt.wantVulns {
				t.Errorf("vulns: got %d, want %d", len(s.Vulnerabilities), tt.wantVulns)
			}
		})
	}
}
