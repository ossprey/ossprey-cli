package ossbom

import (
	"encoding/json"
	"testing"
)

func TestAddComponent_FieldShape(t *testing.T) {
	// Raw `ossprey scan` output must serialize empty component collections as []
	// and {} rather than null; the platform rejected null (OSS-1574).
	s := New(Environment{})
	s.AddComponent(Component{Name: "foo", Version: "1", Type: "pypi"})

	data, err := json.Marshal(s)
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
	for _, key := range []string{"source", "env", "location"} {
		if _, ok := c[key].([]any); !ok {
			t.Errorf("%s: want []any, got %T (%v)", key, c[key], c[key])
		}
	}
	if _, ok := c["metadata"].(map[string]any); !ok {
		t.Errorf("metadata: want map[string]any, got %T (%v)", c["metadata"], c["metadata"])
	}
}

func TestAddComponent_PreservesSuppliedValues(t *testing.T) {
	s := New(Environment{})
	s.AddComponent(Component{
		Name:     "foo",
		Version:  "1",
		Type:     "pypi",
		Source:   []string{"cataloger"},
		Location: []string{"requirements.txt"},
		Metadata: map[string]any{"local": true},
	})

	c := s.Components[0]
	if len(c.Source) != 1 || c.Source[0] != "cataloger" {
		t.Errorf("Source: got %v, want [cataloger]", c.Source)
	}
	if len(c.Location) != 1 || c.Location[0] != "requirements.txt" {
		t.Errorf("Location: got %v, want [requirements.txt]", c.Location)
	}
	if c.Metadata["local"] != true {
		t.Errorf("Metadata[local]: got %v, want true", c.Metadata["local"])
	}
}

func TestAddComponent_DedupeMergeStaysNonNil(t *testing.T) {
	// The dedupe branch merges Source/Location instead of taking the normalized
	// copy, so it needs its own check.
	s := New(Environment{})
	s.AddComponent(Component{Name: "foo", Version: "1", Type: "pypi"})
	s.AddComponent(Component{Name: "foo", Version: "1", Type: "pypi"})

	if len(s.Components) != 1 {
		t.Fatalf("components: got %d, want 1", len(s.Components))
	}
	c := s.Components[0]
	if c.Source == nil || c.Env == nil || c.Location == nil || c.Metadata == nil {
		t.Errorf("nil collection after merge: %+v", c)
	}
}
