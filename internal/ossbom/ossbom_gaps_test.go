package ossbom

import (
	"encoding/json"
	"testing"
)

// The wire purl is pkg:<type>/<name>@<version> with the name verbatim, as the
// Python ossbom library builds it: the backend splits on the last '@', so a
// scoped npm name keeps its leading '@' rather than %40.
func TestToMiniBOM_PurlWireFormat(t *testing.T) {
	s := New(Environment{})
	s.AddComponent(Component{Name: "@babel/core", Version: "7.24.0", Type: "npm"})
	s.AddComponent(Component{Name: "zope.interface", Version: "6.0", Type: "pypi"})
	s.AddComponent(Component{Name: "left-pad", Version: "1.3.0", Type: "npm"})

	got := map[string]bool{}
	for _, c := range s.ToMiniBOM().Components {
		got[c.Purl] = true
	}
	for _, want := range []string{
		"pkg:npm/@babel/core@7.24.0",
		"pkg:pypi/zope.interface@6.0",
		"pkg:npm/left-pad@1.3.0",
	} {
		if !got[want] {
			t.Errorf("missing purl %q in %v", want, got)
		}
	}
}

// Dedupe keys on type too: the same name and version in two ecosystems are two
// packages.
func TestAddComponent_DedupeIsPerEcosystem(t *testing.T) {
	s := New(Environment{})
	s.AddComponent(Component{Name: "requests", Version: "1.0", Type: "pypi", Source: []string{"a"}, Location: []string{"x"}})
	s.AddComponent(Component{Name: "requests", Version: "1.0", Type: "npm"})
	s.AddComponent(Component{Name: "requests", Version: "1.0", Type: "pypi", Source: []string{"b", "a"}, Location: []string{"y"}})

	if len(s.Components) != 2 {
		t.Fatalf("components: got %d, want 2", len(s.Components))
	}
	py := s.Components[0]
	if len(py.Source) != 2 || py.Source[0] != "a" || py.Source[1] != "b" {
		t.Errorf("merged source: got %v, want [a b]", py.Source)
	}
	if len(py.Location) != 2 {
		t.Errorf("merged location: got %v, want both", py.Location)
	}
}

// A versionless component is submitted as such (pkg:x/name@), never dropped.
func TestToMiniBOM_KeepsVersionlessComponents(t *testing.T) {
	s := New(Environment{})
	s.AddComponent(Component{Name: "flask", Type: "pypi"})
	mb := s.ToMiniBOM()
	if len(mb.Components) != 1 || mb.Components[0].Purl != "pkg:pypi/flask@" {
		t.Errorf("components: got %+v", mb.Components)
	}
}

// The submission carries env attribution and any locally-injected vulnerability.
func TestToMiniBOM_CarriesEnvAndVulnerabilities(t *testing.T) {
	s := New(Environment{GithubOrg: "acme", GithubRepo: "widget", Branch: "main", Project: "widget"})
	s.Name = "widget"
	s.AddVulnerability(NewMalwareVulnerability("MAL-1", "pkg:npm/x@1", "test"))

	mb := s.ToMiniBOM()
	if mb.Env != s.Env || mb.Name != "widget" || mb.Format != "OSSBOM" {
		t.Errorf("top-level fields not carried: %+v", mb)
	}
	if len(mb.Vulnerabilities) != 1 || mb.Vulnerabilities[0].Type != "Malware" || mb.Vulnerabilities[0].Reference != "Unknown" {
		t.Errorf("vulnerabilities: got %+v", mb.Vulnerabilities)
	}

	blob, err := json.Marshal(New(Environment{}).ToMiniBOM())
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]any
	if err := json.Unmarshal(blob, &shape); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"components", "vulnerabilities"} {
		if _, ok := shape[k].([]any); !ok {
			t.Errorf("%s: want [], got %T", k, shape[k])
		}
	}
}

// The response is appended, not substituted, and keeps severity and
// description, which grade the finding and explain it.
func TestApplyAPIResponse_AppendsAndKeepsSeverity(t *testing.T) {
	s := New(Environment{})
	s.AddVulnerability(NewMalwareVulnerability("LOCAL", "pkg:npm/a@1", ""))
	raw := `{"vulnerabilities":[{"id":"MAL-2","purl":"pkg:npm/b@2","type":"Malware","reference":"r","severity":"Info","description":"telemetry"}],"unrelated":true}`
	if err := s.ApplyAPIResponse(json.RawMessage(raw)); err != nil {
		t.Fatalf("ApplyAPIResponse: %v", err)
	}
	if len(s.Vulnerabilities) != 2 || s.Vulnerabilities[0].ID != "LOCAL" {
		t.Fatalf("vulnerabilities: got %+v", s.Vulnerabilities)
	}
	if v := s.Vulnerabilities[1]; v.Severity != "Info" || v.Description != "telemetry" {
		t.Errorf("severity/description lost: %+v", v)
	}
}

// Only the platform's skip types count as unscanned, matched exactly.
func TestUnscanned_MatchesSkipTypesExactly(t *testing.T) {
	s := New(Environment{})
	for _, n := range []string{"a", "b", "c", "d"} {
		s.AddComponent(Component{Name: n, Version: "1", Type: "npm"})
	}
	s.Findings = []Finding{
		{Type: "LOOKUP_ONLY"},
		{Type: "not_found"},
		{Type: ""},
		{Type: "MALWARE"},
	}
	if got := s.Unscanned(); got != 1 {
		t.Errorf("Unscanned: got %d, want 1", got)
	}
	if got := New(Environment{}).Unscanned(); got != 0 {
		t.Errorf("empty SBOM Unscanned: got %d", got)
	}
}
