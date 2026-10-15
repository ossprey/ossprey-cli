package check

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testMonitorID = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseSpec_MoreShapes(t *testing.T) {
	tests := []struct {
		eco, token          string
		wantEco, name, want string
	}{
		{"NPM", "lodash@1.0.0", "npm", "lodash", "1.0.0"},
		{" node ", "react", "npm", "react", ""},
		{"Python", "Django==5.0", "pypi", "Django", "5.0"},
		{"pypi", "requests~=2.31", "pypi", "requests", ""},
		{"pypi", "requests!=2.0", "pypi", "requests", ""},
		{"pypi", "requests<3", "pypi", "requests", ""},
		{"github", "ossprey/ossprey-cli@abc123", "github", "ossprey/ossprey-cli", "abc123"},
		{"npm", "@scope/pkg@1.0.0-beta.1", "npm", "@scope/pkg", "1.0.0-beta.1"},
	}
	for _, tt := range tests {
		s, err := ParseSpec(tt.eco, tt.token)
		if err != nil {
			t.Errorf("ParseSpec(%q,%q): %v", tt.eco, tt.token, err)
			continue
		}
		if s.Ecosystem != tt.wantEco || s.Name != tt.name || s.Version != tt.want {
			t.Errorf("ParseSpec(%q,%q) = %+v, want %s/%s@%s", tt.eco, tt.token, s, tt.wantEco, tt.name, tt.want)
		}
	}
}

// The default path submits for a verdict and applies it, with each spec sent
// as pkg:<type>/<name>@<version>.
func TestRun_SubmitsSpecsAndAppliesTheVerdict(t *testing.T) {
	var purls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/v1/scans" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var body struct {
			SBOM struct {
				Components []struct {
					Purl   string   `json:"purl"`
					Source []string `json:"source"`
				} `json:"components"`
			} `json:"sbom"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		for _, c := range body.SBOM.Components {
			purls = append(purls, c.Purl)
			if len(c.Source) != 1 || c.Source[0] != "check" {
				t.Errorf("%s: source %v, want [check]", c.Purl, c.Source)
			}
		}
		io.WriteString(w, `{"vulnerabilities":[{"id":"MAL-1","purl":"pkg:npm/@evil/pkg@1.0.0","type":"Malware","reference":"x"}]}`)
	}))
	defer srv.Close()

	sbom, err := Run(context.Background(), Options{
		Specs: []Spec{
			{Ecosystem: "npm", Name: "@evil/pkg", Version: "1.0.0"},
			{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
		},
		APIURL: srv.URL,
		APIKey: "test-key",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sbom.Vulnerabilities) != 1 || sbom.Vulnerabilities[0].ID != "MAL-1" {
		t.Errorf("verdict not applied: %+v", sbom.Vulnerabilities)
	}
	want := map[string]bool{"pkg:npm/@evil/pkg@1.0.0": true, "pkg:pypi/requests@2.31.0": true}
	if len(purls) != len(want) {
		t.Fatalf("purls: got %v", purls)
	}
	for _, p := range purls {
		if !want[p] {
			t.Errorf("unexpected purl %q", p)
		}
	}
}

// Passive with a monitor id goes through ingest with no credential, even when a
// key is also configured.
func TestRun_SubmitOnlyWithMonitorUsesIngest(t *testing.T) {
	var path, key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, key = r.URL.Path, r.Header.Get("x-api-key")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	_, err := Run(context.Background(), Options{
		Specs:      []Spec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}},
		APIURL:     srv.URL,
		APIKey:     "test-key",
		SubmitOnly: true,
		MonitorID:  testMonitorID,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if want := "/ingest/" + testMonitorID + "/scans"; path != want {
		t.Errorf("path: got %q, want %q", path, want)
	}
	if key != "" {
		t.Errorf("x-api-key sent alongside a monitor id: %q", key)
	}
}

// MonitorID is ignored unless SubmitOnly: a blocking check needs a verdict,
// which a monitor id cannot fetch.
func TestRun_MonitorIgnoredWithoutSubmitOnly(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	_, err := Run(context.Background(), Options{
		Specs:     []Spec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}},
		APIURL:    srv.URL,
		APIKey:    "test-key",
		MonitorID: testMonitorID,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if path != "/public/v1/scans" {
		t.Errorf("path: got %q, want the verdict route", path)
	}
}

// A submit failure is returned, never swallowed into a clean result.
func TestRun_SubmitErrorIsReturned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	for _, submitOnly := range []bool{false, true} {
		sbom, err := Run(context.Background(), Options{
			Specs:      []Spec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}},
			APIURL:     srv.URL,
			APIKey:     "test-key",
			SubmitOnly: submitOnly,
		})
		if err == nil || sbom != nil {
			t.Errorf("SubmitOnly=%v: got sbom=%v err=%v, want an error and no SBOM", submitOnly, sbom, err)
		}
	}
}

// Only a token that pins exactly one release carries a Version. Everything
// else used to reach the API as a bogus name or version — "evil[x]" 404s and is
// skipped, "lodash@^4.17.0" names no release, "lodash@npm:evil" checks lodash —
// so the package actually installed went unchecked.
func TestParseSpec_OnlyAnExactPinIsAVersion(t *testing.T) {
	tests := []struct {
		eco, token, name, version, constraint string
	}{
		// PyPI: extras, markers, operators, wildcards, poetry's "@".
		{"pypi", "evil[x]", "evil", "", ""},
		{"pypi", "evil[x,y]==1.0", "evil", "1.0", ""},
		{"pypi", "evil [x] == 1.0", "evil", "1.0", ""},
		{"pypi", `pkg; python_version>"3"`, "pkg", "", ""},
		{"pypi", `pkg==1.2 ; python_version>"3"`, "pkg", "1.2", ""},
		{"pypi", "pkg===1.0", "pkg", "1.0", ""},
		{"pypi", "pkg==2.*", "pkg", "", ""},
		{"pypi", "pkg>=1,==1.4", "pkg", "1.4", ""},
		{"pypi", "pkg>=1,<2", "pkg", "", ""},
		{"pypi", "requests@", "requests", "", ""},
		{"pypi", "pkg@^7.0", "pkg", "", ""},
		{"pypi", "pkg@latest", "pkg", "", ""},
		{"pypi", "pkg@~=7.0", "pkg", "", ""},
		{"pypi", "pkg@==7.0", "pkg", "7.0", ""},
		{"pypi", "pkg@7.0.1", "pkg", "7.0.1", ""},
		{"pypi", "pkg==1.0.0-beta.1", "pkg", "1.0.0-beta.1", ""},
		// npm: only an exact semver pins; a range or tag is resolved.
		{"npm", "lodash@4.17.21", "lodash", "4.17.21", ""},
		{"npm", "lodash@v4.17.21", "lodash", "4.17.21", ""},
		{"npm", "lodash@=4.17.21", "lodash", "4.17.21", ""},
		{"npm", "lodash@^4.17.0", "lodash", "", "^4.17.0"},
		{"npm", "lodash@~1", "lodash", "", "~1"},
		{"npm", "lodash@1.x", "lodash", "", "1.x"},
		{"npm", "lodash@>=1 <2", "lodash", "", ">=1 <2"},
		{"npm", "lodash@next", "lodash", "", "next"},
		{"npm", "lodash@latest", "lodash", "", ""},
		{"npm", "lodash@", "lodash", "", ""},
		{"npm", "lodash@1.2.3.4", "lodash", "", "1.2.3.4"},
		{"npm", "lodash@npm:evil", "evil", "", ""},
		{"npm", "lodash@npm:evil@1.0.0", "evil", "1.0.0", ""},
		{"npm", "lodash@npm:@evil/pkg@^2", "@evil/pkg", "", "^2"},
		{"npm", "@scope/pkg@npm:evil@1.0.0", "evil", "1.0.0", ""},
		{"npm", "@scope/pkg@next", "@scope/pkg", "", "next"},
	}
	for _, tt := range tests {
		s, err := ParseSpec(tt.eco, tt.token)
		if err != nil {
			t.Errorf("ParseSpec(%q, %q): %v", tt.eco, tt.token, err)
			continue
		}
		if s.Name != tt.name || s.Version != tt.version || s.Constraint != tt.constraint {
			t.Errorf("ParseSpec(%q, %q) = name %q version %q constraint %q, want %q %q %q",
				tt.eco, tt.token, s.Name, s.Version, s.Constraint, tt.name, tt.version, tt.constraint)
		}
	}
}

// A spec no registry serves is not a package to check: the forwarder files it
// with the other non-registry targets instead of looking up a bogus name.
func TestParseSpec_NonRegistrySpecsAreErrors(t *testing.T) {
	for _, tc := range []struct{ eco, token string }{
		{"pypi", "pkg @ https://example.com/pkg.whl"},
		{"pypi", "pkg@file:///tmp/pkg"},
		{"npm", "pkg@github:user/repo"},
		{"npm", "pkg@user/repo"},
		{"npm", "pkg@file:../pkg"},
		{"npm", "pkg@workspace:*"},
		{"npm", "pkg@git+ssh://git@github.com/u/r.git"},
		{"npm", "user/repo"},
		{"npm", "user/repo#v1.0.0"},
	} {
		if s, err := ParseSpec(tc.eco, tc.token); err == nil {
			t.Errorf("ParseSpec(%q, %q) = %+v, want an error", tc.eco, tc.token, s)
		}
	}
}

func TestParseSpec_ScopedNameIsNotAGitHubShorthand(t *testing.T) {
	s, err := ParseSpec("npm", "@scope/pkg@1.2.3")
	if err != nil || s.Name != "@scope/pkg" || s.Version != "1.2.3" {
		t.Fatalf("ParseSpec = %+v, %v", s, err)
	}
}
