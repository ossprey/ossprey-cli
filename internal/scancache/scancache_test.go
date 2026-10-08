package scancache

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// sampleBOM is a two-component SBOM with every Environment field set, so a
// test can prove that each one takes part in the key.
func sampleBOM(t *testing.T, mutate func(*ossbom.SBOM)) ossbom.MiniBOM {
	t.Helper()
	s := ossbom.New(ossbom.Environment{
		GithubRepo:  "svc",
		GithubOrg:   "acme",
		Branch:      "main",
		MachineName: "box",
		Project:     "svc",
		Path:        "/repo/svc",
	})
	s.AddComponent(ossbom.Component{Name: "left-pad", Version: "1.3.0", Type: "npm"})
	s.AddComponent(ossbom.Component{Name: "requests", Version: "2.31.0", Type: "pypi"})
	if mutate != nil {
		mutate(s)
	}
	return s.ToMiniBOM()
}

func baseInput(t *testing.T) KeyInput {
	t.Helper()
	return KeyInput{
		Kind:       Verdict,
		APIURL:     "https://api.ossprey.com",
		Identity:   FingerprintAPIKey("k1"),
		CLIVersion: "1.2.3",
		BOM:        sampleBOM(t, nil),
	}
}

func TestKeyIsSHA256Hex(t *testing.T) {
	k := Key(baseInput(t))
	if !hex64.MatchString(k) {
		t.Fatalf("key %q is not 64 hex characters", k)
	}
}

func TestKeyIsStable(t *testing.T) {
	if Key(baseInput(t)) != Key(baseInput(t)) {
		t.Fatal("the same input produced two different keys")
	}
}

// Every field the brief names must be a miss when it differs: a different
// repo path or branch is a different scan, and a different API URL, identity
// or CLI version must never share a verdict.
func TestKeyChangesWithEveryInput(t *testing.T) {
	base := Key(baseInput(t))
	cases := []struct {
		name   string
		mutate func(*KeyInput)
	}{
		{"kind", func(in *KeyInput) { in.Kind = Posted }},
		{"api url", func(in *KeyInput) { in.APIURL = "https://api.qa.ossprey.com" }},
		{"identity", func(in *KeyInput) { in.Identity = FingerprintAPIKey("k2") }},
		{"cli version", func(in *KeyInput) { in.CLIVersion = "1.2.4" }},
		{"component name", func(in *KeyInput) {
			in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Components[0].Name = "right-pad" })
		}},
		{"component version", func(in *KeyInput) {
			in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Components[0].Version = "1.3.1" })
		}},
		{"component type", func(in *KeyInput) {
			in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Components[0].Type = "pypi" })
		}},
		{"extra component", func(in *KeyInput) {
			in.BOM = sampleBOM(t, func(s *ossbom.SBOM) {
				s.AddComponent(ossbom.Component{Name: "is-odd", Version: "3.0.1", Type: "npm"})
			})
		}},
		{"path", func(in *KeyInput) { in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Env.Path = "/repo/other" }) }},
		{"project", func(in *KeyInput) { in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Env.Project = "other" }) }},
		{"branch", func(in *KeyInput) { in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Env.Branch = "feature" }) }},
		{"machine", func(in *KeyInput) { in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Env.MachineName = "other" }) }},
		{"repo", func(in *KeyInput) { in.BOM = sampleBOM(t, func(s *ossbom.SBOM) { s.Env.GithubRepo = "other" }) }},
	}
	for _, c := range cases {
		in := baseInput(t)
		c.mutate(&in)
		if Key(in) == base {
			t.Errorf("%s: key did not change", c.name)
		}
	}
}

// Created is the one field that differs between two otherwise identical
// scans, and component order is an accident of cataloguing, so neither may
// take part in the key. Key must also leave the caller's BOM untouched.
func TestKeyIgnoresCreatedAndComponentOrder(t *testing.T) {
	a := baseInput(t)
	b := baseInput(t)
	b.BOM.Created = "2001-01-01T00:00:00Z"
	b.BOM.Components[0], b.BOM.Components[1] = b.BOM.Components[1], b.BOM.Components[0]
	first := b.BOM.Components[0].Purl

	if Key(a) != Key(b) {
		t.Fatal("Created or component order changed the key")
	}
	if b.BOM.Components[0].Purl != first {
		t.Fatal("Key reordered the caller's components")
	}
}

func TestFingerprintsAreHexAndKindSpecific(t *testing.T) {
	const secret = "ospy_this-is-a-secret"
	fps := map[string]string{
		"api key": FingerprintAPIKey(secret),
		"monitor": FingerprintMonitor(secret),
		"login":   FingerprintLogin(secret),
	}
	seen := map[string]string{}
	for name, fp := range fps {
		if !hex64.MatchString(fp) {
			t.Errorf("%s fingerprint %q is not 64 hex characters", name, fp)
		}
		if strings.Contains(fp, secret) {
			t.Errorf("%s fingerprint contains the secret", name)
		}
		if other, dup := seen[fp]; dup {
			t.Errorf("%s and %s share a fingerprint for the same input", name, other)
		}
		seen[fp] = name
	}
}

// An empty credential is not an identity; the caller reads "" as "do not
// cache" rather than caching under the hash of nothing.
func TestFingerprintOfEmptyIsEmpty(t *testing.T) {
	if FingerprintAPIKey("") != "" || FingerprintMonitor("") != "" || FingerprintLogin("") != "" {
		t.Fatal("an empty input produced a fingerprint")
	}
}

func TestTTL(t *testing.T) {
	cases := []struct {
		env   string
		want  time.Duration
		warns bool
	}{
		{"", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"0", 0, false},
		{"0s", 0, false},
		{"off", 0, false},
		{"OFF", 0, false},
		{" off ", 0, false},
		{"24h", 24 * time.Hour, false},
		{"48h", 24 * time.Hour, false},
		{"abc", time.Hour, true},
		{"30", time.Hour, true},
		{"-5m", time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			t.Setenv(TTLEnv, c.env)
			ctx := warn.NewContext(context.Background(), false)
			if got := TTL(ctx); got != c.want {
				t.Errorf("TTL(%q) = %v, want %v", c.env, got, c.want)
			}
			out := warn.Drain(ctx)
			if warned := strings.Contains(out, TTLEnv); warned != c.warns {
				t.Errorf("TTL(%q) warned=%v, want %v; drain:\n%s", c.env, warned, c.warns, out)
			}
		})
	}
}

// Clean requires the response to say, in so many words, that it found
// nothing. A response with no vulnerabilities key at all is not a clean
// verdict, it is a response we do not understand, and must not be cached.
func TestClean(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{`{"vulnerabilities":[]}`, true},
		{`{"vulnerabilities":[],"findings":[{"purl":"pkg:npm/x@1","type":"NOT_FOUND"}]}`, true},
		{`{"vulnerabilities":[{"id":"V1","purl":"pkg:npm/x@1","severity":"Info"}]}`, false},
		{`{"vulnerabilities":[{"id":"V1","purl":"pkg:npm/x@1"}]}`, false},
		{`{"vulnerabilities":null}`, false},
		{`{}`, false},
		{`not json`, false},
		{``, false},
	}
	for _, c := range cases {
		if got := Clean(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("Clean(%s) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestFormatAge(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-3 * time.Second, "0s"},
		{45 * time.Second, "45s"},
		{59 * time.Second, "59s"},
		{5*time.Minute + 3*time.Second, "5m"},
		{time.Hour, "1h"},
		{time.Hour + 2*time.Minute, "1h 2m"},
	}
	for _, c := range cases {
		if got := formatAge(c.d); got != c.want {
			t.Errorf("formatAge(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// The cache lives in a scans/ subdirectory of whatever OSSPREY_CACHE_DIR
// names, so pruning never has to look at a file that is not ours.
func TestDirPrefersTheEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv(DirEnv, root)
	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "scans"); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
}

func TestDirDefaultsToTheUserCacheDir(t *testing.T) {
	t.Setenv(DirEnv, "")
	base, err := os.UserCacheDir()
	if err != nil {
		t.Skip("no user cache dir on this machine")
	}
	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "ossprey", "scans"); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
}
