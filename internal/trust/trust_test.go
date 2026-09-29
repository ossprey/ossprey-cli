package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	internalIndex = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/"
	proxyIndex    = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/public-proxy/"
)

func mustPolicy(t *testing.T, registries, scopes []string) Policy {
	t.Helper()
	p, err := Parse(registries, scopes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestNormalizeRegistry(t *testing.T) {
	cases := map[string]string{
		"https://Registry.Example.com":             "https://registry.example.com/",
		"https://registry.example.com:443/npm/x":   "https://registry.example.com/npm/x/",
		"http://registry.example.com:80/npm/x/":    "http://registry.example.com/npm/x/",
		"https://registry.example.com:8443/a//b/":  "https://registry.example.com:8443/a/b/",
		"  https://registry.example.com/simple/  ": "https://registry.example.com/simple/",
	}
	for in, want := range cases {
		got, err := NormalizeRegistry(in)
		if err != nil {
			t.Errorf("NormalizeRegistry(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeRegistry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeRegistryRefuses(t *testing.T) {
	for _, in := range []string{
		"",
		"registry.example.com",
		"ftp://registry.example.com/",
		"file:///srv/registry",
		"https://user:tok3n@registry.example.com/",
		"https://registry.example.com/?token=x",
		"https:///nohost",
	} {
		if got, err := NormalizeRegistry(in); err == nil {
			t.Errorf("NormalizeRegistry(%q) = %q, want an error", in, got)
		}
	}
}

func TestNormalizeRegistryDoesNotEchoCredentials(t *testing.T) {
	_, err := NormalizeRegistry("https://user:s3cret@registry.example.com/")
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error must refuse without echoing the secret, got %v", err)
	}
}

// The case the whole design turns on: two repositories on one host, one of
// them a proxy of the public index.
func TestTrustsRegistryIsPathScopedNotHostScoped(t *testing.T) {
	p := mustPolicy(t, []string{internalIndex}, nil)

	trusted := []string{
		internalIndex,
		internalIndex + "simple/",
		internalIndex + "simple/acme-core/acme_core-1.0.0-py3-none-any.whl",
		strings.ToUpper(internalIndex[:8]) + internalIndex[8:], // scheme case
		"https://aws:token@" + strings.TrimPrefix(internalIndex, "https://") + "simple/",
	}
	for _, u := range trusted {
		if !p.TrustsRegistry(u) {
			t.Errorf("TrustsRegistry(%q) = false, want true", u)
		}
	}

	untrusted := []string{
		proxyIndex + "simple/requests/",
		"https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal-proxy/simple/",
		"https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/",
		// Traversal out of the trusted prefix, plain and percent-encoded.
		internalIndex + "../public-proxy/simple/requests/",
		internalIndex + "%2e%2e/public-proxy/simple/requests/",
		// Host tricks.
		"https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com.evil.example/pypi/internal/",
		"https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com@evil.example/pypi/internal/",
		// Scheme downgrade is a different origin.
		"http://" + strings.TrimPrefix(internalIndex, "https://"),
		// Not URLs at all: uv's editable source, git refs, local paths.
		".",
		"git+ssh://git@github.com/acme/acme-core.git",
		"file:///srv/pypi/internal/",
		"",
	}
	for _, u := range untrusted {
		if p.TrustsRegistry(u) {
			t.Errorf("TrustsRegistry(%q) = true, want false", u)
		}
	}
}

func TestTrustsNpmScope(t *testing.T) {
	p := mustPolicy(t, nil, []string{"@Acme"})
	for _, name := range []string{"@acme/web", "@ACME/web"} {
		if !p.TrustsNpmScope(name) {
			t.Errorf("TrustsNpmScope(%q) = false", name)
		}
	}
	for _, name := range []string{"acme", "@acme", "@acme-evil/web", "@acmex/web", "acme/web", ""} {
		if p.TrustsNpmScope(name) {
			t.Errorf("TrustsNpmScope(%q) = true", name)
		}
	}
}

func TestTrusts(t *testing.T) {
	p := mustPolicy(t, []string{internalIndex}, []string{"@acme"})
	cases := []struct {
		name       string
		eco, pkg   string
		registries []string
		want       bool
	}{
		{"scope rule is npm only", "pypi", "@acme/x", nil, false},
		{"npm scope", "npm", "@acme/x", nil, true},
		{"no recorded source", "pypi", "acme-core", nil, false},
		{"only empty sources", "pypi", "acme-core", []string{"", ""}, false},
		{"trusted source", "pypi", "acme-core", []string{internalIndex + "simple/"}, true},
		{"trusted plus unrecorded", "pypi", "acme-core", []string{"", internalIndex}, true},
		{"one sighting public", "pypi", "acme-core", []string{internalIndex, proxyIndex}, false},
		{"public only", "pypi", "requests", []string{proxyIndex}, false},
	}
	for _, c := range cases {
		if got := p.Trusts(c.eco, c.pkg, c.registries); got != c.want {
			t.Errorf("%s: Trusts(%q, %q, %v) = %v, want %v", c.name, c.eco, c.pkg, c.registries, got, c.want)
		}
	}
}

func TestEmptyPolicyTrustsNothing(t *testing.T) {
	var p Policy
	if !p.Empty() || p.Trusts("npm", "@acme/x", []string{internalIndex}) {
		t.Fatal("the zero policy must trust nothing")
	}
}

func TestNormalizeNpmScope(t *testing.T) {
	for in, want := range map[string]string{"@acme": "@acme", "acme": "@acme", "@Acme/": "@acme", " @a.b-c_d~e ": "@a.b-c_d~e"} {
		got, err := NormalizeNpmScope(in)
		if err != nil || got != want {
			t.Errorf("NormalizeNpmScope(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "@", "@acme/web", "@ac me", "@-acme", "@acme*"} {
		if got, err := NormalizeNpmScope(in); err == nil {
			t.Errorf("NormalizeNpmScope(%q) = %q, want an error", in, got)
		}
	}
}

func TestSaveLoadRoundTripAndEnvOverlay(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	t.Setenv(RegistriesEnv, "")
	t.Setenv(NpmScopesEnv, "")

	if p, err := Load(); err != nil || !p.Empty() {
		t.Fatalf("missing file: got %+v, %v; want an empty policy and no error", p, err)
	}

	stored := mustPolicy(t, []string{internalIndex}, []string{"@acme"})
	if err := Save(stored); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("trust.json mode %o, want owner-only", perm)
	}

	t.Setenv(RegistriesEnv, "https://npm.example.com/repo, "+internalIndex)
	t.Setenv(NpmScopesEnv, "tools")
	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	wantRegs := []string{internalIndex, "https://npm.example.com/repo/"}
	if strings.Join(got.Registries, " ") != strings.Join(wantRegs, " ") {
		t.Errorf("registries = %v, want %v", got.Registries, wantRegs)
	}
	if strings.Join(got.NpmScopes, " ") != "@acme @tools" {
		t.Errorf("scopes = %v", got.NpmScopes)
	}
}

// A hand-edited file with one bad entry keeps the good ones and says so: the
// dropped entry's packages are merely checked.
func TestLoadKeepsValidEntriesAndReportsInvalidOnes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	t.Setenv(RegistriesEnv, "")
	t.Setenv(NpmScopesEnv, "")
	body := `{"registries": ["` + internalIndex + `", "not a url"], "npm_scopes": ["@acme", "@bad scope"]}`
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err == nil {
		t.Fatal("want an error naming the invalid entries")
	}
	if len(got.Registries) != 1 || len(got.NpmScopes) != 1 {
		t.Errorf("valid entries lost: %+v", got)
	}
}

func TestLoadMalformedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load()
	if err == nil || !got.Empty() {
		t.Fatalf("got %+v, %v; want an empty policy and an error", got, err)
	}
}

func TestWithout(t *testing.T) {
	p := mustPolicy(t, []string{internalIndex, proxyIndex}, []string{"@a", "@b"})
	got := p.Without(mustPolicy(t, []string{proxyIndex}, []string{"@a"}))
	if len(got.Registries) != 1 || got.Registries[0] != internalIndex || len(got.NpmScopes) != 1 || got.NpmScopes[0] != "@b" {
		t.Errorf("Without = %+v", got)
	}
}
