package trust

import (
	"strings"
	"testing"
)

const caHost = "acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com"

// A registry stored without its trailing slash is still a path prefix, not a
// string prefix: "/internal" must not trust "/internal-proxy".
func TestTrustsRegistryWithoutTrailingSlashIsStillSegmentScoped(t *testing.T) {
	p := mustPolicy(t, []string{"https://" + caHost + "/pypi/internal"}, nil)
	if !p.TrustsRegistry("https://" + caHost + "/pypi/internal/simple/acme-core/") {
		t.Error("package under the registry not trusted")
	}
	if p.TrustsRegistry("https://" + caHost + "/pypi/internal-proxy/simple/requests/") {
		t.Error("sibling repository sharing a name prefix was trusted")
	}
}

func TestTrustsRegistryCandidateForms(t *testing.T) {
	p := mustPolicy(t, []string{internalIndex}, nil)
	trusted := []string{
		"HTTPS://" + strings.ToUpper(caHost) + "/pypi/internal/simple/",   // scheme and host fold
		"https://" + caHost + ":443/pypi/internal/simple/",                // default port
		"https://" + caHost + "/pypi/internal/simple/x.whl?token=1#sha=2", // query/fragment ignored
		"https://" + caHost + "/pypi/public-proxy/../internal/simple/",    // traversal into it
	}
	for _, u := range trusted {
		if !p.TrustsRegistry(u) {
			t.Errorf("TrustsRegistry(%q) = false, want true", u)
		}
	}
	untrusted := []string{
		"https://" + caHost + "/PYPI/INTERNAL/simple/",                    // paths are case-sensitive
		"https://" + caHost + ":8443/pypi/internal/simple/",               // another port is another origin
		internalIndex + "%2E%2E/public-proxy/simple/requests/",            // upper-case encoded traversal
		internalIndex + "..%2Fpublic-proxy/simple/requests/",              // encoded separator
		internalIndex + "simple/../../public-proxy/simple/requests/",      // deeper traversal
		"https://" + caHost + "/pypi/internal/../../pypi/public-proxy/x/", // climbs out and back in elsewhere
	}
	for _, u := range untrusted {
		if p.TrustsRegistry(u) {
			t.Errorf("TrustsRegistry(%q) = true, want false", u)
		}
	}
}

// One bad environment entry must not cost the good ones, and a tokenised URL
// pasted from .npmrc must not be echoed back in the error.
func TestFromEnvKeepsValidEntriesAndHidesCredentials(t *testing.T) {
	t.Setenv(RegistriesEnv, "https://npm.example.com/repo\thttps://ci:s3cr3t@npm.example.com/other,,")
	t.Setenv(NpmScopesEnv, "@acme  @bad!scope\n@tools")
	got, err := FromEnv()
	if err == nil {
		t.Fatal("want an error naming the invalid entries")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("error echoes the credential: %v", err)
	}
	if strings.Join(got.Registries, " ") != "https://npm.example.com/repo/" {
		t.Errorf("registries = %v", got.Registries)
	}
	if strings.Join(got.NpmScopes, " ") != "@acme @tools" {
		t.Errorf("scopes = %v", got.NpmScopes)
	}
}
