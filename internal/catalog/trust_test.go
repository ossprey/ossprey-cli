package catalog

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/anchore/syft/syft/file"

	"github.com/ossprey/ossprey-cli/internal/trust"
)

const (
	npmInternal  = "https://npm.internal.example/repo/"
	pypiInternal = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/"
	pypiProxy    = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/public-proxy/"
)

func testPolicy(t *testing.T, registries, scopes []string) trust.Policy {
	t.Helper()
	p, err := trust.Parse(registries, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const trustPackageLock = `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/acme-npm": {"version": "1.0.0", "resolved": "https://npm.internal.example/repo/acme-npm/-/acme-npm-1.0.0.tgz"},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
    "node_modules/@acme/web": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/@acme/web/-/web-2.0.0.tgz"},
    "node_modules/sneaky": {"version": "1.0.0", "resolved": "https://npm.internal.example/repo/../public/sneaky/-/sneaky-1.0.0.tgz"}
  }
}`

const trustYarnLock = `# yarn lockfile v1

acme-yarn@^1.0.0:
  version "1.0.0"
  resolved "https://npm.internal.example/repo/acme-yarn/-/acme-yarn-1.0.0.tgz#abc"
  integrity sha512-aaa

is-odd@^3.0.0:
  version "3.0.1"
  resolved "https://registry.yarnpkg.com/is-odd/-/is-odd-3.0.1.tgz#def"
  integrity sha512-bbb
`

const trustUVLock = `version = 1
requires-python = ">=3.12"

[[package]]
name = "acme-core"
version = "1.0.0"
source = { registry = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/simple" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/public-proxy/simple" }

[[package]]
name = "acme-dup"
version = "1.0.0"
source = { registry = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/simple" }
`

// Same acme-dup@1.0.0, but this project fetches it through the public proxy.
const trustUVLockPublicDup = `version = 1
requires-python = ">=3.12"

[[package]]
name = "acme-dup"
version = "1.0.0"
source = { registry = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/public-proxy/simple" }
`

const trustPoetryLock = `[[package]]
name = "acme-models"
version = "2.0.0"
description = ""
optional = false
python-versions = "*"
files = []

[package.source]
type = "legacy"
url = "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/simple"
reference = "internal"

[[package]]
name = "urllib3"
version = "2.2.2"
description = ""
optional = false
python-versions = "*"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "x"
`

func trustFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"web/package-lock.json": trustPackageLock,
		"yarnapp/yarn.lock":     trustYarnLock,
		"pyapp/uv.lock":         trustUVLock,
		"pyapp2/uv.lock":        trustUVLockPublicDup,
		"poetryapp/poetry.lock": trustPoetryLock,
	})
	return root
}

func trustedNames(pkgs []Package) (trusted, checked []string) {
	for _, p := range pkgs {
		id := p.Type + "/" + strings.ToLower(p.Name)
		if p.Trusted {
			trusted = append(trusted, id)
		} else {
			checked = append(checked, id)
		}
	}
	sort.Strings(trusted)
	sort.Strings(checked)
	return trusted, checked
}

func TestCatalogMarksPackagesFromTrustedSources(t *testing.T) {
	root := trustFixture(t)
	policy := testPolicy(t, []string{npmInternal, pypiInternal}, []string{"@acme"})

	pkgs, err := Catalog(context.Background(), root, Options{NoExec: true, SkipVersionLookup: true, Trust: policy})
	if err != nil {
		t.Fatal(err)
	}
	trusted, checked := trustedNames(pkgs)

	wantTrusted := []string{
		"npm/@acme/web",    // by scope, whatever registry it came from
		"npm/acme-npm",     // package-lock resolved
		"npm/acme-yarn",    // yarn.lock resolved
		"pypi/acme-core",   // uv.lock source
		"pypi/acme-models", // poetry.lock [package.source]
	}
	wantChecked := []string{
		"npm/is-odd",
		"npm/left-pad",
		"npm/sneaky",    // traversal out of the trusted prefix
		"pypi/acme-dup", // one project fetches it through the proxy
		"pypi/requests", // same host, public-proxy repository
		"pypi/urllib3",  // no recorded source
	}
	if strings.Join(trusted, " ") != strings.Join(wantTrusted, " ") {
		t.Errorf("trusted = %v\nwant      %v", trusted, wantTrusted)
	}
	if strings.Join(checked, " ") != strings.Join(wantChecked, " ") {
		t.Errorf("checked = %v\nwant      %v", checked, wantChecked)
	}
}

func TestCatalogWithoutPolicyTrustsNothing(t *testing.T) {
	pkgs, err := Catalog(context.Background(), trustFixture(t), Options{NoExec: true, SkipVersionLookup: true})
	if err != nil {
		t.Fatal(err)
	}
	if trusted, _ := trustedNames(pkgs); len(trusted) != 0 {
		t.Errorf("trusted with an empty policy: %v", trusted)
	}
}

// A private package is exactly the one the public registry does not have, so
// looking up its latest version there is the noise trust exists to remove.
func TestCatalogDoesNotLookUpTrustedPackagesOnThePublicRegistry(t *testing.T) {
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"package.json": `{"name": "app", "dependencies": {"@acme/web": "^1.0.0", "left-pad": "^1.0.0"}}`,
	})

	var mu sync.Mutex
	var looked []string
	old := resolveLatestFn
	resolveLatestFn = func(_ context.Context, eco, name string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		looked = append(looked, name)
		return "1.0.0", nil
	}
	t.Cleanup(func() { resolveLatestFn = old })

	pkgs, err := Catalog(context.Background(), root, Options{NoExec: true, Trust: testPolicy(t, nil, []string{"@acme"})})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(looked, " ") != "left-pad" {
		t.Errorf("looked up %v, want only left-pad", looked)
	}
	for _, p := range pkgs {
		if p.Name == "@acme/web" && (!p.Trusted || p.Version != "") {
			t.Errorf("@acme/web = %+v, want trusted and unresolved", p)
		}
	}
}

func TestResolverOutputCarriesItsSource(t *testing.T) {
	loc := file.NewLocation("requirements.txt")
	report := `{"install": [
	  {"metadata": {"name": "acme-core", "version": "1.0.0"},
	   "download_info": {"url": "https://acme-123456789012.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/simple/acme-core/1.0.0/acme_core-1.0.0-py3-none-any.whl"}}
	]}`
	pkgs, err := parsePipReport([]byte(report), loc)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("parsePipReport: %v, %v", pkgs, err)
	}
	if got := registryOf(pkgs[0]); !strings.HasPrefix(got, pypiInternal) {
		t.Errorf("pip report source = %q", got)
	}

	pkgs, err = parseNpmLock([]byte(trustPackageLock), loc)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.Name == "acme-npm" && !strings.HasPrefix(registryOf(p), npmInternal) {
			t.Errorf("npm resolve source = %q", registryOf(p))
		}
	}
}
