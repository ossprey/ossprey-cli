package catalog

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/anchore/syft/syft/file"

	"github.com/ossprey/ossprey-cli/internal/trust"
	"github.com/ossprey/ossprey-cli/internal/warn"
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
		id := p.Type + "/" + strings.ToLower(p.Name) + qualifierKey(p.Qualifiers)
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

const trustCargoLock = `version = 4

[[package]]
name = "acme-sparse"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal/"
checksum = "aaaa"

[[package]]
name = "acme-index"
version = "1.0.0"
source = "registry+https://git.corp.example/acme/crates-index.git"
checksum = "bbbb"

[[package]]
name = "acme-hub"
version = "1.0.0"
source = "registry+https://github.com/acme/crates-index"

[[package]]
name = "acme-twin"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal/"

[[package]]
name = "acme-git"
version = "1.0.0"
source = "git+https://git.corp.example/acme/acme-git#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "acme-proxied"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal-proxy/"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccc"

[[package]]
name = "itoa"
version = "1.0.15"
source = "sparse+https://index.crates.io/"
checksum = "dddd"

[[package]]
name = "ryu"
version = "1.0.20"
source = "registry+https://gİthub.com/rust-lang/crates.io-index"

[[package]]
name = "acme-dotted"
version = "1.0.0"
source = "registry+https://gİt.corp.example/acme/crates-index.git"

[[package]]
name = "acme-backslash"
version = "1.0.0"
source = "sparse+https://github.com\\@evil.example/acme/"

[[package]]
name = "acme-escaped-slash"
version = "1.0.0"
source = "sparse+https://crates.corp.example/public%2F..%2Finternal/"

[[package]]
name = "acme-escaped-lower"
version = "1.0.0"
source = "registry+https://git.corp.example/public%2f..%2facme/crates-index.git"

[[package]]
name = "acme-escaped-dots"
version = "1.0.0"
source = "sparse+https://crates.corp.example/public%2F%2E%2E%2Finternal/"

[[package]]
name = "acme-escaped-backslash"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal/..%5C..%5Cpublic/"
`

// Same acme-twin@1.0.0, but this project locks it from crates.io.
const trustCargoLockCratesIoTwin = `version = 4

[[package]]
name = "acme-twin"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeee"
`

// A crate is trusted by the private index its Cargo.lock names, never from crates.io, git or a host Go and Cargo read apart.
func TestCatalogTrustsCratesByTheirCargoLockIndex(t *testing.T) {
	t.Setenv("CARGO_HOME", t.TempDir())
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"rustapp/Cargo.lock":  trustCargoLock,
		"rustapp2/Cargo.lock": trustCargoLockCratesIoTwin,
	})
	policy := testPolicy(t, []string{
		"https://crates.corp.example/internal/",
		"https://git.corp.example/acme/",
		"https://github.com/",
		"https://index.crates.io/",
	}, nil)

	pkgs, err := Catalog(context.Background(), root, Options{NoExec: true, SkipVersionLookup: true, Trust: policy})
	if err != nil {
		t.Fatal(err)
	}
	trusted, checked := trustedNames(pkgs)

	wantTrusted := []string{
		"cargo/acme-hub?repository_url=https://github.com/",             // git index under a host-wide rule
		"cargo/acme-index?repository_url=https://git.corp.example/",     // git index under its repository prefix
		"cargo/acme-sparse?repository_url=https://crates.corp.example/", // sparse index
		"cargo/acme-twin?repository_url=https://crates.corp.example/",   // the private crate of that name
	}
	wantChecked := []string{
		"cargo/acme-backslash?repository_url=https:///",                   // Cargo reads github.com\ as userinfo and fetches from evil.example
		"cargo/acme-dotted?repository_url=https://g%C4%B0t.corp.example/", // Go folds İ to i, Cargo's IDNA does not
		// Cargo keeps an escape inside its path segment where Go decodes and cleans it into the trusted prefix.
		"cargo/acme-escaped-backslash?repository_url=https://crates.corp.example/",
		"cargo/acme-escaped-dots?repository_url=https://crates.corp.example/",
		"cargo/acme-escaped-lower?repository_url=https://git.corp.example/",
		"cargo/acme-escaped-slash?repository_url=https://crates.corp.example/",
		// Git is never a registry, even under a trusted prefix.
		"cargo/acme-git?vcs_url=git+https://git.corp.example/acme/acme-git@0123456789abcdef0123456789abcdef01234567",
		"cargo/acme-proxied?repository_url=https://crates.corp.example/", // same host, another registry
		"cargo/acme-twin", // locked from crates.io in rustapp2
		"cargo/itoa",      // crates.io under its own sparse host's rule
		"cargo/ryu",       // a non-ASCII host on crates.io's path goes out as twins, neither trusted
		"cargo/ryu?repository_url=https://g%C4%B0thub.com/",
		"cargo/serde", // crates.io under a github.com rule
	}
	if strings.Join(trusted, " ") != strings.Join(wantTrusted, " ") {
		t.Errorf("trusted = %v\nwant      %v", trusted, wantTrusted)
	}
	if strings.Join(checked, " ") != strings.Join(wantChecked, " ") {
		t.Errorf("checked = %v\nwant      %v", checked, wantChecked)
	}
}

// A cargo config replacing any source lets Cargo fetch a crate elsewhere while its Cargo.lock still names the trusted index.
func TestCatalogTrustsNoCrateUnderASourceReplacement(t *testing.T) {
	replace := "[source.corp]\nregistry = \"sparse+https://crates.corp.example/internal/\"\nreplace-with = \"elsewhere\"\n\n[source.elsewhere]\nregistry = \"sparse+https://crates.elsewhere.example/\"\n"
	const replaced, included, unread, aliased = "because a source replacement is configured", "because a cargo config includes another file", "because a cargo config could not be read", "because a cargo alias passes --config"
	for name, c := range map[string]struct {
		files   map[string]string
		links   map[string]string
		modes   map[string]os.FileMode
		warning string
	}{
		"no config":                         {},
		"a replacement in the scan":         {files: map[string]string{"proj/.cargo/config.toml": replace}, warning: replaced},
		"a replacement above the scan root": {files: map[string]string{".cargo/config.toml": replace}, warning: replaced},
		"a replacement in CARGO_HOME":       {files: map[string]string{"home/config.toml": replace}, warning: replaced},
		"an unreadable config":              {files: map[string]string{"proj/.cargo/config.toml": "[net]\nretry = 2\n"}, modes: map[string]os.FileMode{"proj/.cargo/config.toml": 0}, warning: unread},
		"an unparseable config":             {files: map[string]string{"proj/.cargo/config.toml": "[source\n"}, warning: unread},
		"an include in the scan":            {files: map[string]string{"proj/.cargo/config.toml": "include = [\"extra.toml\"]\n", "proj/.cargo/extra.toml": replace}, warning: included},
		"an include in CARGO_HOME":          {files: map[string]string{"home/config.toml": "include = [{ path = \"extra.toml\" }]\n", "home/extra.toml": replace}, warning: included},
		// The vendor filter's manifests above the root play no part in trust.
		"an unparseable manifest above the root": {files: map[string]string{"Cargo.toml": "[package\n"}},
		"an oversized manifest above the root":   {files: map[string]string{"Cargo.toml": "# " + strings.Repeat("x", maxManifestBytes) + "\n"}},
		// A directory outside the scan that can be searched but not listed still has its configs opened by name.
		"a replacement in an unlistable .cargo above the root": {files: map[string]string{".cargo/config.toml": replace}, modes: map[string]os.FileMode{".cargo": 0o311}, warning: replaced},
		"a replacement in an unlistable CARGO_HOME":            {files: map[string]string{"home/config.toml": replace}, modes: map[string]os.FileMode{"home": 0o311}, warning: replaced},
		"an unlistable directory above the scan root":          {modes: map[string]os.FileMode{".": 0o311}},
		// A glob reports a symlink by its target when both match, which hid each of these.
		"a config symlinked to its sibling":               {files: map[string]string{"proj/.cargo/replace.toml": replace}, links: map[string]string{"proj/.cargo/config.toml": "replace.toml"}, warning: replaced},
		"a config symlinked into another dot directory":   {files: map[string]string{"proj/.yarn/cargo.toml": replace}, links: map[string]string{"proj/.cargo/config.toml": "../.yarn/cargo.toml"}, warning: replaced},
		"a symlinked config beside a plain one":           {files: map[string]string{"proj/.cargo/replace.toml": replace, "proj/.cargo/config.toml": "[net]\nretry = 2\n"}, links: map[string]string{"proj/.cargo/config": "replace.toml"}, warning: replaced},
		"a symlinked config named in another case":        {files: map[string]string{"proj/.cargo/replace.toml": replace}, links: map[string]string{"proj/.cargo/Config.toml": "replace.toml"}, warning: replaced},
		"a .cargo directory symlinked to a dot directory": {files: map[string]string{"proj/.yarn/config.toml": replace}, links: map[string]string{"proj/.cargo": ".yarn"}, warning: replaced},
		// An alias applies its --config value or file whenever it runs.
		"an alias passing --config":                 {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nxtask = \"run --config xtask/replace.toml --package xtask --\"\n"}, warning: aliased},
		"an alias passing --config= above the root": {files: map[string]string{".cargo/config.toml": "[alias]\nb = [\"build\", \"--config=source.corp.replace-with='elsewhere'\"]\n"}, warning: aliased},
		"an alias without --config":                 {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nxtask = \"run --package xtask --\"\n"}},
		// A device reports no size and never ends, so only a regular file is read.
		"a config symlinked to a device": {links: map[string]string{"proj/.cargo/config.toml": "/dev/zero"}, warning: unread},
		"an oversized config":            {files: map[string]string{"proj/.cargo/config.toml": "# " + strings.Repeat("x", maxManifestBytes) + "\n"}, warning: unread},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("CARGO_HOME", filepath.Join(base, "home"))
			writeTree(t, base, map[string]string{
				"home/.keep":                 "",
				"proj/Cargo.lock":            "version = 4\n\n[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+https://crates.corp.example/internal/\"\nchecksum = \"aaaa\"\n",
				"proj/web/package-lock.json": trustPackageLock,
			})
			writeTree(t, base, c.files)
			for link, target := range c.links {
				// Symlinks need privileges on Windows, as in the other symlink tests.
				if runtime.GOOS == "windows" {
					t.Skip("symlinks need privileges on Windows")
				}
				p := filepath.Join(base, filepath.FromSlash(link))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			for rel, mode := range c.modes {
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("file modes do not stop this user reading")
				}
				p := filepath.Join(base, filepath.FromSlash(rel))
				if err := os.Chmod(p, mode); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
			}
			ctx := warn.NewContext(context.Background(), false)
			policy := testPolicy(t, []string{"https://crates.corp.example/internal/", npmInternal}, nil)

			pkgs, err := Catalog(ctx, filepath.Join(base, "proj"), Options{NoExec: true, SkipVersionLookup: true, Trust: policy})
			if err != nil {
				t.Fatal(err)
			}
			trusted, _ := trustedNames(pkgs)
			want := []string{"cargo/acme-sparse?repository_url=https://crates.corp.example/", "npm/acme-npm"}
			if c.warning != "" {
				want = want[1:]
			}
			if strings.Join(trusted, " ") != strings.Join(want, " ") {
				t.Errorf("trusted = %v, want %v", trusted, want)
			}
			if got := warn.Drain(ctx); c.warning == "" && strings.Contains(got, "registry trust") || c.warning != "" && strings.Count(got, c.warning) != 1 {
				t.Errorf("warnings = %q, want %q once", got, c.warning)
			}
		})
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
