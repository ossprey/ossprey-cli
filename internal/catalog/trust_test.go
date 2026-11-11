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
	"github.com/anchore/syft/syft/source"

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

[[package]]
name = "acme-empty-segment"
version = "1.0.0"
source = "registry+https://crates.corp.example/public//../internal/index"

[[package]]
name = "acme-dot-segment"
version = "1.0.0"
source = "sparse+https://crates.corp.example/./internal/"

[[package]]
name = "acme-trailing-dots"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal/acme/.."

[[package]]
name = "acme-nested"
version = "1.0.0"
source = "registry+https://crates.corp.example/internal/crates/index"

[[package]]
name = "acme-trailing-nbsp"
version = "1.0.0"
source = "registry+https://crates.corp.example/internal\u00a0"

[[package]]
name = "acme-leading-nbsp"
version = "1.0.0"
source = "\u00a0sparse+https://crates.corp.example/internal/"

[[package]]
name = "acme-tab"
version = "1.0.0"
source = "sparse+https://crates.corp.example/inter\tnal/"

[[package]]
name = "acme-space"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal/acme crates/"

[[package]]
name = "acme-sparse-backslash"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal\\outside/"

[[package]]
name = "acme-registry-backslash"
version = "1.0.0"
source = "registry+https://crates.corp.example/internal\\index"

[[package]]
name = "acme-non-ascii-path"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal/cr\u00e4tes/"

[[package]]
name = "acme-plain"
version = "1.0.0"
source = "sparse+https://crates.corp.example/internal/team-a_b.c~d/"

[[package]]
name = "acme-ipv6"
version = "1.0.0"
source = "sparse+https://[::1]:8443/internal/"
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
		"https://[::1]:8443/internal/",
	}, nil)

	pkgs, err := Catalog(context.Background(), root, Options{NoExec: true, SkipVersionLookup: true, Trust: policy})
	if err != nil {
		t.Fatal(err)
	}
	trusted, checked := trustedNames(pkgs)

	wantTrusted := []string{
		"cargo/acme-hub?repository_url=https://github.com/",             // git index under a host-wide rule
		"cargo/acme-index?repository_url=https://git.corp.example/",     // git index under its repository prefix
		"cargo/acme-nested?repository_url=https://crates.corp.example/", // a normalised path below the prefix
		"cargo/acme-plain?repository_url=https://crates.corp.example/",  // printable ASCII punctuation in a path below the prefix
		"cargo/acme-sparse?repository_url=https://crates.corp.example/", // sparse index
		"cargo/acme-twin?repository_url=https://crates.corp.example/",   // the private crate of that name
	}
	wantChecked := []string{
		"cargo/acme-backslash?repository_url=https:///",                        // Cargo reads github.com\ as userinfo and fetches from evil.example
		"cargo/acme-dot-segment?repository_url=https://crates.corp.example/",   // a path segment Cargo and path.Clean may resolve apart
		"cargo/acme-dotted?repository_url=https://g%C4%B0t.corp.example/",      // Go folds İ to i, Cargo's IDNA does not
		"cargo/acme-empty-segment?repository_url=https://crates.corp.example/", // Cargo's ".." pops the empty segment, landing in /public/internal/
		// Cargo keeps an escape inside its path segment where Go decodes and cleans it into the trusted prefix.
		"cargo/acme-escaped-backslash?repository_url=https://crates.corp.example/",
		"cargo/acme-escaped-dots?repository_url=https://crates.corp.example/",
		"cargo/acme-escaped-lower?repository_url=https://git.corp.example/",
		"cargo/acme-escaped-slash?repository_url=https://crates.corp.example/",
		// Git is never a registry, even under a trusted prefix.
		"cargo/acme-git?vcs_url=git+https://git.corp.example/acme/acme-git@0123456789abcdef0123456789abcdef01234567",
		"cargo/acme-ipv6?repository_url=https://[::1]:8443/",                    // Go keeps an IP literal as written where Cargo serialises it
		"cargo/acme-leading-nbsp?repository_url=https://crates.corp.example/",   // Go trims the NBSP, Cargo reads no sparse+ kind
		"cargo/acme-non-ascii-path?repository_url=https://crates.corp.example/", // only printable ASCII counts
		"cargo/acme-proxied?repository_url=https://crates.corp.example/",        // same host, another registry
		"cargo/acme-registry-backslash?repository_url=https://crates.corp.example/",
		"cargo/acme-space?repository_url=https://crates.corp.example/",
		"cargo/acme-sparse-backslash?repository_url=https://crates.corp.example/", // Cargo keeps '\' inside one sparse+ segment, Go cleans it to /internal/outside/
		"cargo/acme-tab?repository_url=https://crates.corp.example/",
		"cargo/acme-trailing-dots?repository_url=https://crates.corp.example/",
		"cargo/acme-trailing-nbsp?repository_url=https://crates.corp.example/", // Go trims the NBSP, Cargo keeps it as /internal%C2%A0
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
	const linked = "because a symlink in the scan could point cargo at another config"
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
		// A link can resolve differently for cargo than for the scan, so a symlinked config or .cargo is never followed.
		"a config symlinked to its sibling":               {files: map[string]string{"proj/.cargo/replace.toml": replace}, links: map[string]string{"proj/.cargo/config.toml": "replace.toml"}, warning: linked},
		"a config symlinked into another dot directory":   {files: map[string]string{"proj/.yarn/cargo.toml": replace}, links: map[string]string{"proj/.cargo/config.toml": "../.yarn/cargo.toml"}, warning: linked},
		"a symlinked config beside a plain one":           {files: map[string]string{"proj/.cargo/replace.toml": replace, "proj/.cargo/config.toml": "[net]\nretry = 2\n"}, links: map[string]string{"proj/.cargo/config": "replace.toml"}, warning: linked},
		"a symlinked config named in another case":        {files: map[string]string{"proj/.cargo/replace.toml": replace}, links: map[string]string{"proj/.cargo/Config.toml": "replace.toml"}, warning: linked},
		"a .cargo directory symlinked to a dot directory": {files: map[string]string{"proj/.yarn/config.toml": replace}, links: map[string]string{"proj/.cargo": ".yarn"}, warning: linked},
		"a .cargo directory symlinked above the root":     {files: map[string]string{"dotcargo/config.toml": "[net]\nretry = 2\n"}, links: map[string]string{".cargo": "dotcargo"}, warning: unread},
		"a config symlinked in CARGO_HOME":                {files: map[string]string{"cargo.toml": "[net]\nretry = 2\n"}, links: map[string]string{"home/config.toml": "../cargo.toml"}, warning: unread},
		// An alias applies its --config value or file whenever it runs.
		"an alias passing --config":                 {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nxtask = \"run --config xtask/replace.toml --package xtask --\"\n"}, warning: aliased},
		"an alias passing --config= above the root": {files: map[string]string{".cargo/config.toml": "[alias]\nb = [\"build\", \"--config=source.corp.replace-with='elsewhere'\"]\n"}, warning: aliased},
		"an alias without --config":                 {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nxtask = \"run --package xtask --\"\n"}},
		"an array alias without --config":           {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nb = [\"build\", \"--release\"]\n"}},
		// An alias that quotes, escapes or runs a shell may pass --config where a whitespace split sees none.
		"an alias with single quotes":          {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nb = \"build '--config' overrides.toml\"\n"}, warning: aliased},
		"an alias with double quotes":          {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nb = 'build \"--config\" overrides.toml'\n"}, warning: aliased},
		"an alias with a backslash":            {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nb = 'build \\--config overrides.toml'\n"}, warning: aliased},
		"an alias starting with !":             {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nb = \"!cargo build --release\"\n"}, warning: aliased},
		"an array alias with a quoted element": {files: map[string]string{"proj/.cargo/config.toml": "[alias]\nb = [\"build\", \"'--config'\", \"overrides.toml\"]\n"}, warning: aliased},
		"an array alias with a backslash":      {files: map[string]string{".cargo/config.toml": "[alias]\nb = [\"build\", '\\--config', \"overrides.toml\"]\n"}, warning: aliased},
		// cargo reads .cargo above its physical cwd, so a build in a symlinked directory reads configs the index never holds.
		"a replacement above a symlinked directory in a package sink": {files: map[string]string{"proj/.yarn/pkg/.cargo/config.toml": replace, "proj/.yarn/pkg/app/.keep": ""}, links: map[string]string{"proj/app": ".yarn/pkg/app"}, warning: linked},
		"a replacement above a symlinked directory outside the scan":  {files: map[string]string{"elsewhere/pkg/.cargo/config.toml": replace, "elsewhere/pkg/app/.keep": ""}, links: map[string]string{"proj/app": "../elsewhere/pkg/app"}, warning: linked},
		"an include above a symlinked directory in a package sink":    {files: map[string]string{"proj/target/.cargo/config": "include = \"extra.toml\"\n", "proj/target/app/.keep": ""}, links: map[string]string{"proj/app": "target/app"}, warning: linked},
		"a plain config above a symlinked directory":                  {files: map[string]string{"proj/.yarn/pkg/.cargo/config.toml": "[net]\nretry = 2\n", "proj/.yarn/pkg/app/.keep": ""}, links: map[string]string{"proj/app": ".yarn/pkg/app"}, warning: linked},
		"a dangling directory symlink":                                {links: map[string]string{"proj/app": ".yarn/missing"}, warning: linked},
		// Any link in the index ends trust, since the index cleans a target's ".." before an unindexed link in it resolves.
		"a symlink to a file outside the scan": {files: map[string]string{"LICENSE": ""}, links: map[string]string{"proj/LICENSE": "../LICENSE"}, warning: linked},
		"a symlink to a file in the scan":      {files: map[string]string{"proj/docs/LICENSE": ""}, links: map[string]string{"proj/LICENSE": "docs/LICENSE"}, warning: linked},
		"a symlink through a sink link and ..": {files: map[string]string{"proj/y": "", "proj/target/a/b/.keep": "", "proj/target/a/y/.cargo/config.toml": replace}, links: map[string]string{"proj/node_modules": "target/a/b", "proj/app": "node_modules/../y"}, warning: linked},
		// Only a regular file is read, as a device or FIFO may never end.
		"a config symlinked to a device": {links: map[string]string{"proj/.cargo/config.toml": "/dev/zero"}, warning: linked},
		"a config that is a directory":   {files: map[string]string{"proj/.cargo/config.toml/.keep": ""}, warning: unread},
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

// A lock copied out of its workspace is trusted by the configs cargo reads where it runs, not by those around the copy.
func TestCatalogReadsCargoConfigsFromWhereCargoRuns(t *testing.T) {
	replace := "[source.corp]\nregistry = \"sparse+https://crates.corp.example/internal/\"\nreplace-with = \"elsewhere\"\n"
	lock := "version = 4\n\n[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+https://crates.corp.example/internal/\"\nchecksum = \"aaaa\"\n"
	for name, c := range map[string]struct {
		files   map[string]string
		trusted bool
	}{
		"a clean workspace":                      {trusted: true},
		"a replacement where cargo runs":         {files: map[string]string{"ws/member/.cargo/config.toml": replace}},
		"a replacement above where cargo runs":   {files: map[string]string{"ws/.cargo/config.toml": replace}},
		"a replacement above both":               {files: map[string]string{".cargo/config.toml": replace}},
		"a replacement in the copy, not read":    {files: map[string]string{"copy/lock/.cargo/config.toml": replace}, trusted: true},
		"a replacement above the copy, not read": {files: map[string]string{"copy/.cargo/config.toml": replace}, trusted: true},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("CARGO_HOME", filepath.Join(base, "home"))
			writeTree(t, base, map[string]string{"home/.keep": "", "ws/member/.keep": "", "copy/lock/Cargo.lock": lock})
			writeTree(t, base, c.files)
			ctx := warn.NewContext(context.Background(), false)
			policy := testPolicy(t, []string{"https://crates.corp.example/internal/"}, nil)

			pkgs, err := Catalog(ctx, filepath.Join(base, "copy", "lock"), Options{NoExec: true, SkipVersionLookup: true, Trust: policy,
				CargoConfigDir: filepath.Join(base, "ws", "member")})
			if err != nil {
				t.Fatal(err)
			}
			if trusted, _ := trustedNames(pkgs); (len(trusted) == 1) != c.trusted {
				t.Errorf("trusted = %v, want trusted %v", trusted, c.trusted)
			}
		})
	}
}

// cargo 1.99.1 joins a relative CARGO_HOME to where it runs, -C's directory for a copied lock, and cleans `..` without following links (OSS-2553).
func TestCatalogReadsARelativeCargoHomeAsCargoDoes(t *testing.T) {
	mirror := "[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"sparse+https://crates.elsewhere.example/\"\n"
	lock := appLock(registrySerde, "[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+https://crates.corp.example/internal/\"\nchecksum = \"aaaa\"\n")
	for name, c := range map[string]struct {
		// cwd is the process's, configDir where cargo runs for a copied lock, and config the directory holding the mirror.
		cwd, home, configDir, config string
		replaced                     bool
	}{
		"a relative home in a scan":                      {home: "h", config: "h", replaced: true},
		"lnk/../h in a scan":                             {home: "lnk/../h", config: "h", replaced: true},
		"lnk/../h in a scan, not the link's parent":      {home: "lnk/../h", config: "other/h"},
		"a relative home for a copied lock":              {home: "h", configDir: "ws/member", config: "ws/member/h", replaced: true},
		"a relative home for a copied lock, not the cwd": {home: "h", configDir: "ws/member", config: "h"},
		"lnk/../h for a copied lock":                     {cwd: "ws/member", home: "lnk/../h", configDir: "ws/member", config: "ws/member/h", replaced: true},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			if real, err := filepath.EvalSymlinks(base); err == nil {
				base = real
			}
			writeTree(t, base, map[string]string{
				"proj/Cargo.toml":         "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
				"proj/Cargo.lock":         lock,
				"copy/lock/Cargo.lock":    lock,
				"ws/member/.keep":         "",
				"other/deep/.keep":        "",
				"other/h/.keep":           "",
				c.config + "/config.toml": mirror,
			})
			if strings.Contains(c.home, "lnk") {
				if runtime.GOOS == "windows" {
					t.Skip("symlinks need privileges on Windows")
				}
				if err := os.Symlink(filepath.Join(base, "other", "deep"), filepath.Join(base, c.cwd, "lnk")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			t.Chdir(filepath.Join(base, c.cwd))
			t.Setenv("CARGO_HOME", c.home)
			root, configDir := filepath.Join(base, "proj"), ""
			if c.configDir != "" {
				root, configDir = filepath.Join(base, "copy", "lock"), filepath.Join(base, c.configDir)
			}
			ctx := warn.NewContext(context.Background(), false)
			policy := testPolicy(t, []string{"https://crates.corp.example/internal/"}, nil)

			pkgs, err := Catalog(ctx, root, Options{NoExec: true, SkipVersionLookup: true, Trust: policy, ReportCargoReplacement: true, CargoConfigDir: configDir})
			if err != nil {
				t.Fatal(err)
			}
			if trusted, _ := trustedNames(pkgs); (len(trusted) == 0) != c.replaced {
				t.Errorf("trusted = %v, want trusted %v", trusted, !c.replaced)
			}
			if got := warn.Drain(ctx); strings.Contains(got, cargoReplacedEntry.One) != c.replaced {
				t.Errorf("warnings = %q, want the crates.io replacement %v", got, c.replaced)
			}
		})
	}
}

// A cancelled scan may close the walk before a link or config, so no crate is trusted by registry.
func TestCatalogTrustsNoCrateWhenTheConfigWalkIsCancelled(t *testing.T) {
	base := t.TempDir()
	t.Setenv("CARGO_HOME", filepath.Join(base, "home"))
	writeTree(t, base, map[string]string{
		"home/.keep":       "",
		"proj/Cargo.lock":  "version = 4\n\n[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+https://crates.corp.example/internal/\"\nchecksum = \"aaaa\"\n",
		"proj/src/main.rs": "fn main() {}\n",
	})
	root := filepath.Join(base, "proj")
	src, err := newDirectorySource(root)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	r, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	const index = "https://crates.corp.example/internal/"
	policy := testPolicy(t, []string{index}, nil)
	for name, cancelled := range map[string]bool{"a live scan": false, "a cancelled scan": true} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(warn.NewContext(context.Background(), false))
			defer cancel()
			if cancelled {
				cancel()
			}
			pkgs := []Package{{Name: "acme-sparse", Version: "1.0.0", Type: "cargo", Registries: []string{index}}}
			clearReplacedCrateRegistries(ctx, pkgs, policy, r, root, "")
			markTrustedPackages(pkgs, policy)
			if pkgs[0].Trusted == cancelled {
				t.Errorf("trusted = %v, want %v", pkgs[0].Trusted, !cancelled)
			}
			if got := warn.Drain(ctx); cancelled && strings.Count(got, "because a cargo config could not be read") != 1 || !cancelled && got != "" {
				t.Errorf("warnings = %q", got)
			}
		})
	}
}

// A dotfile manager's linked cargo config is read through by the vendor filter, but counts as unreadable for registry trust.
func TestCatalogReadsALinkedCargoConfigForVendoringOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	for name, link := range map[string][2]string{
		"a config symlinked in CARGO_HOME":            {"home/config.toml", "dotfiles/cargo/config.toml"},
		"a .cargo directory symlinked above the root": {".cargo", "dotfiles/cargo"},
	} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("CARGO_HOME", filepath.Join(base, "home"))
			writeTree(t, base, map[string]string{
				"home/.keep":                 "",
				"dotfiles/cargo/config.toml": "[net]\nretry = 2\n",
				"trusted/Cargo.lock":         "version = 4\n\n[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+https://crates.corp.example/internal/\"\nchecksum = \"aaaa\"\n",
			})
			if err := os.Symlink(filepath.Join(base, link[1]), filepath.Join(base, link[0])); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			proj := filepath.Join(base, "vendoring")
			vendoredCrate(t, proj, "vendor/serde", "1.0.228", "cccc", "[dev-dependencies]\nserde_derive = \"=1.0.228\"\n")
			vendoringRoot(t, proj, "", "", lockEntry("serde", "1.0.228", "cccc"))

			pkgs, err := Catalog(context.Background(), proj, Options{NoExec: true, SkipVersionLookup: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range pkgs {
				if p.Name == "serde_derive" {
					t.Errorf("serde_derive came from a proven vendored crate, so the filter never ran")
				}
			}

			ctx := warn.NewContext(context.Background(), false)
			policy := testPolicy(t, []string{"https://crates.corp.example/internal/"}, nil)
			if pkgs, err = Catalog(ctx, filepath.Join(base, "trusted"), Options{NoExec: true, SkipVersionLookup: true, Trust: policy}); err != nil {
				t.Fatal(err)
			}
			if trusted, _ := trustedNames(pkgs); len(trusted) != 0 {
				t.Errorf("trusted = %v, want none", trusted)
			}
			if got := warn.Drain(ctx); strings.Count(got, "because a cargo config could not be read") != 1 {
				t.Errorf("warnings = %q, want the unread config once", got)
			}
		})
	}
}

// On a case-sensitive filesystem a CARGO_HOME spelled like an ancestor's .cargo in another case is another directory, so both configs are read.
func TestCatalogReadsACargoHomeThatDiffersFromAnAncestorOnlyByCase(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "PROJ")); err == nil {
		t.Skip("the filesystem folds case")
	}
	writeTree(t, base, map[string]string{
		"proj/.cargo/config.toml": "[net]\nretry = 2\n",
		"PROJ/.cargo/config.toml": "[source.corp]\nregistry = \"sparse+https://crates.corp.example/internal/\"\nreplace-with = \"elsewhere\"\n",
		"proj/app/Cargo.lock":     "version = 4\n\n[[package]]\nname = \"acme-sparse\"\nversion = \"1.0.0\"\nsource = \"sparse+https://crates.corp.example/internal/\"\nchecksum = \"aaaa\"\n",
	})
	t.Setenv("CARGO_HOME", filepath.Join(base, "PROJ", ".cargo"))
	ctx := warn.NewContext(context.Background(), false)
	policy := testPolicy(t, []string{"https://crates.corp.example/internal/"}, nil)

	pkgs, err := Catalog(ctx, filepath.Join(base, "proj", "app"), Options{NoExec: true, SkipVersionLookup: true, Trust: policy})
	if err != nil {
		t.Fatal(err)
	}
	if trusted, _ := trustedNames(pkgs); len(trusted) != 0 {
		t.Errorf("trusted = %v, want none", trusted)
	}
	if got := warn.Drain(ctx); strings.Count(got, "because a source replacement is configured") != 1 {
		t.Errorf("warnings = %q, want the replacement once", got)
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
