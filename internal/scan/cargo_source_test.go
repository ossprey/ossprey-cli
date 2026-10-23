package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/anchore/packageurl-go"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// stubCratesIo turns version lookup on, answers every lookup with 9.9.9 and
// returns the crate names it was asked for.
func stubCratesIo(t *testing.T) func() []string {
	t.Helper()
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	var mu sync.Mutex
	var asked []string
	old := registry.DefaultHTTP
	registry.DefaultHTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		asked = append(asked, path.Base(r.URL.Path))
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"crate":{"max_stable_version":"9.9.9"}}`)),
			Request:    r,
		}, nil
	})}
	t.Cleanup(func() { registry.DefaultHTTP = old })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(asked)
	}
}

func writeCargoProject(t *testing.T, manifest, lock string) string {
	t.Helper()
	dir := t.TempDir()
	if manifest != "" {
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// wirePurls returns the sorted purls of the MiniBOM the scan submits.
func wirePurls(sbom *ossbom.SBOM) []string {
	var out []string
	for _, c := range sbom.ToMiniBOM().Components {
		out = append(out, c.Purl)
	}
	slices.Sort(out)
	return out
}

func assertPurls(t *testing.T, got, want []string) {
	t.Helper()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("wire purls:\n got  %s\n want %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

const (
	forkedCommit = "0123456789abcdef0123456789abcdef01234567"
	twinCommit   = "89abcdef0123456789abcdef0123456789abcdef"
)

// A git or private-registry crate is not the crates.io crate of that name, so
// it goes out marked with its source rather than as a bare crates.io purl
// (OSS-2484). crates.io itself, in any spelling Cargo resolves to it, is unchanged.
func TestRunMarksCargoLockCratesFromOtherSources(t *testing.T) {
	noCI(t)
	asked := stubCratesIo(t)
	// forked-crate is a [patch] of a crates.io dependency: the manifest's
	// versionless sighting must fold into the git crate, not be looked up.
	dir := writeCargoProject(t, `[package]
name = "acme-root-app"
version = "0.1.0"

[dependencies]
evil-crate = "1"
forked-crate = "2"

[patch.crates-io]
forked-crate = { git = "https://git.example.com/acme/forked-crate", branch = "main" }
`, `version = 4

[[package]]
name = "acme-root-app"
version = "0.1.0"

[[package]]
name = "evil-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "mirror-crate"
version = "5.0.0"
source = "sparse+https://index.crates.io/"
checksum = "bbbb"

[[package]]
name = "forked-crate"
version = "2.0.0"
source = "git+https://git.example.com/acme/forked-crate?branch=main#`+forkedCommit+`"

[[package]]
name = "internal-crate"
version = "3.0.0"
source = "registry+https://crates.corp.example/git/index"
checksum = "cccc"

[[package]]
name = "sparse-internal-crate"
version = "4.0.0"
source = "sparse+https://crates.example.net/api/v1/crates/"
checksum = "dddd"

[[package]]
name = "lookalike-crate"
version = "1.0.0"
source = "registry+https://github.com.evil.example/rust-lang/crates.io-index"
checksum = "eeee"

[[package]]
name = "twin-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ffff"

[[package]]
name = "twin-crate"
version = "1.0.0"
source = "git+ssh://git@git.example.com/acme/twin-crate.git#`+twinCommit+`"

[[package]]
name = "upper-host-crate"
version = "1.0.0"
source = "registry+https://GITHUB.COM/rust-lang/crates.io-index"

[[package]]
name = "port-host-crate"
version = "1.0.0"
source = "registry+https://github.com:443/rust-lang/crates.io-index"

[[package]]
name = "dot-path-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/./crates.io-index"

[[package]]
name = "canonical-path-crate"
version = "1.0.0"
source = "registry+http://github.com/Rust-Lang/crates.io-index.git/"

[[package]]
name = "escaped-host-crate"
version = "1.0.0"
source = "registry+https://git%48ub.com/rust-lang/crates.io-index"

[[package]]
name = "wide-host-crate"
version = "1.0.0"
source = "registry+https://ｇｉｔｈｕｂ.com/rust-lang/crates.io-index"

[[package]]
name = "backslash-crate"
version = "1.0.0"
source = "registry+https:\\\\github.com\\rust-lang\\crates.io-index"

[[package]]
name = "sparse-dot-crate"
version = "1.0.0"
source = "sparse+https://index.crates.io/./"

[[package]]
name = "fork-index-crate"
version = "1.0.0"
source = "registry+https://github.com/acme/crates.io-index"
`)

	sbom, err := Run(warn.NewContext(context.Background(), true), Options{Path: dir, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}

	assertPurls(t, wirePurls(sbom), []string{
		"pkg:cargo/evil-crate@1.0.0",
		"pkg:cargo/mirror-crate@5.0.0",
		"pkg:cargo/twin-crate@1.0.0",
		"pkg:cargo/forked-crate@2.0.0?vcs_url=git%2Bhttps:%2F%2Fgit.example.com%2Facme%2Fforked-crate%40" + forkedCommit,
		"pkg:cargo/twin-crate@1.0.0?vcs_url=git%2Bssh:%2F%2Fgit.example.com%2Facme%2Ftwin-crate.git%40" + twinCommit,
		"pkg:cargo/internal-crate@3.0.0?repository_url=https:%2F%2Fcrates.corp.example%2F",
		"pkg:cargo/sparse-internal-crate@4.0.0?repository_url=https:%2F%2Fcrates.example.net%2F",
		"pkg:cargo/lookalike-crate@1.0.0?repository_url=https:%2F%2Fgithub.com.evil.example%2F",
		"pkg:cargo/fork-index-crate@1.0.0?repository_url=https:%2F%2Fgithub.com%2F",
		// Spellings real Cargo resolves to crates.io once its URL parser and CanonicalUrl have folded them.
		"pkg:cargo/upper-host-crate@1.0.0",
		"pkg:cargo/port-host-crate@1.0.0",
		"pkg:cargo/dot-path-crate@1.0.0",
		"pkg:cargo/canonical-path-crate@1.0.0",
		"pkg:cargo/escaped-host-crate@1.0.0",
		"pkg:cargo/wide-host-crate@1.0.0",
		"pkg:cargo/backslash-crate@1.0.0",
		"pkg:cargo/sparse-dot-crate@1.0.0",
	})
	if got := asked(); len(got) != 0 {
		t.Errorf("crates.io was asked about %v; every crate here is versioned", got)
	}

	// A standard parser reads the source back out of the wire purl.
	for _, s := range wirePurls(sbom) {
		p, err := packageurl.FromString(s)
		if err != nil {
			t.Errorf("%s does not parse: %v", s, err)
			continue
		}
		if p.Name == "forked-crate" {
			want := "git+https://git.example.com/acme/forked-crate@" + forkedCommit
			if got := p.Qualifiers.Map()["vcs_url"]; got != want {
				t.Errorf("vcs_url parses as %q, want %q", got, want)
			}
		}
	}

	// --local carries the same marks for the service, and nothing for crates.io.
	var local struct {
		Components []map[string]any `json:"components"`
	}
	var buf bytes.Buffer
	if err := sbom.Encode(&buf); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf.Bytes(), &local); err != nil {
		t.Fatal(err)
	}
	marked := map[string]any{}
	for _, c := range local.Components {
		if q, ok := c["qualifiers"]; ok {
			marked[c["name"].(string)] = q
		} else if c["name"] == "internal-crate" {
			t.Errorf("--local lost internal-crate's source: %v", c)
		}
	}
	if q, _ := marked["forked-crate"].(map[string]any); q["vcs_url"] != "git+https://git.example.com/acme/forked-crate@"+forkedCommit {
		t.Errorf("--local forked-crate qualifiers = %v", marked["forked-crate"])
	}
	for _, name := range []string{"evil-crate", "mirror-crate"} {
		if q, ok := marked[name]; ok {
			t.Errorf("--local gave crates.io crate %s qualifiers %v", name, q)
		}
	}
}

// A versionless foreign lock entry (hand-edited: Cargo rejects one) is never looked up or folded into a crates.io release.
func TestRunNeverPinsAForeignCrateToCratesIo(t *testing.T) {
	noCI(t)
	asked := stubCratesIo(t)
	dir := writeCargoProject(t, "", `version = 4

[[package]]
name = "ghost-crate"
source = "git+https://git.example.com/acme/ghost-crate#`+forkedCommit+`"

[[package]]
name = "shadow-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "shadow-crate"
source = "registry+https://crates.corp.example/git/index"
`)

	sbom, err := Run(warn.NewContext(context.Background(), true), Options{Path: dir, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}

	assertPurls(t, wirePurls(sbom), []string{
		"pkg:cargo/ghost-crate@?vcs_url=git%2Bhttps:%2F%2Fgit.example.com%2Facme%2Fghost-crate%40" + forkedCommit,
		"pkg:cargo/shadow-crate@1.0.0",
		"pkg:cargo/shadow-crate@?repository_url=https:%2F%2Fcrates.corp.example%2F",
	})
	if got := asked(); len(got) != 0 {
		t.Errorf("crates.io was asked about %v; a foreign crate's latest there is another crate", got)
	}
}

// A lockless project's crates.io dependency is not folded into another workspace's git crate of that name.
func TestRunKeepsAnotherWorkspacesCratesIoDep(t *testing.T) {
	noCI(t)
	asked := stubCratesIo(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"a/Cargo.toml": `[package]
name = "acme-a-app"
version = "0.1.0"

[dependencies]
fold-crate = { git = "https://git.example.com/acme/fold-crate" }
`,
		"a/Cargo.lock": `version = 4

[[package]]
name = "acme-a-app"
version = "0.1.0"

[[package]]
name = "fold-crate"
version = "2.0.0"
source = "git+https://git.example.com/acme/fold-crate#` + forkedCommit + `"
`,
		"b/Cargo.toml": `[package]
name = "acme-b-lib"
version = "0.1.0"

[dependencies]
fold-crate = "1"
`,
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	sbom, err := Run(warn.NewContext(context.Background(), true), Options{Path: dir, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}

	assertPurls(t, wirePurls(sbom), []string{
		"pkg:cargo/fold-crate@2.0.0?vcs_url=git%2Bhttps:%2F%2Fgit.example.com%2Facme%2Ffold-crate%40" + forkedCommit,
		"pkg:cargo/fold-crate@9.9.9",
	})
	if got := asked(); !slices.Equal(got, []string{"fold-crate"}) {
		t.Errorf("crates.io was asked about %v; b's fold-crate is a crates.io dependency", got)
	}
}

// Credentials in a Cargo.lock source never leave the machine: not on the
// wire, not in --local, not in a warning.
func TestRunNeverSendsCargoSourceCredentials(t *testing.T) {
	noCI(t)
	stubCratesIo(t)
	dir := writeCargoProject(t, "", `version = 4

[[package]]
name = "token-git-crate"
version = "1.0.0"
source = "git+https://deploy-user:s3cr3t-pat@git.example.com/acme/token-git-crate?branch=main&access_token=tok3n-in-query#`+forkedCommit+`"

[[package]]
name = "token-registry-crate"
version = "1.0.0"
source = "registry+https://registry-user:passw0rd-here@crates.corp.example/git/index?token=qu3ry-token"

[[package]]
name = "path-token-crate"
version = "1.0.0"
source = "sparse+https://dl.example.com/ent1tlement-t0ken/acme/cargo/index/"

[[package]]
name = "broken-crate"
version = "1.0.0"
source = "git+https://broken-user:br0ken-s3cret@git.example.com:notaport/acme/broken-crate#`+forkedCommit+`"
`)

	ctx := warn.NewContext(context.Background(), true)
	sbom, err := Run(ctx, Options{Path: dir, NoExec: true})
	if err != nil {
		t.Fatal(err)
	}

	assertPurls(t, wirePurls(sbom), []string{
		"pkg:cargo/token-git-crate@1.0.0?vcs_url=git%2Bhttps:%2F%2Fgit.example.com%2Facme%2Ftoken-git-crate%40" + forkedCommit,
		"pkg:cargo/token-registry-crate@1.0.0?repository_url=https:%2F%2Fcrates.corp.example%2F",
		"pkg:cargo/path-token-crate@1.0.0?repository_url=https:%2F%2Fdl.example.com%2F",
	})

	wire, err := json.Marshal(sbom.ToMiniBOM())
	if err != nil {
		t.Fatal(err)
	}
	var local bytes.Buffer
	if err := sbom.Encode(&local); err != nil {
		t.Fatal(err)
	}
	warnings := warn.Drain(ctx)
	if !strings.Contains(warnings, "broken-crate") {
		t.Errorf("the unreadable source was dropped without a warning:\n%s", warnings)
	}
	for _, secret := range []string{
		"deploy-user", "s3cr3t-pat", "access_token", "tok3n-in-query",
		"registry-user", "passw0rd-here", "qu3ry-token",
		"ent1tlement-t0ken", "broken-user", "br0ken-s3cret",
	} {
		for where, out := range map[string]string{"wire": string(wire), "--local": local.String(), "warnings": warnings} {
			if strings.Contains(out, secret) {
				t.Errorf("%s output carries %q:\n%s", where, secret, out)
			}
		}
	}
}
