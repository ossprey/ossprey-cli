package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var rangeCases = []string{
	"^4.17.0", "~1", "~1.2", "~1.2.3", "~>1.2", "1.x", "1.2.x", "1", "1.2", "*", "x",
	">=1 <2", ">= 1.2 < 2", ">1", ">1.2", "<1.2", "<=1.2", "<=1", ">=1.2.3", "<2.0.0",
	"=1.2.3", "1.2.3", "v1.2.3", "^0.2.3", "^0.0.3", "^0.0", "^0", "^1.2.x", "^1.x",
	"1.2.3 - 2.3.4", "1.2 - 2.3", "1 - 2", "1.2.3 - 2", "^1.2.3-beta.2", "~1.2.3-beta",
	">=1.2.3-alpha <1.2.4", "1.x || >=2.5.0 || 5.0.0 - 7.2.3", "<0.0.0", ">*", "",
}

var versionCases = []string{
	"0.0.1", "0.0.3", "0.0.4", "0.2.3", "0.2.9", "0.3.0", "1.0.0", "1.2.0", "1.2.3",
	"1.2.3-beta.1", "1.2.3-beta.2", "1.2.3-beta.10", "1.2.3-alpha", "1.2.4", "1.2.9",
	"1.3.0", "1.9.9", "2.0.0-rc.1", "2.0.0", "2.3.4", "2.3.5", "2.5.0", "3.0.0",
	"4.17.0", "4.17.21", "5.0.0", "7.2.3", "7.2.4",
}

// The range matcher is a port, so it is held to the original: every case is
// asked of the semver package npm bundles, and any disagreement fails.
func TestNpmRangeMatchesNodeSemver(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm not installed")
	}
	cli, err := filepath.EvalSymlinks(npm)
	if err != nil {
		t.Skipf("resolve npm: %v", err)
	}
	semverDir := filepath.Join(filepath.Dir(filepath.Dir(cli)), "node_modules", "semver")
	if _, err := os.Stat(semverDir); err != nil {
		t.Skipf("no semver bundled beside %s", cli)
	}
	in, _ := json.Marshal(map[string][]string{"ranges": rangeCases, "versions": versionCases})
	const script = `
const semver = require(process.argv[1])
const { ranges, versions } = JSON.parse(process.argv[2])
const out = {}
for (const r of ranges) {
  out[r] = { valid: semver.validRange(r) !== null, sat: versions.filter((v) => semver.satisfies(v, r)) }
}
console.log(JSON.stringify(out))
`
	raw, err := exec.Command(node, "-e", script, semverDir, string(in)).Output()
	if err != nil {
		t.Fatalf("node semver: %v", err)
	}
	var want map[string]struct {
		Valid bool
		Sat   []string
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for _, rs := range rangeCases {
		r, ok := parseNpmRange(rs)
		if ok != want[rs].Valid {
			t.Errorf("range %q: valid = %v, node-semver says %v", rs, ok, want[rs].Valid)
			continue
		}
		if !ok {
			continue
		}
		sat := map[string]bool{}
		for _, v := range want[rs].Sat {
			sat[v] = true
		}
		for _, vs := range versionCases {
			v, _ := parseSemver(vs)
			if got := r.satisfies(v); got != sat[vs] {
				t.Errorf("satisfies(%q, %q) = %v, node-semver says %v", vs, rs, got, sat[vs])
			}
		}
	}
}

// A range or a dist-tag is resolved to the release npm would install, not
// sent as if it were a version — which named no release, so the package that
// was installed went unchecked.
func TestResolve_NpmRangeAndTag(t *testing.T) {
	var accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		io.WriteString(w, `{"dist-tags":{"latest":"4.17.21","next":"5.0.0-rc.1"},
			"versions":{"3.10.1":{},"4.17.0":{},"4.17.21":{},"5.0.0-rc.1":{},"2.4.2":{}}}`)
	}))
	defer srv.Close()
	pointAt(t, srv)

	for _, tc := range []struct{ constraint, want string }{
		{"", "4.17.21"},
		{"^4.17.0", "4.17.21"}, // latest satisfies: npm prefers it
		{"^3", "3.10.1"},       // highest match below latest
		{"~2.4", "2.4.2"},
		{"next", "5.0.0-rc.1"},     // a dist-tag
		{"^9", "4.17.21"},          // nothing matches: latest
		{"no-such-tag", "4.17.21"}, // unknown tag: latest
	} {
		got, err := Resolve(context.Background(), "npm", "lodash", tc.constraint)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.constraint, err)
		}
		if got != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.constraint, got, tc.want)
		}
	}
	if accept != "application/vnd.npm.install-v1+json" {
		t.Errorf("Accept = %q, want the abbreviated packument", accept)
	}
}

// npm ranks deprecated versions last, and skips a deprecated latest: checking
// the top match regardless would check a release npm does not install.
func TestResolve_NpmSkipsDeprecated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"dist-tags":{"latest":"1.2.5"},
			"versions":{"1.2.3":{},"1.2.4":{"deprecated":false},"1.2.5":{"deprecated":"oops"},
			"2.0.0":{"deprecated":"a"},"2.0.1":{"deprecated":"b"}}}`)
	}))
	defer srv.Close()
	pointAt(t, srv)

	for _, tc := range []struct{ constraint, want string }{
		{"^1", "1.2.4"},    // deprecated latest and top match both skipped
		{"^2", "2.0.1"},    // all deprecated: highest of them
		{"1.2.5", "1.2.5"}, // an exact range still gets its one version
	} {
		got, err := Resolve(context.Background(), "npm", "x", tc.constraint)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.constraint, err)
		}
		if got != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.constraint, got, tc.want)
		}
	}
}

// A lookup failure is returned untouched, so the caller still grades a 404 apart
// from an outage.
func TestResolve_NpmNotFoundIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	pointAt(t, srv)
	if _, err := Resolve(context.Background(), "npm", "nope", "^1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
