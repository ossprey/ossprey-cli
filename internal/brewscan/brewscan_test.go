package brewscan

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/gitscan"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/scan"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

func TestTargets(t *testing.T) {
	cases := []struct {
		args       []string
		want       string
		head, isOK bool
	}{
		{[]string{"install", "jq", "homebrew/core/ripgrep"}, "jq,ripgrep", false, true},
		{[]string{"--debug", "reinstall", "--HEAD", "python@3.12"}, "python@3.12", true, true},
		{[]string{"upgrade"}, "", false, true},
		{[]string{"install", "--cask", "firefox"}, "", false, false},
		{[]string{"install", "user/tap/tool", "./x.rb"}, "", false, true},
		{[]string{"list"}, "", false, false},
		{[]string{"fetch", "jq"}, "", false, false},
	}
	for _, c := range cases {
		names, head, ok := targets(c.args)
		if strings.Join(names, ",") != c.want || head != c.head || ok != c.isOK {
			t.Errorf("targets(%v) = %v, %v, %v; want %q, %v, %v", c.args, names, head, ok, c.want, c.head, c.isOK)
		}
	}
}

func TestParseArchiveURL(t *testing.T) {
	good := map[string]string{
		"https://github.com/BurntSushi/ripgrep/archive/refs/tags/15.2.0.tar.gz":     "BurntSushi/ripgrep@15.2.0",
		"https://github.com/o/r/archive/v1.0.zip":                                   "o/r@v1.0",
		"https://github.com/o/r/archive/refs/heads/main.tar.gz":                     "o/r@main",
		"https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-1.8.2.tar.gz":   "jqlang/jq@jq-1.8.2",
		"https://codeload.github.com/o/r/tar.gz/v2":                                 "o/r@v2",
		"https://github.com/o/r/archive/" + sha + ".tar.gz":                         "o/r@" + sha,
		"https://github.com/o/r/archive/refs/tags/release/1.0.tar.gz":               "o/r@release/1.0",
		"https://github.com/o/r/releases/download/v1.0/sub/dir.tgz":                 "o/r@v1.0",
		"https://github.com/o/r/archive/refs/tags/v1.0.tar.gz?ignored=1#fragment":   "o/r@v1.0",
		"https://GITHUB.com/o/r/archive/v3.tar.bz2":                                 "o/r@v3",
		"https://github.com/o/r.js/releases/download/v1/r.tar.xz":                   "o/r.js@v1",
		"https://github.com/o/r/archive/refs/tags/v1.0.tar.gz/":                     "o/r@v1.0",
		"https://codeload.github.com/o/r/zip/refs/tags/v9":                          "o/r@refs/tags/v9",
		"https://github.com/o/r/releases/download/untagged-123/a.tar.gz":            "o/r@untagged-123",
		"https://github.com/o/r/archive/refs/tags/1.0.tgz":                          "o/r@1.0",
		"https://github.com/owner-with-dash/repo_with_underscore/archive/v1.tar.gz": "owner-with-dash/repo_with_underscore@v1",
	}
	for in, want := range good {
		s, ok := parseArchiveURL(in)
		if !ok || s.repo.String()+"@"+s.ref != want {
			t.Errorf("parseArchiveURL(%q) = %s@%s, %v; want %s", in, s.repo, s.ref, ok, want)
		}
	}
	for _, in := range []string{
		"https://nodejs.org/dist/v26/node.tar.xz",
		"http://github.com/o/r/archive/v1.tar.gz",
		"https://github.com/o/r",
		"https://github.com/o/r/blob/main/x",
		"https://github.com/o/../archive/v1.tar.gz",
		"https://evilgithub.com/o/r/archive/v1.tar.gz",
	} {
		if s, ok := parseArchiveURL(in); ok {
			t.Errorf("parseArchiveURL(%q) = %+v; want rejected", in, s)
		}
	}
}

func TestSourceOf(t *testing.T) {
	tag, rev := "v1.0", sha
	f := &formula{}
	f.URLs.Stable.URL = "https://github.com/o/r.git"
	f.URLs.Stable.Tag = &tag
	if s, ok := sourceOf(f, false); !ok || s.ref != "v1.0" || s.pinned {
		t.Errorf("git tag: %+v %v", s, ok)
	}
	f.URLs.Stable.Revision = &rev
	if s, ok := sourceOf(f, false); !ok || s.ref != sha || !s.pinned {
		t.Errorf("git revision: %+v %v", s, ok)
	}
	if _, ok := sourceOf(f, true); ok {
		t.Error("--HEAD with no head url should not resolve")
	}
	f.URLs.Head = &struct {
		URL    string `json:"url"`
		Branch string `json:"branch"`
	}{"https://github.com/o/r.git", "main"}
	if s, ok := sourceOf(f, true); !ok || s.ref != "main" {
		t.Errorf("--HEAD: %+v %v", s, ok)
	}
}

func TestPickSHA(t *testing.T) {
	other := strings.Repeat("a", 40)
	out := other + "\trefs/tags/v1\n" + sha + "\trefs/tags/v1^{}\n"
	if got := pickSHA(out, "v1"); got != sha {
		t.Errorf("peeled tag not preferred: %s", got)
	}
	if got := pickSHA(other+"\trefs/heads/main\n", "main"); got != other {
		t.Errorf("branch: %s", got)
	}
	if got := pickSHA("", "v1"); got != "" {
		t.Errorf("empty: %s", got)
	}
}

// fakeBrewAPI serves formulae: name -> {stable url, deps}.
func fakeBrewAPI(t *testing.T, formulae map[string]string, deps map[string][]string, fail string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")
		if name == fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		u, ok := formulae[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		ds := `[]`
		if d := deps[name]; len(d) > 0 {
			ds = `["` + strings.Join(d, `","`) + `"]`
		}
		_, _ = w.Write([]byte(`{"name":"` + name + `","urls":{"stable":{"url":"` + u + `","tag":null,"revision":null}},"dependencies":` + ds + `}`))
	}))
	t.Cleanup(srv.Close)
	old, oldLs := formulaAPIURL, lsRemoteFn
	formulaAPIURL = srv.URL + "/"
	lsRemoteFn = func(gitscan.Repo, string) string { return sha }
	t.Cleanup(func() { formulaAPIURL, lsRemoteFn = old, oldLs })
}

type calls struct {
	execs, handoffs [][]string
	checks          []check.Options
}

func stub(t *testing.T, malicious bool) *calls {
	c := &calls{}
	oldExec, oldHandoff, oldCheck, oldErr, oldProg, oldRepo := execFn, handoffFn, checkFn, errOut, progressOut, repoSBOMFn
	repoSBOMFn = func(context.Context, Options, string) ([]ossbom.Component, error) { return nil, nil }
	execFn = func(_ context.Context, bin string, args []string) error {
		c.execs = append(c.execs, append([]string{bin}, args...))
		return nil
	}
	handoffFn = func(_ context.Context, bin string, args []string) error {
		c.handoffs = append(c.handoffs, append([]string{bin}, args...))
		return nil
	}
	checkFn = func(_ context.Context, o check.Options) (*ossbom.SBOM, error) {
		c.checks = append(c.checks, o)
		sbom := ossbom.New(ossbom.Environment{})
		for _, s := range o.Specs {
			sbom.AddComponent(ossbom.Component{Name: s.Name, Version: s.Version, Type: s.Ecosystem})
		}
		if malicious {
			if err := scan.InjectTestVulnerability(sbom); err != nil {
				t.Fatal(err)
			}
		}
		return sbom, nil
	}
	errOut, progressOut = &bytes.Buffer{}, &bytes.Buffer{}
	t.Cleanup(func() {
		execFn, handoffFn, checkFn, errOut, progressOut, repoSBOMFn = oldExec, oldHandoff, oldCheck, oldErr, oldProg, oldRepo
	})
	return c
}

func specNames(o check.Options) string {
	var s []string
	for _, sp := range o.Specs {
		s = append(s, sp.Name)
	}
	return strings.Join(s, ",")
}

func TestRun_ChecksFormulaAndDependencies(t *testing.T) {
	fakeBrewAPI(t, map[string]string{
		"ripgrep": "https://github.com/BurntSushi/ripgrep/archive/refs/tags/15.2.0.tar.gz",
		"pcre2":   "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.47/pcre2-10.47.tar.bz2",
		"zlib":    "https://zlib.net/zlib.tar.gz",
	}, map[string][]string{"ripgrep": {"pcre2"}, "pcre2": {"zlib", "ripgrep"}}, "")
	c := stub(t, false)
	if err := Run(context.Background(), Options{Args: []string{"install", "ripgrep"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.checks) != 1 || specNames(c.checks[0]) != "BurntSushi/ripgrep,PCRE2Project/pcre2" {
		t.Fatalf("checks = %+v", c.checks)
	}
	for _, s := range c.checks[0].Specs {
		if s.Ecosystem != "github" || s.Version != sha {
			t.Errorf("spec = %+v", s)
		}
	}
	if len(c.handoffs) != 1 || c.handoffs[0][0] != "brew" {
		t.Errorf("handoffs = %v", c.handoffs)
	}
}

func TestRun_MaliciousBlocksBrew(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"jq": "https://github.com/jqlang/jq/releases/download/jq-1/jq.tar.gz"}, nil, "")
	c := stub(t, true)
	err := Run(context.Background(), Options{Args: []string{"install", "jq"}})
	if !errors.Is(err, forward.ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if len(c.execs)+len(c.handoffs) != 0 {
		t.Errorf("brew ran despite malware")
	}
}

func TestRun_PassThrough(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"node": "https://nodejs.org/dist/node.tar.xz"}, nil, "")
	c := stub(t, true)
	for _, args := range [][]string{{"list"}, {"install", "--cask", "firefox"}, {"install", "firefox"}, {"install", "node"}, {"upgrade"}} {
		if err := Run(context.Background(), Options{Args: args}); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if len(c.checks) != 0 || len(c.handoffs) != 5 {
		t.Errorf("checks=%d handoffs=%d", len(c.checks), len(c.handoffs))
	}
}

func TestRun_LookupErrorFailsOpenLoudly(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"jq": "https://github.com/jqlang/jq/archive/v1.tar.gz"}, nil, "jq")
	c := stub(t, true)
	if err := Run(context.Background(), Options{Args: []string{"install", "jq"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.checks) != 0 || len(c.handoffs) != 1 {
		t.Errorf("checks=%d handoffs=%d", len(c.checks), len(c.handoffs))
	}
	if !strings.Contains(errOut.(*bytes.Buffer).String(), "could not look up") {
		t.Errorf("fail-open was silent: %q", errOut)
	}
}

func TestRun_CheckErrorFailsOpen(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"jq": "https://github.com/jqlang/jq/archive/v1.tar.gz"}, nil, "")
	c := stub(t, false)
	checkFn = func(context.Context, check.Options) (*ossbom.SBOM, error) { return nil, errors.New("api down") }
	if err := Run(context.Background(), Options{Args: []string{"install", "jq"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.handoffs) != 1 {
		t.Error("brew not forwarded on API error")
	}
}

func TestRun_PassiveSubmitsAfterBrew(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"jq": "https://github.com/jqlang/jq/archive/v1.tar.gz"}, nil, "")
	c := stub(t, true)
	var order []string
	execFn = func(_ context.Context, bin string, args []string) error {
		order = append(order, "brew")
		return nil
	}
	inner := checkFn
	checkFn = func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		order = append(order, "submit")
		return inner(ctx, o)
	}
	if err := Run(context.Background(), Options{Args: []string{"install", "jq"}, Passive: true}); err != nil {
		t.Fatalf("passive must never block: %v", err)
	}
	if strings.Join(order, ",") != "brew,submit" || !c.checks[0].SubmitOnly {
		t.Errorf("order = %v", order)
	}
}

func TestRun_RepoDependenciesAreChecked(t *testing.T) {
	fakeBrewAPI(t, map[string]string{
		"ripgrep": "https://github.com/BurntSushi/ripgrep/archive/refs/tags/15.2.0.tar.gz",
		"jq":      "https://github.com/jqlang/jq/archive/v1.tar.gz",
	}, nil, "")
	c := stub(t, false)
	var asked []string
	var mu sync.Mutex
	repoSBOMFn = func(_ context.Context, _ Options, purl string) ([]ossbom.Component, error) {
		mu.Lock()
		asked = append(asked, purl)
		mu.Unlock()
		if strings.Contains(purl, "jq") {
			return nil, errors.New("timeout")
		}
		return []ossbom.Component{{Name: "regex", Version: "1.11.0", Type: "cargo"}}, nil
	}
	if err := Run(context.Background(), Options{Args: []string{"install", "ripgrep", "jq"}}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(asked)
	if want := "pkg:github/BurntSushi/ripgrep@" + sha + ",pkg:github/jqlang/jq@" + sha; strings.Join(asked, ",") != want {
		t.Errorf("asked %v", asked)
	}
	o := c.checks[0]
	if len(o.Specs) != 2 || len(o.Extra) != 1 || o.Extra[0].Name != "regex" {
		t.Errorf("specs=%v extra=%v", o.Specs, o.Extra)
	}
	if !strings.Contains(errOut.(*bytes.Buffer).String(), "1 of 2 repositories") {
		t.Errorf("failed expansion was silent: %q", errOut)
	}
}

func TestRun_MonitorPassiveSkipsExpansion(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"jq": "https://github.com/jqlang/jq/archive/v1.tar.gz"}, nil, "")
	stub(t, false)
	repoSBOMFn = func(context.Context, Options, string) ([]ossbom.Component, error) {
		t.Error("monitor id has no tools route; expansion must be skipped")
		return nil, nil
	}
	if err := Run(context.Background(), Options{Args: []string{"install", "jq"}, Passive: true, MonitorID: "ospi_x"}); err != nil {
		t.Fatal(err)
	}
}
