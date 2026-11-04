package brewscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
		req, ok := targets(c.args)
		if strings.Join(req.names, ",") != c.want || req.head != c.head || ok != c.isOK {
			t.Errorf("targets(%v) = %+v, %v; want %q, %v, %v", c.args, req, ok, c.want, c.head, c.isOK)
		}
	}
	req, _ := targets([]string{"install", "--only-dependencies", "--ignore-dependencies", "jq"})
	if !req.onlyDeps || !req.ignoreDeps {
		t.Errorf("dependency modes not read: %+v", req)
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
		"https://codeload.github.com/o/r/zip/refs/tags/v9":                          "o/r@v9",
		"https://github.com/o/r/releases/download/release%2F1.0/src.tar.gz":         "o/r@release/1.0",
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
	if got := pickSHA(out, refCandidates("v1", kindUnknown)); got != sha {
		t.Errorf("peeled tag not preferred: %s", got)
	}
	if got := pickSHA(other+"\trefs/heads/main\n", refCandidates("main", kindUnknown)); got != other {
		t.Errorf("branch: %s", got)
	}
	if got := pickSHA("", refCandidates("v1", kindTag)); got != "" {
		t.Errorf("empty: %s", got)
	}
	// A tag and a branch sharing a name: the source's namespace decides.
	both := other + "\trefs/tags/x\n" + sha + "\trefs/heads/x\n"
	if got := pickSHA(both, refCandidates("x", kindBranch)); got != sha {
		t.Errorf("branch source picked the tag: %s", got)
	}
	if got := pickSHA(both, refCandidates("x", kindTag)); got != other {
		t.Errorf("tag source picked the branch: %s", got)
	}
	s, _ := parseArchiveURL("https://github.com/o/r/archive/refs/heads/x.tar.gz")
	if s.kind != kindBranch {
		t.Errorf("refs/heads archive kind = %q", s.kind)
	}
}

func TestRuntimeDeps(t *testing.T) {
	var f formula
	if err := json.Unmarshal([]byte(`{
		"dependencies": ["a"],
		"uses_from_macos": ["expat", {"perl": ["build", "test"]}, "zlib"],
		"uses_from_macos_bounds": [{}, {}, {"since": "sequoia"}],
		"head_dependencies": {"dependencies": ["h"]},
		"variations": {"x86_64_linux": {"dependencies": ["curl"]}, "arm64_sonoma": {"dependencies": ["mac"]}}
	}`), &f); err != nil {
		t.Fatal(err)
	}
	old := goos
	t.Cleanup(func() { goos = old })
	for _, c := range []struct {
		os   string
		head bool
		want string
	}{
		{"linux", false, "a,curl,expat,zlib"},
		{"darwin", false, "a,mac,zlib"},
		{"darwin", true, "h,mac"},
	} {
		goos = c.os
		got := f.runtimeDeps(c.head)
		sort.Strings(got)
		if strings.Join(got, ",") != c.want {
			t.Errorf("%s head=%v: %v, want %s", c.os, c.head, got, c.want)
		}
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
	lsRemoteFn = func(gitscan.Repo, string, string) string { return sha }
	t.Cleanup(func() { formulaAPIURL, lsRemoteFn = old, oldLs })
}

type calls struct {
	execs, handoffs [][]string
	checks          []check.Options
}

func stub(t *testing.T, malicious bool) *calls {
	c := &calls{}
	oldExec, oldHandoff, oldCheck, oldErr, oldProg, oldRepo, oldAlias := execFn, handoffFn, checkFn, errOut, progressOut, newRepoSBOMer, aliasFn
	setRepoSBOM(func(string) ([]ossbom.Component, error) { return nil, nil })
	aliasFn = func(context.Context, string) string { return "" }
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
		execFn, handoffFn, checkFn, errOut, progressOut, newRepoSBOMer, aliasFn = oldExec, oldHandoff, oldCheck, oldErr, oldProg, oldRepo, oldAlias
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
	setRepoSBOM(func(purl string) ([]ossbom.Component, error) {
		mu.Lock()
		asked = append(asked, purl)
		mu.Unlock()
		if strings.Contains(purl, "jq") {
			return nil, errors.New("timeout")
		}
		return []ossbom.Component{{Name: "regex", Version: "1.11.0", Type: "cargo"}}, nil
	})
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
	setRepoSBOM(func(string) ([]ossbom.Component, error) {
		t.Error("monitor id has no tools route; expansion must be skipped")
		return nil, nil
	})
	if err := Run(context.Background(), Options{Args: []string{"install", "jq"}, Passive: true, MonitorID: "ospi_x"}); err != nil {
		t.Fatal(err)
	}
}

// fakeSBOMer serves RepoSBOM from a function.
type fakeSBOMer func(purl string) ([]ossbom.Component, error)

func (f fakeSBOMer) RepoSBOM(_ context.Context, purl string) ([]ossbom.Component, error) {
	return f(purl)
}

func setRepoSBOM(f func(string) ([]ossbom.Component, error)) {
	newRepoSBOMer = func(context.Context, Options) (repoSBOMer, error) { return fakeSBOMer(f), nil }
}

func TestRun_DependencyModes(t *testing.T) {
	fakeBrewAPI(t, map[string]string{
		"rg":  "https://github.com/o/rg/archive/v1.tar.gz",
		"dep": "https://github.com/o/dep/archive/v1.tar.gz",
	}, map[string][]string{"rg": {"dep"}}, "")
	c := stub(t, false)
	for args, want := range map[string]string{
		"install --only-dependencies rg":   "o/dep",
		"install --ignore-dependencies rg": "o/rg",
	} {
		c.checks = nil
		if err := Run(context.Background(), Options{Args: strings.Fields(args)}); err != nil {
			t.Fatal(err)
		}
		if got := specNames(c.checks[0]); got != want {
			t.Errorf("%s checked %s, want %s", args, got, want)
		}
	}
}

func TestRun_CapWarnsWhenAnyFormulaIsLeftOut(t *testing.T) {
	formulae := map[string]string{"root": "https://github.com/o/root/archive/v1.tar.gz"}
	var leaves []string
	for i := 0; i < maxFormulae; i++ {
		n := fmt.Sprintf("leaf%d", i)
		formulae[n] = "https://example.com/" + n + ".tar.gz"
		leaves = append(leaves, n)
	}
	fakeBrewAPI(t, formulae, map[string][]string{"root": leaves}, "")
	stub(t, false)
	if err := Run(context.Background(), Options{Args: []string{"install", "root"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.(*bytes.Buffer).String(), "exceeds") {
		t.Error("root plus 300 leaves left one out without a warning")
	}
}

func TestRun_AliasResolvesThroughBrew(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"python@3.14": "https://github.com/python/cpython/archive/v3.14.0.tar.gz"}, nil, "")
	c := stub(t, false)
	aliasFn = func(_ context.Context, n string) string {
		if n == "python" {
			return "python@3.14"
		}
		return ""
	}
	if err := Run(context.Background(), Options{Args: []string{"install", "python"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.checks) != 1 || specNames(c.checks[0]) != "python/cpython" {
		t.Errorf("alias not followed: %+v", c.checks)
	}
}

func TestExpandSharesOneClient(t *testing.T) {
	stub(t, false)
	made := 0
	newRepoSBOMer = func(context.Context, Options) (repoSBOMer, error) {
		made++
		return fakeSBOMer(func(string) ([]ossbom.Component, error) { return nil, nil }), nil
	}
	specs := []check.Spec{{Name: "a/b", Version: "1"}, {Name: "c/d", Version: "1"}, {Name: "e/f", Version: "1"}}
	expand(context.Background(), Options{}, specs)
	if made != 1 {
		t.Errorf("clients made = %d, want 1 (concurrent token refresh)", made)
	}
}

func TestRun_PassiveRunsBrewBeforeAnyLookup(t *testing.T) {
	fakeBrewAPI(t, map[string]string{"jq": "https://github.com/jqlang/jq/archive/v1.tar.gz"}, nil, "")
	stub(t, false)
	var order []string
	execFn = func(context.Context, string, []string) error {
		order = append(order, "brew")
		return nil
	}
	lsRemoteFn = func(gitscan.Repo, string, string) string {
		order = append(order, "lookup")
		return sha
	}
	if err := Run(context.Background(), Options{Args: []string{"install", "jq"}, Passive: true}); err != nil {
		t.Fatal(err)
	}
	if len(order) == 0 || order[0] != "brew" {
		t.Errorf("order = %v, want brew first", order)
	}
}
