package gitscan

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/scan"
)

const sha = "0123456789abcdef0123456789abcdef01234567"

func TestParseGitHubURL(t *testing.T) {
	good := map[string]string{
		"https://github.com/pallets/click":          "pallets/click",
		"https://github.com/pallets/click.git":      "pallets/click",
		"https://github.com/pallets/click/":         "pallets/click",
		"git@github.com:pallets/click.git":          "pallets/click",
		"ssh://git@github.com/pallets/click.git":    "pallets/click",
		"https://user@github.com/pallets/click.git": "pallets/click",
	}
	for in, want := range good {
		r, ok := ParseGitHubURL(in)
		if !ok || r.String() != want {
			t.Errorf("ParseGitHubURL(%q) = %q, %v; want %q", in, r, ok, want)
		}
	}
	for _, in := range []string{
		"https://gitlab.com/a/b", "https://github.com/a", "https://github.com/a/b/c",
		"file:///tmp/x", "../local", "origin", "https://github.com/a/..", "https://github.com/a/b%2Fc",
	} {
		if r, ok := ParseGitHubURL(in); ok {
			t.Errorf("ParseGitHubURL(%q) = %q; want rejected", in, r)
		}
	}
}

func TestTarget(t *testing.T) {
	gitOutFn = func(dir string, args ...string) string {
		switch strings.Join(args, " ") {
		case "symbolic-ref --short -q HEAD":
			return "main"
		case "config branch.main.remote":
			return "upstream"
		case "config branch.main.merge":
			return "refs/heads/dev"
		case "remote get-url upstream", "remote get-url origin":
			return "git@github.com:o/r.git"
		}
		return ""
	}
	t.Cleanup(func() { gitOutFn = gitOutput })

	cases := []struct {
		args    []string
		want    string
		ref     string
		matched bool
	}{
		{[]string{"clone", "https://github.com/o/r"}, "o/r", "", true},
		{[]string{"clone", "--depth", "1", "-b", "v1", "https://github.com/o/r", "dest"}, "o/r", "v1", true},
		{[]string{"-c", "x=y", "clone", "--branch=v2", "https://github.com/o/r"}, "o/r", "v2", true},
		{[]string{"clone", "https://gitlab.com/o/r"}, "", "", false},
		{[]string{"pull"}, "o/r", "dev", true},
		{[]string{"-C", "sub", "pull", "--rebase", "origin", "+feature:local"}, "o/r", "feature", true},
		{[]string{"pull", "origin"}, "o/r", "", true},
		{[]string{"status"}, "", "", false},
		{[]string{"log", "clone"}, "", "", false},
		{[]string{"--version"}, "", "", false},
	}
	for _, c := range cases {
		r, ok := target(c.args)
		if ok != c.matched || (ok && (r.String() != c.want || r.Ref != c.ref)) {
			t.Errorf("target(%v) = %q@%q, %v; want %q@%q, %v", c.args, r, r.Ref, ok, c.want, c.ref, c.matched)
		}
	}
}

// fakeGitHub serves one public and one private repo.
func fakeGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("GitHub lookup must be unauthenticated")
		}
		switch r.URL.Path {
		case "/repos/o/pub":
			w.Write([]byte(`{"private":false,"default_branch":"main"}`))
		case "/repos/o/pub/commits/main":
			w.Write([]byte(sha))
		case "/repos/o/priv":
			w.Write([]byte(`{"private":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := githubAPIURL
	githubAPIURL = srv.URL + "/"
	t.Cleanup(func() { githubAPIURL = old })
}

type calls struct {
	execs    [][]string
	handoffs [][]string
	checks   []check.Options
}

func stub(t *testing.T, malicious bool) *calls {
	c := &calls{}
	oldExec, oldHandoff, oldCheck, oldErr, oldProg := execFn, handoffFn, checkFn, errOut, progressOut
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
		execFn, handoffFn, checkFn, errOut, progressOut = oldExec, oldHandoff, oldCheck, oldErr, oldProg
	})
	return c
}

func TestRun_PublicCloneIsCheckedThenForwarded(t *testing.T) {
	fakeGitHub(t)
	c := stub(t, false)
	if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(c.checks))
	}
	got := c.checks[0].Specs[0]
	if got.Ecosystem != "github" || got.Name != "o/pub" || got.Version != sha {
		t.Errorf("spec = %+v", got)
	}
	if len(c.handoffs) != 1 || c.handoffs[0][0] != "git" {
		t.Errorf("handoffs = %v, want git handed off once", c.handoffs)
	}
}

func TestRun_MaliciousRepoBlocksGit(t *testing.T) {
	fakeGitHub(t)
	c := stub(t, true)
	err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}})
	if !errors.Is(err, forward.ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if len(c.execs) != 0 || len(c.handoffs) != 0 {
		t.Errorf("git ran despite malware: execs=%v handoffs=%v", c.execs, c.handoffs)
	}
}

func TestRun_PrivateAndUnknownReposAreNotChecked(t *testing.T) {
	fakeGitHub(t)
	c := stub(t, true)
	for _, u := range []string{"https://github.com/o/priv", "https://github.com/o/missing", "https://gitlab.com/o/pub"} {
		if err := Run(context.Background(), Options{Args: []string{"clone", u}}); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	if len(c.checks) != 0 {
		t.Errorf("checked non-public repos: %v", c.checks)
	}
	if len(c.handoffs) != 3 {
		t.Errorf("handoffs = %d, want 3", len(c.handoffs))
	}
}

func TestRun_OtherVerbsPassThrough(t *testing.T) {
	c := stub(t, true)
	if err := Run(context.Background(), Options{Args: []string{"status"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.checks) != 0 || len(c.handoffs) != 1 {
		t.Errorf("checks=%d handoffs=%d", len(c.checks), len(c.handoffs))
	}
}

func TestRun_CheckErrorFailsOpen(t *testing.T) {
	fakeGitHub(t)
	c := stub(t, false)
	checkFn = func(context.Context, check.Options) (*ossbom.SBOM, error) { return nil, errors.New("api down") }
	if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.handoffs) != 1 {
		t.Errorf("git not forwarded on API error")
	}
}

func TestRun_PassiveSubmitsAfterGit(t *testing.T) {
	fakeGitHub(t)
	c := stub(t, true)
	var order []string
	execFn = func(_ context.Context, bin string, args []string) error {
		order = append(order, "git")
		c.execs = append(c.execs, append([]string{bin}, args...))
		return nil
	}
	inner := checkFn
	checkFn = func(ctx context.Context, o check.Options) (*ossbom.SBOM, error) {
		order = append(order, "submit")
		return inner(ctx, o)
	}
	if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}, Passive: true}); err != nil {
		t.Fatalf("passive must never block: %v", err)
	}
	if strings.Join(order, ",") != "git,submit" || len(c.execs) != 1 || len(c.handoffs) != 0 || !c.checks[0].SubmitOnly {
		t.Errorf("order = %v, submitOnly = %v", order, c.checks[0].SubmitOnly)
	}
}
