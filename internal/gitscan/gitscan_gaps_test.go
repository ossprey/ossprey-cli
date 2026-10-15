package gitscan

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/shim"
)

// githubServing points the lookup at handler and records every request path.
func githubServing(t *testing.T, handler http.HandlerFunc) *[]string {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	old := githubAPIURL
	githubAPIURL = srv.URL + "/"
	t.Cleanup(func() { githubAPIURL = old })
	return &paths
}

// Any GitHub failure that is not a clean 404 / private answer fails open -- git
// runs, nothing is checked -- and says so even when quiet.
func TestRun_GitHubFailuresFailOpenWithAWarning(t *testing.T) {
	t.Setenv("OSSPREY_VERBOSE", "")
	cases := map[string]http.HandlerFunc{
		"rate limited": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
		},
		"server error": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		},
		"malformed json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{not json`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			githubServing(t, h)
			c := stub(t, true)
			if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}}); err != nil {
				t.Fatalf("Run = %v, want git forwarded", err)
			}
			if len(c.checks) != 0 || len(c.execs) != 1 {
				t.Fatalf("checks=%d execs=%d, want 0 and 1", len(c.checks), len(c.execs))
			}
			if !strings.Contains(errOut.(*bytes.Buffer).String(), "could not look up o/pub") {
				t.Fatalf("fail-open was silent: %q", errOut.(*bytes.Buffer).String())
			}
		})
	}
}

func TestRun_GitHubUnreachableFailsOpen(t *testing.T) {
	t.Setenv("OSSPREY_VERBOSE", "")
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/"
	srv.Close()
	old := githubAPIURL
	githubAPIURL = url
	t.Cleanup(func() { githubAPIURL = old })

	c := stub(t, true)
	if err := Run(context.Background(), Options{Args: []string{"clone", "git@github.com:o/pub.git"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.checks) != 0 || len(c.execs) != 1 {
		t.Fatalf("checks=%d execs=%d", len(c.checks), len(c.execs))
	}
	if !strings.Contains(errOut.(*bytes.Buffer).String(), "warning") {
		t.Fatal("network failure was silent")
	}
}

// The lookup never carries a credential, even when one is in the environment:
// a token would make a private repo look checkable.
func TestRun_LookupIgnoresGitHubTokensInEnv(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_secret")
	t.Setenv("GH_TOKEN", "ghp_secret")
	var sawAuth bool
	githubServing(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || strings.Contains(r.URL.String(), "ghp_") {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/repos/o/pub":
			w.Write([]byte(`{"private":false,"default_branch":"main"}`))
		default:
			w.Write([]byte(sha))
		}
	})
	stub(t, false)
	if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}}); err != nil {
		t.Fatal(err)
	}
	if sawAuth {
		t.Fatal("GitHub lookup sent a credential")
	}
}

// The ref asked for is what is resolved and checked; an unresolvable sha falls
// back to the ref name rather than skipping the check.
func TestRun_RefResolution(t *testing.T) {
	paths := githubServing(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/pub":
			w.Write([]byte(`{"private":false,"default_branch":"main"}`))
		case "/repos/o/pub/commits/v1.2":
			w.Write([]byte(sha + "\n"))
		case "/repos/o/pub/commits/weird":
			w.Write([]byte("not-a-sha"))
		default:
			http.NotFound(w, r)
		}
	})
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"clone", "-b", "v1.2", "https://github.com/o/pub"}, sha},
		{[]string{"clone", "--branch", "weird", "https://github.com/o/pub"}, "weird"},
		{[]string{"clone", "--revision=gone", "https://github.com/o/pub"}, "gone"},
	}
	for _, tc := range cases {
		c := stub(t, false)
		if err := Run(context.Background(), Options{Args: tc.args}); err != nil {
			t.Fatal(err)
		}
		if len(c.checks) != 1 || c.checks[0].Specs[0].Version != tc.want {
			t.Errorf("%v: checked %+v, want version %q", tc.args, c.checks, tc.want)
		}
	}
	if !contains(*paths, "/repos/o/pub/commits/v1.2") {
		t.Errorf("the asked-for ref was not resolved: %v", *paths)
	}
}

// --skip-ci forwards without even asking GitHub.
func TestRun_SkipCIMakesNoLookup(t *testing.T) {
	paths := githubServing(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	c := stub(t, true)
	if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}, SkipCI: true}); err != nil {
		t.Fatal(err)
	}
	if len(*paths) != 0 || len(c.checks) != 0 || len(c.execs) != 1 {
		t.Fatalf("lookups=%v checks=%d execs=%d", *paths, len(c.checks), len(c.execs))
	}
}

// A clean check prints nothing of ossprey's by default.
func TestRun_CleanCheckIsSilent(t *testing.T) {
	t.Setenv("OSSPREY_VERBOSE", "")
	fakeGitHub(t)
	stub(t, false)
	if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}}); err != nil {
		t.Fatal(err)
	}
	if s := errOut.(*bytes.Buffer).String(); s != "" {
		t.Fatalf("quiet clean run printed %q", s)
	}
}

// git's own exit status reaches the caller unchanged.
func TestRun_GitErrorIsReturned(t *testing.T) {
	fakeGitHub(t)
	stub(t, false)
	gitErr := errors.New("exit status 128")
	execFn = func(context.Context, string, []string) error { return gitErr }
	if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}}); !errors.Is(err, gitErr) {
		t.Fatalf("Run = %v, want git's error", err)
	}
}

// Passive never blocks: a failed GitHub lookup forwards without submitting, a
// failed submission warns and still returns git's result.
func TestRun_PassiveFailuresNeverBlock(t *testing.T) {
	t.Run("lookup fails", func(t *testing.T) {
		githubServing(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusBadGateway) })
		c := stub(t, true)
		if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}, Passive: true}); err != nil {
			t.Fatal(err)
		}
		if len(c.checks) != 0 || len(c.execs) != 1 {
			t.Fatalf("checks=%d execs=%d", len(c.checks), len(c.execs))
		}
	})
	t.Run("submit fails", func(t *testing.T) {
		fakeGitHub(t)
		c := stub(t, true)
		checkFn = func(context.Context, check.Options) (*ossbom.SBOM, error) { return nil, errors.New("api down") }
		if err := Run(context.Background(), Options{Args: []string{"clone", "https://github.com/o/pub"}, Passive: true}); err != nil {
			t.Fatal(err)
		}
		if len(c.execs) != 1 || !strings.Contains(errOut.(*bytes.Buffer).String(), "could not post scan") {
			t.Fatalf("execs=%d out=%q", len(c.execs), errOut.(*bytes.Buffer).String())
		}
	})
}

// Value-flag tables: a value-taking flag must consume its value (or the value
// reads as the URL), and a boolean must not (or it swallows the URL and the
// check is skipped).
func TestTarget_CloneFlags(t *testing.T) {
	const u = "https://github.com/o/r"
	cases := []struct {
		args []string
		ref  string
	}{
		{[]string{"clone", "-o", "upstream", u}, ""},
		{[]string{"clone", "--origin", "upstream", u}, ""},
		{[]string{"clone", "--template", "/tmp/t", u}, ""},
		{[]string{"clone", "-c", "core.autocrlf=false", u}, ""},
		{[]string{"clone", "--config", "a=b", u}, ""},
		{[]string{"clone", "--depth", "1", u}, ""},
		{[]string{"clone", "--reference", "/srv/cache", u}, ""},
		{[]string{"clone", "--filter", "blob:none", u}, ""},
		{[]string{"clone", "-j", "4", u}, ""},
		{[]string{"clone", "-u", "/usr/bin/git-upload-pack", u}, ""},
		{[]string{"clone", "--separate-git-dir", "/tmp/g", u}, ""},
		{[]string{"clone", "--shallow-since", "2020-01-01", u}, ""},
		{[]string{"clone", "-q", "--bare", "--mirror", "--recursive", "--recurse-submodules", "-n", "--no-checkout",
			"--single-branch", "--no-tags", "-l", "-s", "--progress", "--sparse", u, "dest"}, ""},
		{[]string{"clone", "--", u}, ""},
		{[]string{"clone", "--depth=1", "-b", "dev", u, "dest"}, "dev"},
		{[]string{"--git-dir", "/x", "--work-tree", "/y", "--no-pager", "-P", "--bare", "clone", u}, ""},
		{[]string{"--config-env", "a=B", "--namespace", "ns", "clone", u}, ""},
	}
	for _, tc := range cases {
		r, ok := target(tc.args)
		if !ok || r.String() != "o/r" || r.Ref != tc.ref {
			t.Errorf("target(%v) = %q@%q, %v; want o/r@%q", tc.args, r, r.Ref, ok, tc.ref)
		}
	}
}

func TestTarget_PullFlags(t *testing.T) {
	var asked [][]string
	gitOutFn = func(dir string, args ...string) string {
		asked = append(asked, append([]string{dir}, args...))
		switch strings.Join(args, " ") {
		case "symbolic-ref --short -q HEAD":
			return "main"
		case "remote get-url upstream":
			return "https://github.com/o/r.git"
		}
		return ""
	}
	t.Cleanup(func() { gitOutFn = gitOutput })

	cases := []struct {
		args []string
		ref  string
	}{
		{[]string{"pull", "-s", "ours", "upstream", "main"}, "main"},
		{[]string{"pull", "--strategy", "ours", "upstream", "refs/heads/dev"}, "dev"},
		{[]string{"pull", "-X", "theirs", "upstream", "x"}, "x"},
		{[]string{"pull", "--depth", "1", "upstream", "y"}, "y"},
		{[]string{"pull", "-o", "opt", "upstream", "z"}, "z"},
		{[]string{"pull", "--rebase", "--ff-only", "-q", "-v", "--no-edit", "--autostash", "--all", "upstream", "w"}, "w"},
		{[]string{"pull", "https://github.com/o/r", "v"}, "v"},
	}
	for _, tc := range cases {
		r, ok := target(tc.args)
		if !ok || r.String() != "o/r" || r.Ref != tc.ref {
			t.Errorf("target(%v) = %q@%q, %v; want o/r@%q", tc.args, r, r.Ref, ok, tc.ref)
		}
	}

	// A URL remote is used directly, without asking git for it.
	asked = nil
	target([]string{"pull", "git@github.com:o/r.git"})
	for _, a := range asked {
		if strings.Contains(strings.Join(a, " "), "get-url") {
			t.Errorf("a URL remote was looked up via git: %v", a)
		}
	}
}

// A pull whose remote is not on GitHub, or a detached HEAD with no origin,
// is not checked.
func TestTarget_PullNotGitHub(t *testing.T) {
	gitOutFn = func(dir string, args ...string) string {
		if strings.Join(args, " ") == "remote get-url origin" {
			return "https://gitlab.com/o/r.git"
		}
		return ""
	}
	t.Cleanup(func() { gitOutFn = gitOutput })
	for _, args := range [][]string{{"pull"}, {"pull", "origin", "main"}, {"pull", "https://example.com/o/r"}} {
		if r, ok := target(args); ok {
			t.Errorf("target(%v) = %q; want not checked", args, r)
		}
	}
}

// -C stacks like git's: relative values join, an absolute one replaces.
func TestTarget_PullHonoursDashC(t *testing.T) {
	var dirs []string
	gitOutFn = func(dir string, args ...string) string {
		dirs = append(dirs, dir)
		if strings.Join(args, " ") == "remote get-url origin" {
			return "https://github.com/o/r"
		}
		return ""
	}
	t.Cleanup(func() { gitOutFn = gitOutput })

	abs := filepath.Join(t.TempDir(), "repo")
	cases := map[string][]string{
		filepath.Join("a", "b"): {"-C", "a", "-C", "b", "pull"},
		abs:                     {"-C", "a", "-C", abs, "pull"},
	}
	for want, args := range cases {
		dirs = nil
		if _, ok := target(args); !ok {
			t.Fatalf("target(%v) not matched", args)
		}
		for _, d := range dirs {
			if d != want {
				t.Errorf("target(%v) ran git in %q, want %q", args, d, want)
			}
		}
	}
}

func TestParseGitHubURL_MoreForms(t *testing.T) {
	good := map[string]string{
		"http://github.com/o/r":                   "o/r",
		"git://github.com/o/r.git":                "o/r",
		"https://GitHub.com/o/r":                  "o/r",
		"https://github.com:443/o/r.git":          "o/r",
		"ssh://git@github.com:22/o/r.git":         "o/r",
		"git@github.com:o/r":                      "o/r",
		"git@github.com:o/r/":                     "o/r",
		"https://github.com/o/r.git/":             "o/r",
		"https://github.com/o.dots/r_under-score": "o.dots/r_under-score",
	}
	for in, want := range good {
		if r, ok := ParseGitHubURL(in); !ok || r.String() != want {
			t.Errorf("ParseGitHubURL(%q) = %q, %v; want %q", in, r, ok, want)
		}
	}
	bad := []string{
		"https://github.example.com/o/r",      // enterprise host: not github.com
		"git@github.example.com:o/r.git",      // enterprise scp
		"https://github.com.evil.example/o/r", // lookalike host
		"https://evil.example/github.com/o/r",
		"ftp://github.com/o/r",
		"file://github.com/o/r",
		"https://github.com/o/r/tree/main",
		"https://github.com//r",
		"git@github.com:o",
		"https://github.com/o/r%20x",
	}
	for _, in := range bad {
		if r, ok := ParseGitHubURL(in); ok {
			t.Errorf("ParseGitHubURL(%q) = %q; want rejected", in, r)
		}
	}
}

// gitOutput must run the real git -- never a shim -- and mark the call as a
// bypass, or a git shim would re-enter ossprey on every pull.
func TestGitOutputUsesTheRealGitWithBypass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake git")
	}
	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	for _, d := range []string{shimDir, realDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	shimGit := filepath.Join(shimDir, "git")
	if err := os.WriteFile(shimGit, []byte(shim.Script(shim.ScriptOptions{Manager: "git", Dir: shimDir, Binary: "/nonexistent"})), 0o755); err != nil {
		t.Fatal(err)
	}
	realGit := filepath.Join(realDir, "git")
	if err := os.WriteFile(realGit, []byte("#!/bin/sh\necho \"real bypass=$"+shim.BypassEnv+" args=$*\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+":"+realDir)
	t.Setenv(shim.BypassEnv, "")

	got := gitOutput("some/dir", "config", "branch.main.remote")
	if want := "real bypass=1 args=-C some/dir config branch.main.remote"; got != want {
		t.Fatalf("gitOutput = %q, want %q", got, want)
	}

	// Only a shim on PATH: no git to ask, so the pull resolves nothing.
	t.Setenv("PATH", shimDir)
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	if p, err := shim.LookPathReal("git"); err == nil {
		t.Fatalf("LookPathReal returned the shim %q", p)
	}
	if got := gitOutput(".", "x"); got != "" {
		t.Fatalf("gitOutput ran the shim: %q", got)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
