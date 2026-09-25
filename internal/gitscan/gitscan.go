// Package gitscan backs `ossprey git`: before a clone or pull of a public
// GitHub repository it checks the repository itself (not its dependencies)
// against the Ossprey API, blocks on malware, then execs the real git.
package gitscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ossprey/ossprey-cli/internal/alert"
	"github.com/ossprey/ossprey-cli/internal/ansi"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/progress"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/shim"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Test seams.
var (
	execFn                  = forward.Exec
	checkFn                 = check.Run
	gitOutFn                = gitOutput
	githubAPIURL            = "https://api.github.com/"
	HTTP                    = &http.Client{Timeout: 10 * time.Second}
	errOut        io.Writer = os.Stderr
	progressOut   io.Writer = os.Stderr
	errNotPublic            = errors.New("not a public repository")
	errNotFound             = errors.New("repository not found")
	ownerRepoPart           = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	shaPattern              = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Options configures a Run.
type Options struct {
	Args      []string
	APIURL    string
	APIKey    string
	SkipCI    bool
	Passive   bool
	MonitorID string
}

// Repo names one GitHub repository at a ref.
type Repo struct {
	Owner, Name string
	Ref         string // branch/tag/sha asked for; "" means the default branch
}

func (r Repo) String() string { return r.Owner + "/" + r.Name }

// Run checks the repository a clone/pull fetches, then execs the real git.
// Everything else (and any repo that is not public on GitHub) passes through.
// Returns forward.ErrBlocked on malware or *exec.ExitError from git.
func Run(ctx context.Context, opts Options) error {
	forwardTo := func() error {
		fmt.Fprint(errOut, warn.Drain(ctx))
		return execFn(ctx, "git", opts.Args)
	}

	repo, ok := target(opts.Args)
	if !ok {
		return forwardTo()
	}
	if opts.SkipCI {
		fmt.Fprintf(errOut, "ossprey: skip-ci set; forwarding `git %s` without checking\n", strings.Join(opts.Args, " "))
		return forwardTo()
	}

	ref, err := publicRef(ctx, repo)
	switch {
	case errors.Is(err, errNotPublic), errors.Is(err, errNotFound):
		// Private or unknown: we only scan public repositories.
		return forwardTo()
	case err != nil:
		// Fail open: a GitHub outage or rate limit must not break git.
		fmt.Fprintf(errOut, "ossprey: warning: could not look up %s on GitHub (%v); forwarding unchecked\n", repo, err)
		return forwardTo()
	}

	spec := check.Spec{Ecosystem: "github", Name: repo.String(), Version: ref}
	copts := check.Options{Specs: []check.Spec{spec}, APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID}

	if opts.Passive {
		execErr := forwardTo()
		copts.SubmitOnly = true
		stop := progress.Submit(progressOut, 1)
		_, err := checkFn(ctx, copts)
		stop()
		if err != nil {
			fmt.Fprintf(errOut, "ossprey: warning: could not post scan of %s (%v)\n", repo, err)
		} else {
			fmt.Fprintf(errOut, "ossprey: scan of %s posted to the Ossprey dashboard (passive)\n", repo)
		}
		return execErr
	}

	stop := progress.Scan(progressOut, 1)
	sbom, err := checkFn(ctx, copts)
	stop()
	if err != nil {
		// Fail open: an API outage or exhausted quota must not break git.
		fmt.Fprintf(errOut, "ossprey: warning: could not scan %s (%v); forwarding unchecked\n", repo, err)
		return forwardTo()
	}
	return report(ctx, opts, repo, sbom)
}

func report(ctx context.Context, opts Options, repo Repo, sbom *ossbom.SBOM) error {
	fmt.Fprint(errOut, warn.Drain(ctx))
	summary, hasMalware := scan.MalwareReports(sbom, severity.FailingFloor)
	for _, msg := range summary.Informational {
		fmt.Fprintln(errOut, "ossprey: "+msg)
	}
	if hasMalware {
		profile := ansi.Detect(errOut)
		fmt.Fprint(errOut, alert.Malware(summary.Alert(), "Git command blocked.", profile))
		for _, msg := range summary.Failing {
			fmt.Fprintln(errOut, profile.Red("Error: "+msg))
		}
		fmt.Fprintf(errOut, "ossprey: blocked `git %s`\n", strings.Join(opts.Args, " "))
		return forward.ErrBlocked
	}
	fmt.Fprintf(errOut, "ossprey: no malware found in %s, forwarding to git\n", repo)
	return execFn(ctx, "git", opts.Args)
}

// globalValueFlags are git options before the verb that take a separate value.
// Only list flags known to take one: a boolean listed here swallows the verb.
var globalValueFlags = flagSet("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix")

// Post-verb value flags. Same asymmetry as the forwarder: a boolean listed
// here swallows the URL/remote and skips the check.
var cloneValueFlags = flagSet("-o", "--origin", "-b", "--branch", "-u", "--upload-pack",
	"--reference", "--reference-if-able", "--separate-git-dir", "--depth", "--shallow-since",
	"--shallow-exclude", "-c", "--config", "--server-option", "--filter", "--template",
	"-j", "--jobs", "--bundle-uri", "--ref-format", "--revision")

var pullValueFlags = flagSet("-s", "--strategy", "-X", "--strategy-option", "--depth",
	"--shallow-since", "--shallow-exclude", "--deepen", "-o", "--server-option",
	"--upload-pack", "-j", "--jobs", "--negotiation-tip")

// target finds the GitHub repository a clone or pull will fetch.
func target(args []string) (Repo, bool) {
	dir, i := ".", 0
	for i < len(args) {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			break
		}
		if globalValueFlags[a] && i+1 < len(args) {
			if a == "-C" {
				dir = joinDir(dir, args[i+1])
			}
			i += 2
			continue
		}
		i++
	}
	if i >= len(args) {
		return Repo{}, false
	}
	verb, rest := args[i], args[i+1:]
	switch verb {
	case "clone":
		pos, flags := split(rest, cloneValueFlags)
		if len(pos) == 0 {
			return Repo{}, false
		}
		r, ok := ParseGitHubURL(pos[0])
		if !ok {
			return Repo{}, false
		}
		r.Ref = firstOf(flags, "-b", "--branch", "--revision")
		return r, true
	case "pull":
		pos, _ := split(rest, pullValueFlags)
		return pullTarget(dir, pos)
	}
	return Repo{}, false
}

// pullTarget resolves `git pull [<remote> [<refspec>]]` against the repo in dir.
func pullTarget(dir string, pos []string) (Repo, bool) {
	branch := gitOutFn(dir, "symbolic-ref", "--short", "-q", "HEAD")
	remote := ""
	if len(pos) > 0 {
		remote = pos[0]
	} else if branch != "" {
		remote = gitOutFn(dir, "config", "branch."+branch+".remote")
	}
	if remote == "" {
		remote = "origin"
	}
	u := remote
	if _, ok := ParseGitHubURL(remote); !ok {
		u = gitOutFn(dir, "remote", "get-url", remote)
	}
	r, ok := ParseGitHubURL(u)
	if !ok {
		return Repo{}, false
	}
	switch {
	case len(pos) > 1:
		r.Ref = refspecSource(pos[1])
	case len(pos) == 0 && branch != "":
		r.Ref = strings.TrimPrefix(gitOutFn(dir, "config", "branch."+branch+".merge"), "refs/heads/")
	}
	return r, true
}

// refspecSource returns the remote side of "+src:dst".
func refspecSource(s string) string {
	s = strings.TrimPrefix(s, "+")
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimPrefix(s, "refs/heads/")
}

// split separates positionals from flags, consuming values of valueFlags.
// Returns positionals and a flag->value map.
func split(args []string, valueFlags map[string]bool) ([]string, map[string]string) {
	var pos []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		if k, v, ok := strings.Cut(a, "="); ok {
			flags[k] = v
			continue
		}
		if valueFlags[a] && i+1 < len(args) {
			flags[a] = args[i+1]
			i++
			continue
		}
		flags[a] = ""
	}
	return pos, flags
}

func firstOf(flags map[string]string, names ...string) string {
	for _, n := range names {
		if v := flags[n]; v != "" {
			return v
		}
	}
	return ""
}

// ParseGitHubURL recognises https, ssh and scp-style github.com URLs.
func ParseGitHubURL(raw string) (Repo, bool) {
	var path string
	switch {
	case strings.HasPrefix(raw, "git@github.com:"):
		path = strings.TrimPrefix(raw, "git@github.com:")
	case strings.Contains(raw, "://"):
		u, err := url.Parse(raw)
		if err != nil || !strings.EqualFold(u.Hostname(), "github.com") {
			return Repo{}, false
		}
		switch u.Scheme {
		case "https", "http", "ssh", "git":
		default:
			return Repo{}, false
		}
		path = u.Path
	default:
		return Repo{}, false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 {
		return Repo{}, false
	}
	owner, name := parts[0], strings.TrimSuffix(parts[1], ".git")
	if !ownerRepoPart.MatchString(owner) || !ownerRepoPart.MatchString(name) || name == "." || name == ".." {
		return Repo{}, false
	}
	return Repo{Owner: owner, Name: name}, true
}

// publicRef confirms the repository is public and resolves the ref to a commit
// sha. Unauthenticated on purpose: a 200 without a token means public.
func publicRef(ctx context.Context, r Repo) (string, error) {
	var meta struct {
		Private       bool   `json:"private"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := getJSON(ctx, "repos/"+r.Owner+"/"+r.Name, &meta); err != nil {
		return "", err
	}
	if meta.Private {
		return "", errNotPublic
	}
	ref := r.Ref
	if ref == "" {
		ref = meta.DefaultBranch
	}
	if ref == "" {
		ref = "HEAD"
	}
	// Best effort: fall back to the ref name if the sha can't be resolved.
	if sha, err := commitSHA(ctx, r, ref); err == nil {
		return sha, nil
	}
	return ref, nil
}

func commitSHA(ctx context.Context, r Repo, ref string) (string, error) {
	body, err := get(ctx, "repos/"+r.Owner+"/"+r.Name+"/commits/"+url.PathEscape(ref), "application/vnd.github.sha")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(string(body))
	if !shaPattern.MatchString(sha) {
		return "", fmt.Errorf("unexpected sha %q", sha)
	}
	return sha, nil
}

func getJSON(ctx context.Context, path string, v any) error {
	body, err := get(ctx, path, "application/vnd.github+json")
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func get(ctx context.Context, path, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub API %s", resp.Status)
	}
	return body, nil
}

// gitOutput runs the real git (never a shim) and returns trimmed stdout, or "".
func gitOutput(dir string, args ...string) string {
	path, err := shim.LookPathReal("git")
	if err != nil {
		return ""
	}
	cmd := exec.Command(path, append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), shim.BypassEnv+"=1")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func joinDir(base, d string) string {
	if filepath.IsAbs(d) {
		return d
	}
	return filepath.Join(base, d)
}

func flagSet(flags ...string) map[string]bool {
	m := make(map[string]bool, len(flags))
	for _, f := range flags {
		m[f] = true
	}
	return m
}
