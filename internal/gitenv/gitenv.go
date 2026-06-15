// Package gitenv detects the GitHub coordinates (owner/org, repo, branch) of a
// scanned project so the Ossprey dashboard can title scans "org/repo@branch"
// and link back to the source. Without these the dashboard can only show the
// repo name (or a hash of the scan id) and the user can't navigate to the repo.
//
// It mirrors the python client's ossprey/environment.py: CI environment
// variables take precedence (GitHub Actions / Codespaces set GITHUB_REPOSITORY
// to "owner/repo"), with a local `git remote` fallback so developer-machine
// scans are attributed too.
package gitenv

import (
	"os"
	"os/exec"
	"strings"
)

// GitHub holds the coordinates of a scanned project's GitHub origin. All fields
// are empty when no GitHub origin can be determined.
type GitHub struct {
	Org        string // repo owner (org or user)
	Repo       string // repo name
	Branch     string // current branch (empty when detached or unknown)
	ProductEnv string // CI context: CODESPACE, GITHUB_ACTIONS, or "" for local
}

// OK reports whether both the owner and repo were resolved — the minimum the
// dashboard needs to title the scan and link to the source.
func (g GitHub) OK() bool { return g.Org != "" && g.Repo != "" }

// Detect resolves the GitHub coordinates for the checkout at path. CI env vars
// win; otherwise the git `origin` remote is parsed. Returns a zero GitHub when
// the project has no resolvable GitHub origin.
func Detect(path string) GitHub {
	if gh, ok := detectFromEnv(); ok {
		if gh.Branch == "" {
			gh.Branch = gitBranch(path)
		}
		return gh
	}
	if org, repo, ok := ParseRemoteURL(gitRemoteURL(path)); ok {
		return GitHub{Org: org, Repo: repo, Branch: gitBranch(path)}
	}
	return GitHub{}
}

// detectFromEnv reads GitHub coordinates from CI environment variables, matching
// the python client. ok is false when GITHUB_REPOSITORY is missing or malformed.
func detectFromEnv() (GitHub, bool) {
	repo := os.Getenv("GITHUB_REPOSITORY") // "owner/repo"
	org, name, ok := strings.Cut(repo, "/")
	if !ok || org == "" || name == "" {
		return GitHub{}, false
	}
	gh := GitHub{
		Org:    org,
		Repo:   strings.TrimSuffix(name, ".git"),
		Branch: os.Getenv("GITHUB_REF_NAME"),
	}
	switch {
	case os.Getenv("CODESPACES") != "":
		gh.ProductEnv = "CODESPACE"
	case os.Getenv("GITHUB_ACTIONS") != "":
		gh.ProductEnv = "GITHUB_ACTIONS"
	}
	return gh, true
}

// ParseRemoteURL extracts the owner and repo from a GitHub remote URL in either
// https ("https://github.com/owner/repo.git") or ssh
// ("git@github.com:owner/repo.git", "ssh://git@github.com/owner/repo") form.
// ok is false when url is empty or not a github.com URL.
func ParseRemoteURL(url string) (org, repo string, ok bool) {
	url = strings.TrimSpace(url)
	if url == "" {
		return "", "", false
	}

	// Reduce every supported form to the "owner/repo" path after the host.
	var path string
	switch {
	case strings.HasPrefix(url, "git@"):
		// scp-like syntax: git@github.com:owner/repo.git
		host, p, found := strings.Cut(url, ":")
		if !found || !strings.Contains(host, "github.com") {
			return "", "", false
		}
		path = p
	default:
		// strip scheme (https://, ssh://, git://) if present
		if _, after, found := strings.Cut(url, "://"); found {
			url = after
		}
		// strip any user@ prefix (e.g. ssh://git@github.com/...)
		if _, after, found := strings.Cut(url, "@"); found {
			url = after
		}
		host, p, found := strings.Cut(url, "/")
		if !found || !strings.Contains(host, "github.com") {
			return "", "", false
		}
		path = p
	}

	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	owner, name, found := strings.Cut(path, "/")
	if !found || owner == "" || name == "" {
		return "", "", false
	}
	// name may itself contain extra path segments for non-repo URLs; keep only
	// the first segment (the repo).
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[:i]
	}
	return owner, name, true
}

// gitRemoteURL returns the `origin` remote URL for the checkout at path, or ""
// when git is unavailable or path is not a repo.
func gitRemoteURL(path string) string {
	return runGit(path, "remote", "get-url", "origin")
}

// gitBranch returns the current branch name, or "" when detached or unknown.
func gitBranch(path string) string {
	b := runGit(path, "rev-parse", "--abbrev-ref", "HEAD")
	if b == "HEAD" { // detached HEAD
		return ""
	}
	return b
}

// runGit runs `git -C path <args...>` and returns trimmed stdout, or "" on any
// error (missing binary, not a repo, no origin, …) — git context is best-effort.
func runGit(path string, args ...string) string {
	if _, err := exec.LookPath("git"); err != nil {
		return ""
	}
	out, err := exec.Command("git", append([]string{"-C", path}, args...)...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
