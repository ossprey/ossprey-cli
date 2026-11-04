// Package brewscan backs `ossprey brew`: before a formula install it maps each
// formula, and its runtime dependencies, to the GitHub repository its source
// is fetched from, checks those repositories against the Ossprey API, blocks on
// malware, then execs the real brew.
package brewscan

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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ossprey/ossprey-cli/internal/alert"
	"github.com/ossprey/ossprey-cli/internal/ansi"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/env"
	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/gitscan"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/progress"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/shim"
	"github.com/ossprey/ossprey-cli/internal/submit"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Test seams.
var (
	execFn                  = forward.Exec
	handoffFn               = forward.Handoff
	checkFn                 = check.Run
	lsRemoteFn              = lsRemote
	repoSBOMFn              = repoSBOM
	formulaAPIURL           = "https://formulae.brew.sh/api/formula/"
	HTTP                    = &http.Client{Timeout: 10 * time.Second}
	errOut        io.Writer = os.Stderr
	progressOut   io.Writer = os.Stderr
	errNotFound             = errors.New("formula not found")
	formulaName             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.@-]*$`)
	shaPattern              = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// maxFormulae caps the dependency walk; a tree this big is checked partially.
const (
	maxFormulae = 300
	workers     = 8
	// repoSBOMBudget caps the whole dependency expansion; each server-side
	// call can take up to 30s (the API's ceiling).
	repoSBOMBudget = 60 * time.Second
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

// installVerbs install formulae from source or a bottle built from it.
var installVerbs = map[string]bool{"install": true, "reinstall": true, "upgrade": true}

func note(format string, a ...any) {
	if env.Verbose() {
		fmt.Fprintf(errOut, format, a...)
	}
}

func flushWarnings(ctx context.Context) {
	if s := warn.Drain(ctx); env.Verbose() {
		fmt.Fprint(errOut, s)
	}
}

func progressTo() io.Writer {
	if env.Verbose() {
		return progressOut
	}
	return progress.Transient(progressOut)
}

// Run checks the formulae an install fetches, then execs the real brew.
// Returns forward.ErrBlocked on malware or *exec.ExitError from brew.
func Run(ctx context.Context, opts Options) error {
	forwardTo := func() error {
		flushWarnings(ctx)
		return handoffFn(ctx, "brew", opts.Args)
	}

	names, head, ok := targets(opts.Args)
	if !ok || len(names) == 0 {
		return forwardTo()
	}
	if opts.SkipCI {
		note("ossprey: skip-ci set; forwarding `brew %s` without checking\n", strings.Join(opts.Args, " "))
		return forwardTo()
	}

	specs, err := resolve(ctx, names, head)
	if err != nil {
		// Fail open: a Homebrew API outage must not break brew.
		fmt.Fprintf(errOut, "ossprey: warning: could not look up formulae (%v); checking what resolved\n", err)
	}
	if len(specs) == 0 {
		note("ossprey: no formula sources on GitHub; forwarding unchecked\n")
		return forwardTo()
	}

	copts := check.Options{Specs: specs, APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID}
	if opts.Passive {
		flushWarnings(ctx)
		execErr := execFn(ctx, "brew", opts.Args)
		if opts.MonitorID == "" {
			copts.Extra = expand(ctx, opts, specs)
		}
		copts.SubmitOnly = true
		stop := progress.Submit(progressTo(), len(specs))
		_, err := checkFn(ctx, copts)
		stop()
		if err != nil {
			fmt.Fprintf(errOut, "ossprey: warning: could not post scan (%v)\n", err)
		}
		return execErr
	}

	copts.Extra = expand(ctx, opts, specs)
	stop := progress.Scan(progressTo(), len(specs)+len(copts.Extra))
	sbom, err := checkFn(ctx, copts)
	stop()
	if err != nil {
		fmt.Fprintf(errOut, "ossprey: warning: could not scan formulae (%v); forwarding unchecked\n", err)
		return forwardTo()
	}
	return report(ctx, opts, sbom)
}

func report(ctx context.Context, opts Options, sbom *ossbom.SBOM) error {
	flushWarnings(ctx)
	summary, hasMalware := scan.MalwareReports(sbom, severity.ParseFloor(sbom.FailingSeverityFloor))
	if env.Verbose() {
		for _, msg := range summary.Informational {
			fmt.Fprintln(errOut, "ossprey: "+msg)
		}
	}
	if hasMalware {
		profile := ansi.Detect(errOut)
		fmt.Fprint(errOut, alert.Malware(summary.Alert(), "Installation blocked.", profile))
		for _, msg := range summary.Failing {
			fmt.Fprintln(errOut, profile.Red("Error: "+msg))
		}
		fmt.Fprintf(errOut, "ossprey: blocked `brew %s`\n", strings.Join(opts.Args, " "))
		return forward.ErrBlocked
	}
	note("ossprey: no malware found, forwarding to brew\n")
	return handoffFn(ctx, "brew", opts.Args)
}

// expand asks the API for each repo's SBOM (its own lockfiles: crates, Go
// modules, npm...), since those are built into the bottle. A repo that fails
// is still checked on its own; the failure is said out loud.
func expand(ctx context.Context, opts Options, specs []check.Spec) []ossbom.Component {
	ctx, cancel := context.WithTimeout(ctx, repoSBOMBudget)
	defer cancel()
	stop := progress.Start(progressTo(), fmt.Sprintf("reading dependencies of %d repositories...", len(specs)))
	defer stop()

	out := make([][]ossbom.Component, len(specs))
	errs := make([]error, len(specs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, s := range specs {
		wg.Add(1)
		go func(i int, purl string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], errs[i] = repoSBOMFn(ctx, opts, purl)
		}(i, "pkg:github/"+s.Name+"@"+s.Version)
	}
	wg.Wait()

	var comps []ossbom.Component
	failed := 0
	for i := range specs {
		if errs[i] != nil {
			failed++
			note("ossprey: could not read dependencies of %s (%v)\n", specs[i].Name, errs[i])
			continue
		}
		comps = append(comps, out[i]...)
	}
	if failed > 0 {
		fmt.Fprintf(errOut, "ossprey: warning: could not read the dependencies of %d of %d repositories; checking those repositories alone\n", failed, len(specs))
	}
	return comps
}

func repoSBOM(ctx context.Context, opts Options, purl string) ([]ossbom.Component, error) {
	c, err := submit.NewClient(ctx, opts.APIURL, opts.APIKey)
	if err != nil {
		return nil, err
	}
	return c.RepoSBOM(ctx, purl)
}

// targets returns the core formulae an install names, and whether --HEAD was
// asked for. ok is false for anything that is not a formula install.
func targets(args []string) (names []string, head, ok bool) {
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		i++
	}
	if i >= len(args) || !installVerbs[args[i]] {
		return nil, false, false
	}
	for _, a := range args[i+1:] {
		switch {
		case a == "--cask" || a == "--casks":
			return nil, false, false
		case a == "--HEAD":
			head = true
		case strings.HasPrefix(a, "-"):
			// brew's value options are --opt=value; the rest are switches.
		default:
			n := strings.TrimPrefix(strings.ToLower(a), "homebrew/core/")
			if formulaName.MatchString(n) {
				names = append(names, n)
			} else {
				note("ossprey: %s is not a homebrew/core formula; not checked\n", a)
			}
		}
	}
	return names, head, true
}

// formula is the part of the Homebrew API's formula JSON we read.
type formula struct {
	Name string `json:"name"`
	URLs struct {
		Stable struct {
			URL      string  `json:"url"`
			Tag      *string `json:"tag"`
			Revision *string `json:"revision"`
		} `json:"stable"`
		Head *struct {
			URL    string `json:"url"`
			Branch string `json:"branch"`
		} `json:"head"`
	} `json:"urls"`
	Dependencies []string `json:"dependencies"`
}

// resolve walks the named formulae and their runtime dependencies and returns
// one github spec per distinct source. A lookup error is returned beside
// whatever did resolve.
func resolve(ctx context.Context, names []string, head bool) ([]check.Spec, error) {
	type result struct {
		name string
		f    *formula
		err  error
	}
	seen := map[string]bool{}
	named := map[string]bool{}
	for _, n := range names {
		named[n] = true
	}
	var (
		specs   []check.Spec
		errs    []error
		dedup   = map[string]bool{}
		pending = names
	)
	for len(pending) > 0 && len(seen) < maxFormulae {
		var batch []string
		for _, n := range pending {
			if !seen[n] && len(seen) < maxFormulae {
				seen[n] = true
				batch = append(batch, n)
			}
		}
		pending = nil
		results := make([]result, len(batch))
		var wg sync.WaitGroup
		sem := make(chan struct{}, workers)
		for i, n := range batch {
			wg.Add(1)
			go func(i int, n string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				f, err := lookup(ctx, n)
				results[i] = result{n, f, err}
			}(i, n)
		}
		wg.Wait()

		srcs := make([]source, len(results))
		for i, r := range results {
			switch {
			case errors.Is(r.err, errNotFound):
				// Likely a cask (brew falls back to one) or an alias.
				note("ossprey: %s is not a homebrew/core formula; not checked\n", r.name)
				continue
			case r.err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", r.name, r.err))
				continue
			}
			pending = append(pending, r.f.Dependencies...)
			src, ok := sourceOf(r.f, head && named[r.name])
			if !ok {
				note("ossprey: %s is not fetched from GitHub; not checked\n", r.name)
				continue
			}
			srcs[i] = src
		}
		pinSources(srcs)
		for i, src := range srcs {
			if src.repo.Owner == "" {
				continue
			}
			spec := check.Spec{Ecosystem: "github", Name: src.repo.String(), Version: src.ref}
			if spec.Version == "" {
				spec.Version = "HEAD"
			}
			if k := spec.String(); !dedup[k] {
				dedup[k] = true
				specs = append(specs, spec)
				note("ossprey: %s -> %s@%s\n", results[i].name, spec.Name, spec.Version)
			}
		}
	}
	if len(pending) > 0 {
		fmt.Fprintf(errOut, "ossprey: warning: dependency tree exceeds %d formulae; the rest are not checked\n", maxFormulae)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].String() < specs[j].String() })
	return specs, errors.Join(errs...)
}

func lookup(ctx context.Context, name string) (*formula, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, formulaAPIURL+url.PathEscape(name)+".json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("Homebrew API %s", resp.Status)
	}
	var f formula
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// source is a GitHub repository at the ref a formula builds from.
type source struct {
	repo   gitscan.Repo
	ref    string
	pinned bool // ref is already a commit sha
}

// sourceOf maps a formula's stable (or --HEAD) URL to its GitHub repository.
func sourceOf(f *formula, head bool) (source, bool) {
	if head {
		if f.URLs.Head == nil {
			return source{}, false
		}
		r, ok := gitscan.ParseGitHubURL(f.URLs.Head.URL)
		return source{repo: r, ref: f.URLs.Head.Branch}, ok
	}
	s := f.URLs.Stable
	if r, ok := gitscan.ParseGitHubURL(s.URL); ok {
		// A git checkout: revision beats tag.
		switch {
		case s.Revision != nil && shaPattern.MatchString(*s.Revision):
			return source{repo: r, ref: *s.Revision, pinned: true}, true
		case s.Tag != nil:
			return source{repo: r, ref: *s.Tag}, true
		}
		return source{repo: r}, true
	}
	return parseArchiveURL(s.URL)
}

// parseArchiveURL reads the repository and ref out of a GitHub tarball URL:
// .../archive/refs/tags/<tag>.tar.gz, .../archive/<ref>.tar.gz,
// .../releases/download/<tag>/<file>, codeload.github.com/o/r/tar.gz/<ref>.
func parseArchiveURL(raw string) (source, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return source{}, false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	host := strings.ToLower(u.Hostname())
	var owner, name, ref string
	switch {
	case host == "github.com" && len(parts) >= 4 && parts[2] == "archive":
		owner, name = parts[0], parts[1]
		ref = strings.TrimPrefix(strings.Join(parts[3:], "/"), "refs/tags/")
		ref = strings.TrimPrefix(ref, "refs/heads/")
		ref = trimArchiveExt(ref)
	case host == "github.com" && len(parts) >= 6 && parts[2] == "releases" && parts[3] == "download":
		owner, name, ref = parts[0], parts[1], parts[4]
	case host == "codeload.github.com" && len(parts) >= 4:
		owner, name, ref = parts[0], parts[1], strings.Join(parts[3:], "/")
	default:
		return source{}, false
	}
	r, ok := gitscan.ParseGitHubURL("https://github.com/" + owner + "/" + name)
	if !ok || ref == "" {
		return source{}, false
	}
	return source{repo: r, ref: ref, pinned: shaPattern.MatchString(ref)}, true
}

func trimArchiveExt(s string) string {
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"} {
		if strings.HasSuffix(s, ext) {
			return strings.TrimSuffix(s, ext)
		}
	}
	return s
}

// pinSources resolves each unpinned ref to a commit sha with `git ls-remote`,
// which needs no GitHub API quota. A ref that cannot be resolved is kept by
// name.
func pinSources(srcs []source) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := range srcs {
		if srcs[i].repo.Owner == "" || srcs[i].pinned {
			continue
		}
		wg.Add(1)
		go func(s *source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if sha := lsRemoteFn(s.repo, s.ref); sha != "" {
				s.ref, s.pinned = sha, true
			}
		}(&srcs[i])
	}
	wg.Wait()
}

// lsRemote returns the commit sha ref names in repo, or "". A tag's peeled
// (^{}) entry wins, since an annotated tag's own sha is not a commit.
func lsRemote(r gitscan.Repo, ref string) string {
	path, err := shim.LookPathReal("git")
	if err != nil {
		return ""
	}
	if ref == "" {
		ref = "HEAD"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "ls-remote", "https://github.com/"+r.String()+".git",
		ref, "refs/tags/"+ref+"^{}", "refs/heads/"+ref)
	cmd.Env = append(os.Environ(), shim.BypassEnv+"=1", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return pickSHA(string(out), ref)
}

// pickSHA chooses from ls-remote output: peeled tag, then tag, then branch.
func pickSHA(out, ref string) string {
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && shaPattern.MatchString(sha) {
			got[name] = sha
		}
	}
	for _, k := range []string{"refs/tags/" + ref + "^{}", "refs/tags/" + ref, "refs/heads/" + ref, ref} {
		if sha := got[k]; sha != "" {
			return sha
		}
	}
	return ""
}
