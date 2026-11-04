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
	"runtime"
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
	newRepoSBOMer           = newClient
	aliasFn                 = brewAlias
	goos                    = runtime.GOOS
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

	req, ok := targets(opts.Args)
	if !ok || len(req.names) == 0 {
		return forwardTo()
	}
	if opts.SkipCI {
		note("ossprey: skip-ci set; forwarding `brew %s` without checking\n", strings.Join(opts.Args, " "))
		return forwardTo()
	}

	if opts.Passive {
		// Passive blocks nothing, so the lookups wait until brew is done.
		flushWarnings(ctx)
		execErr := execFn(ctx, "brew", opts.Args)
		passive(ctx, opts, req)
		return execErr
	}

	specs := resolveOrWarn(ctx, req)
	if len(specs) == 0 {
		note("ossprey: no formula sources on GitHub; forwarding unchecked\n")
		return forwardTo()
	}

	copts := check.Options{Specs: specs, APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID}

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

// resolveOrWarn resolves sources, failing open out loud on a lookup error.
func resolveOrWarn(ctx context.Context, req request) []check.Spec {
	specs, err := resolve(ctx, req)
	if err != nil {
		fmt.Fprintf(errOut, "ossprey: warning: could not look up formulae (%v); checking what resolved\n", err)
	}
	return specs
}

// passive submits what an install fetched, after brew has run.
func passive(ctx context.Context, opts Options, req request) {
	defer flushWarnings(ctx)
	specs := resolveOrWarn(ctx, req)
	if len(specs) == 0 {
		return
	}
	copts := check.Options{Specs: specs, APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID, SubmitOnly: true}
	if opts.MonitorID == "" {
		copts.Extra = expand(ctx, opts, specs)
	}
	stop := progress.Submit(progressTo(), len(specs)+len(copts.Extra))
	_, err := checkFn(ctx, copts)
	stop()
	if err != nil {
		fmt.Fprintf(errOut, "ossprey: warning: could not post scan (%v)\n", err)
	}
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
	// Printed even when quiet, like the package forwarders' clean line; a
	// check the platform scanned none of gets no verdict.
	if verdict, ok := forward.CleanVerdict(sbom, len(summary.Informational), ""); ok {
		fmt.Fprintf(errOut, "ossprey: %s, forwarding to brew\n", verdict)
	} else {
		note("ossprey: the platform checked none of the formula sources; forwarding unchecked\n")
	}
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
	// One client for all workers: a stored login refreshes its token here,
	// once, not concurrently in every worker.
	c, err := newRepoSBOMer(ctx, opts)
	if err != nil {
		fmt.Fprintf(errOut, "ossprey: warning: could not read repository dependencies (%v); checking the repositories alone\n", err)
		return nil
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, s := range specs {
		wg.Add(1)
		go func(i int, purl string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i], errs[i] = c.RepoSBOM(ctx, purl)
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

// repoSBOMer fetches a repo's SBOM; *client.Client is one.
type repoSBOMer interface {
	RepoSBOM(ctx context.Context, purl string) ([]ossbom.Component, error)
}

func newClient(ctx context.Context, opts Options) (repoSBOMer, error) {
	return submit.NewClient(ctx, opts.APIURL, opts.APIKey)
}

// request is what a formula install asks brew for.
type request struct {
	names      []string
	head       bool // --HEAD: build the named formulae from their head repo
	onlyDeps   bool // --only-dependencies: the named formulae are not installed
	ignoreDeps bool // --ignore-dependencies: their dependencies are not
}

// targets parses a formula install. ok is false for anything else.
func targets(args []string) (request, bool) {
	var req request
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		i++
	}
	if i >= len(args) || !installVerbs[args[i]] {
		return req, false
	}
	for _, a := range args[i+1:] {
		switch {
		case a == "--cask" || a == "--casks":
			return request{}, false
		case a == "--HEAD":
			req.head = true
		case a == "--only-dependencies":
			req.onlyDeps = true
		case a == "--ignore-dependencies":
			req.ignoreDeps = true
		case strings.HasPrefix(a, "-"):
			// brew's value options are --opt=value; the rest are switches.
		default:
			n := strings.TrimPrefix(strings.ToLower(a), "homebrew/core/")
			if formulaName.MatchString(n) {
				req.names = append(req.names, n)
			} else {
				note("ossprey: %s is not a homebrew/core formula; not checked\n", a)
			}
		}
	}
	return req, true
}

// deps is one dependency set of the Homebrew API's formula JSON.
type deps struct {
	Dependencies  []string          `json:"dependencies"`
	UsesFromMacOS []json.RawMessage `json:"uses_from_macos"`
	// Bounds pairs with UsesFromMacOS: {"since": "sonoma"} means the OS
	// supplies it from that release on, so older ones install it.
	Bounds []map[string]string `json:"uses_from_macos_bounds"`
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
	deps
	HeadDeps   *deps           `json:"head_dependencies"`
	Variations map[string]deps `json:"variations"`
}

// runtimeDeps are the formulae brew installs beside f on this OS. It errs
// toward checking: every variation for this OS family is included, since the
// exact bottle tag (macOS release, arch) would need brew's own logic.
func (f *formula) runtimeDeps(head bool) []string {
	base := f.deps
	if head && f.HeadDeps != nil {
		base = *f.HeadDeps
	}
	sets := []deps{base}
	for tag, v := range f.Variations {
		if strings.HasSuffix(tag, "_linux") == (goos == "linux") {
			sets = append(sets, v)
		}
	}
	var out []string
	for _, d := range sets {
		out = append(out, d.Dependencies...)
		out = append(out, d.usesFromMacOS()...)
	}
	return out
}

// usesFromMacOS returns the runtime uses_from_macos entries brew installs
// here: all of them on Linux; on macOS only those the OS supplies from some
// release on, since an older macOS installs them.
func (d deps) usesFromMacOS() []string {
	var out []string
	for i, raw := range d.UsesFromMacOS {
		var name string
		if json.Unmarshal(raw, &name) != nil {
			// {"perl": ["build", "test"]}: typed entries are build or test
			// only, which a bottle install does not pull in.
			continue
		}
		if goos != "linux" && (i >= len(d.Bounds) || len(d.Bounds[i]) == 0) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// resolve walks the named formulae and their runtime dependencies and returns
// one github spec per distinct source. A lookup error is returned beside
// whatever did resolve.
func resolve(ctx context.Context, req request) ([]check.Spec, error) {
	type result struct {
		name string
		f    *formula
		err  error
	}
	named := map[string]bool{}
	for _, n := range req.names {
		named[n] = true
	}
	var (
		specs     []check.Spec
		errs      []error
		seen      = map[string]bool{}
		dedup     = map[string]bool{}
		pending   = req.names
		truncated bool
	)
	for len(pending) > 0 {
		var batch []string
		for _, n := range pending {
			switch {
			case seen[n]:
			case len(seen) >= maxFormulae:
				truncated = true
			default:
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
				if errors.Is(err, errNotFound) && named[n] {
					// The API serves canonical names only; `python` is an alias.
					if canon := aliasFn(ctx, n); canon != "" && canon != n {
						f, err = lookup(ctx, canon)
					}
				}
				results[i] = result{n, f, err}
			}(i, n)
		}
		wg.Wait()

		srcs := make([]source, len(results))
		for i, r := range results {
			switch {
			case errors.Is(r.err, errNotFound):
				// Likely a cask (brew falls back to one).
				note("ossprey: %s is not a homebrew/core formula; not checked\n", r.name)
				continue
			case r.err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", r.name, r.err))
				continue
			}
			if !req.ignoreDeps {
				pending = append(pending, r.f.runtimeDeps(req.head && named[r.name])...)
			}
			if req.onlyDeps && named[r.name] {
				continue
			}
			src, ok := sourceOf(r.f, req.head && named[r.name])
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
	if truncated {
		// A cap keeps a pathological tree from walking the whole catalogue.
		fmt.Fprintf(errOut, "ossprey: warning: dependency tree exceeds %d formulae; the rest are not checked\n", maxFormulae)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].String() < specs[j].String() })
	return specs, errors.Join(errs...)
}

// brewAlias asks the real brew for a name's canonical formula, or "".
func brewAlias(ctx context.Context, name string) string {
	path, err := shim.LookPathReal("brew")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "info", "--json=v2", "--formula", name)
	cmd.Env = append(os.Environ(), shim.BypassEnv+"=1", "HOMEBREW_NO_AUTO_UPDATE=1")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	var info struct {
		Formulae []struct {
			Name string `json:"name"`
		} `json:"formulae"`
	}
	if json.Unmarshal(out, &info) != nil || len(info.Formulae) != 1 {
		return ""
	}
	if n := info.Formulae[0].Name; formulaName.MatchString(n) {
		return n
	}
	return ""
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

// Ref kinds: brew names a tag or a branch; unknown tries both, tag first.
const (
	kindUnknown = ""
	kindTag     = "tag"
	kindBranch  = "branch"
)

// source is a GitHub repository at the ref a formula builds from.
type source struct {
	repo   gitscan.Repo
	ref    string
	kind   string
	pinned bool // ref is already a commit sha
}

// sourceOf maps a formula's stable (or --HEAD) URL to its GitHub repository.
func sourceOf(f *formula, head bool) (source, bool) {
	if head {
		if f.URLs.Head == nil {
			return source{}, false
		}
		r, ok := gitscan.ParseGitHubURL(f.URLs.Head.URL)
		return source{repo: r, ref: f.URLs.Head.Branch, kind: kindBranch}, ok
	}
	s := f.URLs.Stable
	if r, ok := gitscan.ParseGitHubURL(s.URL); ok {
		// A git checkout: revision beats tag.
		switch {
		case s.Revision != nil && shaPattern.MatchString(*s.Revision):
			return source{repo: r, ref: *s.Revision, pinned: true}, true
		case s.Tag != nil:
			return source{repo: r, ref: *s.Tag, kind: kindTag}, true
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
	// Split before unescaping, so an escaped "/" in a tag stays in the tag.
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	for i, p := range parts {
		if parts[i], err = url.PathUnescape(p); err != nil {
			return source{}, false
		}
	}
	host := strings.ToLower(u.Hostname())
	var owner, name, ref, kind string
	switch {
	case host == "github.com" && len(parts) >= 4 && parts[2] == "archive":
		owner, name = parts[0], parts[1]
		ref, kind = splitRefKind(trimArchiveExt(strings.Join(parts[3:], "/")))
	case host == "github.com" && len(parts) >= 6 && parts[2] == "releases" && parts[3] == "download":
		owner, name, ref, kind = parts[0], parts[1], parts[4], kindTag
	case host == "codeload.github.com" && len(parts) >= 4:
		owner, name = parts[0], parts[1]
		ref, kind = splitRefKind(strings.Join(parts[3:], "/"))
	default:
		return source{}, false
	}
	r, ok := gitscan.ParseGitHubURL("https://github.com/" + owner + "/" + name)
	if !ok || ref == "" {
		return source{}, false
	}
	return source{repo: r, ref: ref, kind: kind, pinned: shaPattern.MatchString(ref)}, true
}

// splitRefKind strips a qualified ref's namespace and reports which it was.
func splitRefKind(ref string) (string, string) {
	if t, ok := strings.CutPrefix(ref, "refs/tags/"); ok {
		return t, kindTag
	}
	if b, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return b, kindBranch
	}
	return ref, kindUnknown
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
			if sha := lsRemoteFn(s.repo, s.ref, s.kind); sha != "" {
				s.ref, s.pinned = sha, true
			}
		}(&srcs[i])
	}
	wg.Wait()
}

// refCandidates are the ls-remote names for ref, in preference order. A
// tag's peeled (^{}) entry wins, since an annotated tag's own sha is not a
// commit.
func refCandidates(ref, kind string) []string {
	if ref == "" {
		return []string{"HEAD"}
	}
	tag := []string{"refs/tags/" + ref + "^{}", "refs/tags/" + ref}
	branch := []string{"refs/heads/" + ref}
	switch kind {
	case kindTag:
		return tag
	case kindBranch:
		return branch
	}
	return append(tag, branch...)
}

// lsRemote returns the commit sha ref names in repo, or "".
func lsRemote(r gitscan.Repo, ref, kind string) string {
	path, err := shim.LookPathReal("git")
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := append([]string{"ls-remote", "https://github.com/" + r.String() + ".git"}, refCandidates(ref, kind)...)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), shim.BypassEnv+"=1", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return pickSHA(string(out), refCandidates(ref, kind))
}

// pickSHA returns the sha of the first candidate ls-remote listed.
func pickSHA(out string, candidates []string) string {
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		sha, name, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if ok && shaPattern.MatchString(sha) {
			got[name] = sha
		}
	}
	for _, k := range candidates {
		if sha := got[k]; sha != "" {
			return sha
		}
	}
	return ""
}
