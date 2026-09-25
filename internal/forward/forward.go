// Package forward implements the package-manager forwarder: it inspects an
// install command (npm/yarn/pip/poetry/uv) or an npx fetch-and-run, checks the named packages against
// the Ossprey API, blocks the install if any are malicious, and otherwise execs
// the real package manager with the original arguments untouched.
//
// Scope: only the packages named on the command line are checked. Transitive
// dependencies are NOT resolved here — run `ossprey scan` after install for
// full-tree coverage.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/alert"
	"github.com/ossprey/ossprey-cli/internal/ansi"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/env"
	"github.com/ossprey/ossprey-cli/internal/monitor"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/progress"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/shim"
	"github.com/ossprey/ossprey-cli/internal/submit"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Test seams: overridable in tests so Run's decision logic can be exercised
// without a real package manager on PATH or a live API.
var (
	execFn        = Exec
	checkFn       = check.Run
	scanProjectFn = scanProject
)

// ErrBlocked is returned by Run when malware is found and the install was
// blocked. Callers map it to a non-zero exit code without printing it (Run has
// already printed the report).
var ErrBlocked = errors.New("install blocked: malware detected")

var errOut io.Writer = os.Stderr

// progressOut is where the "still working" indicator is drawn. Kept apart from
// errOut so a test capturing the verdict lines is not also handed the
// animation; both default to stderr.
var progressOut io.Writer = os.Stderr

// Manager describes a supported package manager and how to recognise its
// install command.
type Manager struct {
	Bin       string // executable name, e.g. "npm"
	Ecosystem string // "npm" or "pypi"
	// Lockfile marks a manager that *can* write a lockfile enumerating
	// everything it installed, transitives included. Passive mode reads that
	// lockfile after the install instead of resolving the same tree a second
	// time in front of it. pip never can: `pip install foo` updates no file, so
	// there is nothing to read afterwards.
	//
	// A capability, not a promise about any given command — the invocation
	// decides, so route on writesLocalLockfile rather than on this flag.
	Lockfile  bool
	installAt func(args []string) (specStart int, ok bool)
	// parse classifies the arguments after installAt's specStart. Nil means
	// ParseSpecs, which understands install verbs.
	parse func(args []string) installArgs
	// FetchExec marks a manager that downloads a package and runs it rather
	// than installing into a project (npx). It has no manifest install: naming
	// nothing means it runs something already on disk, so it never triggers a
	// project scan.
	FetchExec bool
}

// noLocalLockfileFlags name the options that stop an install from updating a
// lockfile in the current directory: a global install, a lockfile explicitly
// disabled, or a run redirected at another project. When one is present, a
// post-install catalogue of "." would describe a tree this command never
// touched, so passive mode submits the packages named on the command line
// instead.
//
// Bias: listing a harmless flag costs a fallback to the older, slower passive
// path. Missing one costs a passive install that reports the wrong tree, or
// nothing at all — so when in doubt, list it. `--no-save` is deliberately
// absent: npm still updates an existing package-lock.json.
var noLocalLockfileFlags = map[string]map[string]bool{
	"npm": flagSet("-g", "--global", "--no-package-lock", "--package-lock",
		"--location", "--prefix", "-C"),
	"pnpm":   flagSet("-g", "--global", "--no-lockfile", "--lockfile", "--dir", "-C"),
	"yarn":   flagSet("-g", "--global", "--no-lockfile", "--cwd"),
	"poetry": flagSet("-C", "--directory", "--project"),
	"uv":     flagSet("--directory", "--project", "--system"),
}

// hereValues are the values of a redirecting flag that still mean "this
// directory", so `npm --prefix . install x` keeps the post-install path.
var hereValues = flagSet(".", "./", ".\\")

// writesLocalLockfile reports whether this invocation is expected to leave an
// up-to-date lockfile in the current directory — which is the thing passive
// mode reads once the install is done.
//
// The manager alone does not settle it. `uv pip install foo` resolves into an
// environment and leaves uv.lock alone; `npm install -g foo` touches nothing
// local; `npm install --no-package-lock foo` writes no lock by request; and
// `pnpm --dir ../other add foo` locks a directory we are not scanning. Reading
// "." after any of those would submit a tree that has nothing to do with the
// command, and the package actually installed would go unreported.
func writesLocalLockfile(m *Manager, args []string) bool {
	if !m.Lockfile {
		return false
	}
	// `uv pip install` is pip wearing uv's coat. `uv add` / `uv sync` do lock.
	if m.Bin == "uv" {
		if i := verbIndex("uv", args); i >= 0 && args[i] == "pip" {
			return false
		}
	}
	blocking := noLocalLockfileFlags[m.Bin]
	for i := 0; i < len(args); i++ {
		flag, value, hasInline := splitFlagValue(args[i])
		if !blocking[flag] {
			continue
		}
		if !hasInline && isDirFlag(flag) && i+1 < len(args) {
			value = args[i+1]
		}
		// The spellings that keep the local lockfile: a redirect that points
		// here, npm's project location, an explicitly enabled lockfile.
		switch {
		case isDirFlag(flag) && hereValues[value]:
			continue
		case flag == "--location" && value == "project":
			continue
		case (flag == "--package-lock" || flag == "--lockfile") && value == "true":
			continue
		}
		return false
	}
	return true
}

// isDirFlag reports whether a flag's value names the directory the manager
// operates on, rather than being a boolean.
func isDirFlag(flag string) bool {
	switch flag {
	case "--prefix", "-C", "--dir", "--cwd", "--directory", "--project":
		return true
	}
	return false
}

// managers is the registry of supported forwarders. Install verbs include both
// the package-adding forms (`npm install <pkg>`, `yarn add <pkg>`) and the
// manifest-installing forms with no named packages (`npm install`, `npm ci`,
// `yarn install`, `poetry install`, `uv sync`); the latter trigger a project
// manifest scan instead of falling through unchecked (OSS-1284).
var managers = map[string]*Manager{
	"npm":    {Bin: "npm", Ecosystem: "npm", Lockfile: true, installAt: verbAt("npm", "install", "i", "add", "ci", "update", "up")},
	"pnpm":   {Bin: "pnpm", Ecosystem: "npm", Lockfile: true, installAt: verbAt("pnpm", "install", "i", "add", "update", "up")},
	"yarn":   {Bin: "yarn", Ecosystem: "npm", Lockfile: true, installAt: verbAt("yarn", "add", "install", "upgrade", "up")},
	"pip":    {Bin: "pip", Ecosystem: "pypi", installAt: verbAt("pip", "install")},
	"pip3":   {Bin: "pip3", Ecosystem: "pypi", installAt: verbAt("pip3", "install")},
	"poetry": {Bin: "poetry", Ecosystem: "pypi", Lockfile: true, installAt: verbAt("poetry", "add", "install", "update", "lock")},
	// uv: `uv add <pkg>`, `uv sync`, and `uv pip install <pkg>`.
	"uv": {Bin: "uv", Ecosystem: "pypi", Lockfile: true, installAt: uvInstallAt},
	// npx: `npx <pkg>`, `npx -p <pkg> <cmd>`. See npx.go.
	"npx": {Bin: "npx", Ecosystem: "npm", FetchExec: true, installAt: npxInstallAt, parse: npxParse},
}

// Managers returns the names of every supported forwarder, for CLI wiring.
func Managers() []string {
	out := make([]string, 0, len(managers))
	for name := range managers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the Manager for a binary name.
func Lookup(bin string) (*Manager, bool) {
	m, ok := managers[bin]
	return m, ok
}

// verbAt returns an installAt matcher: the verb is the first token that is not a
// global flag (or a global flag's value), it must equal one of verbs, and the
// package specs begin just after it.
func verbAt(bin string, verbs ...string) func([]string) (int, bool) {
	return func(args []string) (int, bool) {
		idx := verbIndex(bin, args)
		if idx < 0 || idx >= len(args) {
			return 0, false
		}
		if slices.Contains(verbs, args[idx]) {
			return idx + 1, true
		}
		return 0, false
	}
}

// verbIndex returns the index of the sub-command verb, skipping global flags
// that precede it. Package managers accept their global options before the verb
// — `pnpm --filter web add x`, `npm --prefix /tmp install x`, `pip --quiet
// install x` — and pnpm workspaces do it as a matter of course. Reading only
// args[0] classified those as "not an install" and forwarded them unchecked.
//
// Only the first non-flag token is considered: it is the verb or nothing is. We
// never scan ahead for a verb-shaped token, because `pnpm run add` must stay a
// script run rather than becoming an install of a package called "add".
func verbIndex(bin string, args []string) int {
	global := globalValueFlags[bin]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if !strings.HasPrefix(a, "-") {
			return i
		}
		// "--" ends option parsing; the verb cannot follow it meaningfully.
		if a == "--" {
			return -1
		}
		flag, _, hasInline := splitFlagValue(a)
		if global[flag] && !hasInline {
			i++ // this flag's value is the next token, not the verb
		}
	}
	return -1
}

// uvInstallAt matches `uv add ...`, `uv sync`, and `uv pip install ...`, with
// uv's global flags allowed before the verb.
func uvInstallAt(args []string) (int, bool) {
	idx := verbIndex("uv", args)
	if idx < 0 {
		return 0, false
	}
	rest := args[idx:]
	if len(rest) >= 1 && (rest[0] == "add" || rest[0] == "sync") {
		return idx + 1, true
	}
	if len(rest) >= 2 && rest[0] == "pip" && rest[1] == "install" {
		return idx + 2, true
	}
	return 0, false
}

// globalValueFlags lists, per manager, the flags valid *before* the verb whose
// following token is a value rather than the verb itself.
//
// Bias: when in doubt, leave a flag out. Omitting a value-taking flag means its
// value is read as the verb, matches nothing, and the command forwards unchecked
// — the same fail-open behaviour as before this existed. Wrongly listing a
// *boolean* flag would instead swallow the real verb and hide an install, so
// only flags known to take a value belong here. Notably pnpm's -w
// (--workspace-root) is boolean, where npm's -w (--workspace) takes a value.
var globalValueFlags = map[string]map[string]bool{
	"npm": flagSet("--prefix", "-C", "--loglevel", "--registry", "--userconfig",
		"--globalconfig", "--cache", "-w", "--workspace", "--omit", "--include"),
	"pnpm": flagSet("--filter", "-F", "--filter-prod", "--dir", "-C", "--loglevel",
		"--reporter", "--store-dir", "--virtual-store-dir", "--resolution-mode",
		"--use-node-version", "--package-import-method", "--workspace-concurrency",
		"--network-concurrency", "--registry"),
	"yarn": flagSet("--cwd", "--registry", "--cache-folder", "--modules-folder"),
	"pip": flagSet("--log", "--proxy", "--timeout", "--retries", "--cache-dir",
		"--python", "-i", "--index-url"),
	"poetry": flagSet("-C", "--directory", "--project", "-P"),
	"uv": flagSet("--directory", "--project", "--cache-dir", "--python", "-p",
		"--config-file", "--color"),
}

// Options configures a forwarder Run.
type Options struct {
	Bin    string
	Args   []string
	APIURL string
	APIKey string
	// ResolveLatest fills a concrete version for unpinned packages. Defaults to
	// registry.ResolveLatest; overridable in tests.
	ResolveLatest func(ctx context.Context, ecosystem, name string) (string, error)
	// ResolveSpec picks the npm release a dist-tag or range names, for npx.
	// Defaults to registry.ResolveNpmSpec; overridable in tests.
	ResolveSpec func(ctx context.Context, name, spec string) (string, error)
	SkipCI      bool
	// Passive submits the scan and forwards the install without waiting for a
	// verdict. This is what the watchdog and monitor shims run in.
	Passive bool
	// MonitorID sends a passive submission through a monitor's ingest token, so
	// the machine needs no login and no API key. Ignored unless Passive.
	MonitorID string
}

// Run executes the forwarder flow:
//  1. If the command is not an install, exec the real manager unchanged.
//  2. If the install names packages, check exactly those (resolving unpinned
//     versions); block (ErrBlocked) on malware.
//  3. If the install names no packages (bare `npm install`, `npm ci`, `pip
//     install -r req.txt`, `yarn install`, `poetry install`, `uv sync`), it
//     installs from the project manifest/lockfile — so scan that project and
//     check every dependency it declares (OSS-1284). Blocks on malware.
//  4. Otherwise (only un-checkable local/URL targets) exec the real manager.
//
// The returned error is ErrBlocked on malware, an *exec.ExitError when the real
// manager exits non-zero, or any setup/API error.
func Run(ctx context.Context, opts Options) error {
	m, ok := Lookup(opts.Bin)
	if !ok {
		return fmt.Errorf("unsupported package manager %q", opts.Bin)
	}

	// Every exit that hands control to the real manager goes through forwardTo,
	// so no path can exec without first flushing what we gathered. The real
	// manager's output starts immediately after this and never stops, and the
	// forwarder exits via os.Exit on a non-zero code, so a warning not printed
	// here is either buried or lost outright (OSS-2001).
	forwardTo := func() error {
		fmt.Fprint(errOut, warn.Drain(ctx))
		return execFn(ctx, m.Bin, opts.Args)
	}

	finish := func(sbom *ossbom.SBOM, err error) error {
		if err != nil {
			return err
		}
		return reportAndForward(ctx, m, opts, sbom)
	}

	resolve := opts.ResolveLatest
	if resolve == nil {
		resolve = registry.ResolveLatest
	}
	resolveSpec := opts.ResolveSpec
	if resolveSpec == nil {
		resolveSpec = registry.ResolveNpmSpec
	}

	start, isInstall := m.installAt(opts.Args)
	if !isInstall {
		// Not an install (e.g. `npm run`, `pip list`) — nothing to check.
		return forwardTo()
	}

	if opts.SkipCI {
		fmt.Fprintf(errOut, "ossprey: skip-ci set; forwarding `%s %s` without checking\n",
			m.Bin, strings.Join(opts.Args, " "))
		return forwardTo()
	}

	// Passive mode blocks nothing, so nothing it does belongs in front of the
	// install. When the install will leave a lockfile here, that lockfile is
	// the resolution we used to duplicate: let the manager run, then catalogue
	// what it wrote. Cheaper (no second `npm install --package-lock-only`),
	// raceless (we read the tree after it settles), and more accurate, because
	// it describes what was installed rather than what we predicted. An
	// invocation that locks somewhere else — or nowhere — falls through to the
	// spec path below, which submits the packages it can name.
	if opts.Passive && writesLocalLockfile(m, opts.Args) {
		return passiveAfterInstall(ctx, m, opts)
	}

	var parsed installArgs
	if m.parse != nil {
		parsed = m.parse(opts.Args[start:])
	} else {
		parsed = ParseSpecs(m, opts.Args[start:])
	}
	// resolveAll pins every named package to the release that will actually be
	// installed or run.
	resolveAll := func(ctx context.Context) []check.Spec {
		specs := parsed.Specs
		if m.FetchExec {
			specs = resolveNpxSpecifiers(ctx, resolveSpec, specs)
		}
		return resolveSpecs(ctx, resolve, specs)
	}

	switch {
	case len(parsed.Specs) > 0:
		// Explicit packages named — check exactly those.
		if other := slices.Concat(parsed.NonPackages, parsed.ReqFiles); len(other) > 0 {
			fmt.Fprintf(errOut, "ossprey: not checking non-registry install targets: %s (run `ossprey scan` for full coverage)\n",
				strings.Join(other, ", "))
		}
		if opts.Passive {
			// This invocation leaves no lockfile here to read afterwards (pip,
			// `uv pip install`, a global or redirected install), so the names
			// on the command line are all we will ever know. Resolve and
			// submit them beside the install rather than ahead of it.
			return passiveAlongside(ctx, m, opts, len(parsed.Specs), func(ctx context.Context) (*ossbom.SBOM, error) {
				resolved := resolveAll(ctx)
				if len(resolved) == 0 {
					return nil, errNothingToCheck
				}
				return checkFn(ctx, check.Options{
					Specs:      resolved,
					APIURL:     opts.APIURL,
					APIKey:     opts.APIKey,
					SubmitOnly: true,
					MonitorID:  opts.MonitorID,
				})
			})
		}
		resolved := resolveAll(ctx)
		if len(resolved) == 0 {
			fmt.Fprintln(errOut, "ossprey: nothing left to check after version resolution; forwarding")
			return forwardTo()
		}
		// The scan is the one part of a forwarded install that takes visible
		// time, and until it prints something the terminal looks hung.
		stop := progress.Scan(progressOut, len(resolved))
		sbom, err := checkFn(ctx, check.Options{
			Specs:     resolved,
			APIURL:    opts.APIURL,
			APIKey:    opts.APIKey,
			MonitorID: opts.MonitorID,
		})
		stop()
		return finish(sbom, err)

	case m.FetchExec:
		// Nothing named will be fetched: a local bin, `npx --version`, or
		// `npx -c` in the project's own context. A git or URL target is fetched
		// and run, though, and cannot be checked, so say so.
		if len(parsed.NonPackages) > 0 {
			fmt.Fprintf(errOut, "ossprey: not checking non-registry targets: %s; forwarding\n",
				strings.Join(parsed.NonPackages, ", "))
		}
		return forwardTo()

	case manifestInstall(parsed):
		// No packages named — the manager installs from the project manifest /
		// lockfile. Scan the project and check every declared dependency rather
		// than falling through unchecked.
		if opts.Passive {
			// As above: nothing will be written here for us to read, so the
			// project's own manifest is the best description of this install,
			// and it exists before it as well as after. Scan beside the
			// install rather than in front of it.
			fmt.Fprintf(errOut, "ossprey: no packages named; scanning project manifest alongside `%s %s`\n",
				m.Bin, strings.Join(opts.Args, " "))
			return passiveAlongside(ctx, m, opts, 0, func(ctx context.Context) (*ossbom.SBOM, error) {
				return scanProjectFn(ctx, scanRequest{
					Dir: ".", APIURL: opts.APIURL, APIKey: opts.APIKey,
					MonitorID: opts.MonitorID, SubmitOnly: true,
				})
			})
		}
		fmt.Fprintf(errOut, "ossprey: no packages named; scanning project manifest before `%s %s`\n",
			m.Bin, strings.Join(opts.Args, " "))
		// Cataloguing a whole project can take longer than the API scan itself
		// (npm range resolution, uv), so the indicator wraps both.
		stop := progress.Start(progressOut, "ossprey: scan in progress")
		sbom, err := scanProjectFn(ctx, scanRequest{
			Dir: ".", APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID,
		})
		stop()
		return finish(sbom, err)

	default:
		// Only un-checkable explicit targets (local paths, archives, URLs, VCS
		// refs). Can't verify them against a registry — forward with a warning.
		fmt.Fprintf(errOut, "ossprey: not checking non-registry install targets: %s; forwarding (run `ossprey scan` after install)\n",
			strings.Join(parsed.NonPackages, ", "))
		return forwardTo()
	}
}

// resolveSpecs fills concrete versions for unpinned specs. Fail open: a registry
// outage must not block the developer — warn and drop that one from the check.
func resolveSpecs(ctx context.Context, resolve func(context.Context, string, string) (string, error), specs []check.Spec) []check.Spec {
	resolved := make([]check.Spec, 0, len(specs))
	for _, s := range specs {
		if s.Version == "" {
			v, err := resolve(ctx, s.Ecosystem, s.Name)
			if err != nil {
				// Different consequence from the scan path, so a different
				// class: here the package is not checked at all, which is
				// worse than being submitted unversioned.
				warn.Add(ctx, registry.UnresolvedEntry(s.Ecosystem, s.Name, err,
					"skipping its check"))
				continue
			}
			s.Version = v
		}
		resolved = append(resolved, s)
	}
	return resolved
}

// reportAndForward blocks (ErrBlocked) if sbom carries malware, else execs the
// real manager with the original args.
func reportAndForward(ctx context.Context, m *Manager, opts Options, sbom *ossbom.SBOM) error {
	// Warnings gathered while cataloguing and resolving go out first, so the
	// verdict is the last thing on screen rather than the first thing scrolled
	// past (OSS-2001).
	fmt.Fprint(errOut, warn.Drain(ctx))

	// The forwarders parse no flags of their own (DisableFlagParsing), so there
	// is nowhere to opt into a stricter floor; the default applies.
	summary, hasMalware := scan.MalwareReports(sbom, severity.FailingFloor)
	for _, msg := range summary.Informational {
		fmt.Fprintln(errOut, "ossprey: "+msg)
	}
	if hasMalware {
		profile := ansi.Detect(errOut)
		outcome := "Installation blocked."
		if m.FetchExec {
			outcome = "Execution blocked."
		}
		fmt.Fprint(errOut, alert.Malware(summary.Alert(), outcome, profile))
		for _, msg := range summary.Failing {
			fmt.Fprintln(errOut, profile.Red("Error: "+msg))
		}
		fmt.Fprintf(errOut, "ossprey: blocked `%s %s`\n", m.Bin, strings.Join(opts.Args, " "))
		return ErrBlocked
	}
	// Both messages sit after the malware check, never in front of it: gating the
	// block on a component count would forward an SBOM that carried a verdict but
	// no components.
	if n := len(sbom.Components); n == 0 {
		// Nothing catalogued means nothing verified, whether the project declares
		// nothing or every cataloger failed. "No malware found" would read as a
		// clean bill of health for an install that was never checked.
		fmt.Fprintf(errOut, "ossprey: found no dependencies to check; forwarding `%s %s` unchecked\n",
			m.Bin, strings.Join(opts.Args, " "))
	} else {
		// The count is load-bearing: "no malware found" alone read the same
		// whether 40 packages were checked or none were.
		fmt.Fprintf(errOut, "ossprey: no malware found in %s, forwarding to %s\n",
			countPackages(n), m.Bin)
	}
	// Already drained at the top of this function, ahead of the verdict.
	return execFn(ctx, m.Bin, opts.Args)
}

func countPackages(n int) string {
	if n == 1 {
		return "1 package"
	}
	return fmt.Sprintf("%d packages", n)
}

// manifestInstall reports whether an install with no explicitly named packages
// pulls its packages from the project manifest/lockfile — i.e. a bare install
// (`npm install`, `npm ci`, `yarn install`, `poetry install`, `uv sync`) or an
// install driven by a requirements file (`pip install -r req.txt`). In both
// cases the project should be scanned. An install whose only targets are local
// paths / URLs is NOT a manifest install.
func manifestInstall(p installArgs) bool {
	if len(p.Specs) > 0 {
		return false
	}
	return len(p.ReqFiles) > 0 || len(p.NonPackages) == 0
}

// scanProject catalogs a directory, submits the resulting SBOM to the Ossprey
// API, and returns it with any vulnerabilities applied. It is the default
// scanProjectFn seam. When the directory has no catalogable dependencies it
// returns the empty SBOM without an API call so a bare install in a non-project
// dir forwards.

// scanRequest describes one project scan-and-submit.
type scanRequest struct {
	Dir       string
	APIURL    string
	APIKey    string
	MonitorID string
	// SubmitOnly posts the SBOM without polling for a verdict (passive).
	SubmitOnly bool
	// Installed catalogues what the manager just installed rather than what the
	// project declares: manifests and lockfiles are parsed, but the catalogers
	// that shell out to uv/npm to resolve ranges are not run. After an install
	// the lockfile already names the whole resolved tree, so re-resolving it
	// would only repeat, slower, work the manager has just finished.
	Installed bool
}

func scanProject(ctx context.Context, req scanRequest) (*ossbom.SBOM, error) {
	sbom, err := scan.Run(ctx, scan.Options{Path: req.Dir, NoExec: req.Installed})
	if err != nil {
		return nil, err
	}
	if req.Installed && len(sbom.Components) == 0 {
		// The install wrote no lockfile we can read (an unsupported layout, or
		// a failed install). Fall back to the declaring scan rather than
		// reporting a project with no dependencies: passive mode's whole job is
		// to see this machine's installs.
		if sbom, err = scan.Run(ctx, scan.Options{Path: req.Dir}); err != nil {
			return nil, err
		}
	}
	if len(sbom.Components) == 0 {
		return sbom, nil // nothing declared to check
	}
	if req.SubmitOnly {
		if err := submit.Post(ctx, sbom, req.APIURL, req.APIKey, req.MonitorID); err != nil {
			return nil, err
		}
		return sbom, nil
	}
	if err := submit.Validate(ctx, sbom, req.APIURL, req.APIKey); err != nil {
		return nil, err
	}
	return sbom, nil
}

// errNothingToCheck reports a passive submission that had nothing to send —
// every named package failed version resolution. Not an error the user caused,
// so it gets its own line rather than a "could not post scan" warning.
var errNothingToCheck = errors.New("nothing left to check after version resolution")

// passiveAfterInstall forwards the install first and catalogues what it left
// behind: the lockfile the manager wrote names every package it actually
// installed, transitives included.
//
// Order is the point. Running in front of the install delayed it by a full
// resolution (`npm install --package-lock-only`, uv) to predict a tree the
// manager was about to resolve for real; running *beside* it removed the delay
// but raced the manager for the same files. Running after it costs a parse and
// a POST, reads a settled directory, and describes what was installed instead
// of what we guessed would be.
//
// Passive blocks nothing, so a failed install is still worth cataloguing (it
// may have installed most of the tree before failing) and its exit code is
// returned untouched.
func passiveAfterInstall(ctx context.Context, m *Manager, opts Options) error {
	// Nothing of ours has run yet, so this drain is normally empty — it is here
	// so that no path execs the real manager without flushing first.
	fmt.Fprint(errOut, warn.Drain(ctx))
	execErr := execFn(ctx, m.Bin, opts.Args)

	// Only now is there a wait to announce, and it is a short one: parsing a
	// lockfile and posting it, with no resolver in the way.
	stop := progress.Submit(progressOut, 0)
	sbom, err := scanProjectFn(ctx, scanRequest{
		Dir:        ".",
		APIURL:     opts.APIURL,
		APIKey:     opts.APIKey,
		MonitorID:  opts.MonitorID,
		SubmitOnly: true,
		Installed:  true,
	})
	stop()

	fmt.Fprint(errOut, warn.Drain(ctx))
	reportPassive(opts, sbom, err)
	return execErr
}

// passiveAlongside runs work concurrently with the real package manager, for
// the one manager that leaves nothing to read afterwards (pip). The install
// starts immediately; the submission catches up with it.
func passiveAlongside(ctx context.Context, m *Manager, opts Options, n int, work func(context.Context) (*ossbom.SBOM, error)) error {
	type outcome struct {
		sbom *ossbom.SBOM
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		sbom, err := work(ctx)
		done <- outcome{sbom, err}
	}()

	// Warnings are deliberately not drained here: the goroutine is still
	// filling them, and from this line on the manager's output owns the
	// terminal. They go out below, before this function returns, which is
	// before main can os.Exit on a non-zero install.
	execErr := execFn(ctx, m.Bin, opts.Args)

	var res outcome
	select {
	case res = <-done:
	default:
		// The install finished first, so there is a residual wait and it is
		// worth announcing. Nothing was drawn earlier, when the manager's own
		// output would have been fighting it.
		stop := progress.Submit(progressOut, n)
		res = <-done
		stop()
	}

	fmt.Fprint(errOut, warn.Drain(ctx))
	reportPassive(opts, res.sbom, res.err)
	return execErr
}

// reportPassive states what the passive submission did. It never returns an
// error: passive mode never blocks an install, not even on a failed submission
// — a monitor that can break `npm install` is a monitor people rip out.
func reportPassive(opts Options, sbom *ossbom.SBOM, err error) {
	mode := "passive"
	if opts.MonitorID != "" {
		// Named because a monitor also decides whose account this lands in, and
		// the env var carrying it may not have been set by the person reading
		// this line.
		mode = "passive, monitor " + monitor.Redact(opts.MonitorID)
	}
	switch {
	case errors.Is(err, errNothingToCheck):
		fmt.Fprintf(errOut, "ossprey: nothing left to check after version resolution; nothing posted (%s)\n", mode)
	case err != nil:
		fmt.Fprintf(errOut, "ossprey: warning: could not post scan (%v); the install was not blocked (%s)\n", err, mode)
	case sbom != nil && len(sbom.Components) == 0:
		// "Scan posted" would claim coverage of an install we catalogued
		// nothing from.
		fmt.Fprintf(errOut, "ossprey: found no dependencies to report; nothing posted (%s)\n", mode)
	default:
		fmt.Fprintf(errOut, "ossprey: scan posted to the Ossprey dashboard; the install was not blocked (%s)\n", mode)
	}
}

// installArgs is the classification of an install command's arguments
// (everything after the install verb).
type installArgs struct {
	// Specs are registry packages named on the command line, to check individually.
	Specs []check.Spec
	// NonPackages are explicit targets that can't be checked against a registry:
	// local paths, archive files, URLs, VCS refs.
	NonPackages []string
	// ReqFiles are requirements files referenced via -r/--requirement. Their
	// packages live in the file, not on the command line.
	ReqFiles []string
}

// ParseSpecs classifies install arguments. A real-world multi-package install
// interleaves package names with flags, flag-values, paths and URLs — e.g.
//
//	pip install requests -r extra.txt -t ./vendor flask ./local.whl
//
// so naively treating every non-flag token as a package produces bogus specs.
// ParseSpecs therefore (a) consumes the values of value-taking flags, (b) tracks
// requirements-file values separately, and (c) structurally separates tokens
// that can't be a registry package from the real package specs.
func ParseSpecs(m *Manager, args []string) installArgs {
	valFlags := valueFlags[m.Bin]
	reqFlags := requirementFileFlags[m.Bin]
	var out installArgs

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}

		if strings.HasPrefix(a, "-") {
			flag, inlineVal, hasInline := splitFlagValue(a)
			switch {
			case reqFlags[flag]:
				// Requirements file: track it; its packages are scanned, not parsed here.
				if hasInline {
					out.ReqFiles = append(out.ReqFiles, inlineVal)
				} else if i+1 < len(args) {
					out.ReqFiles = append(out.ReqFiles, args[i+1])
					i++
				}
			case valFlags[flag] && !hasInline && i+1 < len(args):
				i++ // consume the flag's value so it isn't read as a package
			}
			continue
		}

		// Local paths, archives, URLs and VCS refs aren't registry packages.
		if isNonPackageToken(a) {
			out.NonPackages = append(out.NonPackages, a)
			continue
		}

		s, err := check.ParseSpec(m.Ecosystem, a)
		if err != nil {
			out.NonPackages = append(out.NonPackages, a)
			continue
		}
		out.Specs = append(out.Specs, s)
	}
	return out
}

// splitFlagValue splits "--flag=value" into ("--flag", "value", true). A flag
// with no inline value returns (flag, "", false).
func splitFlagValue(arg string) (flag, value string, hasInline bool) {
	if eq := strings.IndexByte(arg, '='); eq >= 0 {
		return arg[:eq], arg[eq+1:], true
	}
	return arg, "", false
}

// isNonPackageToken reports whether token is an install target that can't be
// resolved against a package registry: a local path, a local archive file, a
// URL, or a VCS ref.
func isNonPackageToken(token string) bool {
	// URLs and VCS refs.
	if strings.Contains(token, "://") {
		return true
	}
	for _, p := range []string{"git+", "git:", "http:", "https:", "file:", "ssh:"} {
		if strings.HasPrefix(token, p) {
			return true
		}
	}
	// Local paths (POSIX and Windows). An npm scoped name like "@scope/pkg"
	// also contains '/', so match path *prefixes* rather than any '/'.
	switch {
	case token == "." || token == "..":
		return true
	case strings.HasPrefix(token, "./") || strings.HasPrefix(token, "../"):
		return true
	case strings.HasPrefix(token, `.\`) || strings.HasPrefix(token, `..\`):
		return true
	case strings.HasPrefix(token, "/") || strings.HasPrefix(token, "~"):
		return true
	}
	// Local archive files.
	for _, ext := range []string{".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".tbz2", ".whl", ".zip"} {
		if strings.HasSuffix(token, ext) {
			return true
		}
	}
	return false
}

// flagSet builds a lookup set from flag names.
func flagSet(flags ...string) map[string]bool {
	m := make(map[string]bool, len(flags))
	for _, f := range flags {
		m[f] = true
	}
	return m
}

// valueFlags lists, per manager binary, the flags whose following argument is a
// value (a path, URL, name, etc.) rather than a package to check. Both short
// and long forms are listed. Boolean flags (e.g. npm --save-dev) are absent so
// the package after them is still read. The structural isNonPackageToken check
// is the backstop for value flags not listed here whose value is a URL or path.
//
// Same asymmetry as globalValueFlags, and it bites harder here: omitting a
// value-taking flag makes its value read as a package, which checks something
// that isn't being installed (noisy, but safe), while wrongly listing a boolean
// flag swallows the package name and skips its check entirely (silent, unsafe).
// Only flags known to take a value belong. Per-manager tables, never shared —
// pnpm inheriting npm's list is what hid `pnpm add -w <pkg>` (OSS-1577).
var valueFlags = map[string]map[string]bool{
	"npm": flagSet("--registry", "--prefix", "-C", "--cache", "--userconfig",
		"--globalconfig", "--tag", "--otp", "-w", "--workspace", "--omit", "--include"),
	// pnpm's own, deliberately not npm's: -w is --workspace-root here and takes
	// no value, and --filter is accepted after the verb as well as before it.
	"pnpm": flagSet("--filter", "-F", "--filter-prod", "--dir", "-C", "--registry",
		"--store-dir", "--virtual-store-dir", "--cache-dir", "--loglevel", "--reporter",
		"--resolution-mode", "--use-node-version", "--package-import-method",
		"--workspace-concurrency", "--network-concurrency"),
	"yarn": flagSet("--registry", "--cache-folder", "--modules-folder", "--cwd"),
	"pip": flagSet("-t", "--target", "-e", "--editable", "-i", "--index-url",
		"--extra-index-url", "-f", "--find-links", "-c", "--constraint", "--prefix",
		"--root", "--src", "--python", "--cache-dir", "--log", "--no-binary",
		"--only-binary", "--platform", "--python-version", "--implementation",
		"--abi", "--progress-bar", "--report"),
	"poetry": flagSet("--source", "-G", "--group", "--python", "-P", "--project", "-C"),
	// uv covers both `uv add` (uv-native flags) and `uv pip install` (pip-style flags).
	"uv": flagSet("-i", "--index-url", "--extra-index-url", "--index", "--default-index",
		"-f", "--find-links", "--cache-dir", "-p", "--python", "--project", "-c",
		"--constraint", "-o", "--override", "--group", "--index-strategy",
		"-t", "--target", "--prefix", "-e", "--editable", "--optional", "--extra"),
}

// pip3 is pip under another name, so it shares every table. pnpm is not npm and
// has its own (OSS-1577).
func init() {
	valueFlags["pip3"] = valueFlags["pip"]
	requirementFileFlags["pip3"] = requirementFileFlags["pip"]
	globalValueFlags["pip3"] = globalValueFlags["pip"]
}

// requirementFileFlags name the flags whose value is a requirements/constraints
// file. The packages it lists are NOT checked by the forwarder (use `ossprey
// scan` for full coverage), so the value is reported as skipped to warn the user.
var requirementFileFlags = map[string]map[string]bool{
	"pip": flagSet("-r", "--requirement"),
	"uv":  flagSet("-r", "--requirement"),
}

// Exec runs the real package manager, inheriting stdio. The child's exit code
// is propagated via the returned *exec.ExitError.
func Exec(ctx context.Context, bin string, args []string) error {
	path, err := shim.LookPathReal(bin)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = envWithoutMonitorID()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// envWithoutMonitorID drops the monitor id before handing control to the real
// package manager.
//
// A monitor shim exports it so ossprey can read it, and the manager inherits
// whatever ossprey has -- which would put the id in the environment of every
// `postinstall` and `setup.py` the manager runs. Those scripts are the exact
// thing this tool exists to watch, and the id is a live write credential
// against the owner's account, so it stops here.
func envWithoutMonitorID() []string {
	full := os.Environ()
	out := make([]string, 0, len(full))
	for _, kv := range full {
		if strings.HasPrefix(kv, env.MonitorIDEnv+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}
