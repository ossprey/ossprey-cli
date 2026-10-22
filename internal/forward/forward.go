// Package forward implements the package-manager forwarder: it inspects an
// install command (npm/yarn/bun/pip/poetry/uv), checks the packages it would
// install against the Ossprey API, blocks the install if any are malicious,
// and otherwise execs the real package manager with the original arguments
// untouched.
//
// A named install is checked with the dependencies it brings in, resolved by
// the manager's own kind of dry run (see expand.go); when that dry run cannot
// be had, the named packages are checked alone and a warning says so.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
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
	"github.com/ossprey/ossprey-cli/internal/trust"
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

// A forwarder sits in front of every install, so by default it is silent: the
// only things it prints are a malware block (the full report) and a platform
// error. Everything else — a clean verdict, why it did not check, what it is
// scanning, collected warnings, informational findings — is narration, and
// only OSSPREY_VERBOSE shows it. The forwarders parse no flags of their own, so
// the env var is the only switch. The real manager's own output is never
// touched: it inherits our stdio.

// note prints a line of narration, shown only when verbose.
func note(format string, a ...any) {
	if env.Verbose() {
		fmt.Fprintf(errOut, format, a...)
	}
}

// flushWarnings empties the collector, printing it only when verbose. It must
// still drain when quiet, or main's safety-net drain would print it anyway.
func flushWarnings(ctx context.Context) {
	if s := warn.Drain(ctx); env.Verbose() {
		fmt.Fprint(errOut, s)
	}
}

// progressTo is where a wait is announced. Quiet, only a terminal gets one: the
// animation erases itself, whereas into a pipe or CI log it is a line that
// stays, and that would be a second line.
func progressTo() io.Writer {
	if env.Verbose() {
		return progressOut
	}
	return progress.Transient(progressOut)
}

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
	// reqFileArgs reports whether this invocation's positional arguments are
	// requirements files rather than packages (`uv pip sync req.txt`).
	reqFileArgs func(args []string) bool
	// toolRunAt matches fetch-and-execute (`uvx ruff`, `npx cowsay`): one
	// package is fetched and run, and everything after it is the program's own
	// argv. Parsed by parseRun, never ParseSpecs.
	toolRunAt func(args []string) (start int, ok bool)
	// parseRun classifies a tool run's arguments from start on. Unset means
	// uv's syntax, parseToolRun.
	parseRun func(args []string) installArgs
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
	// `uv pip install` is pip wearing uv's coat, and `uv tool install` puts
	// the tool in uv's own tool directory. `uv add` / `uv sync` / `uv lock` lock.
	if m.Bin == "uv" {
		if i := verbIndex("uv", args); i >= 0 && (args[i] == "pip" || args[i] == "tool") {
			return false
		}
	}
	// `yarn global add` installs into yarn's global directory.
	if m.Bin == "yarn" {
		if i := verbIndex("yarn", args); i >= 0 && args[i] == "global" {
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
// `yarn install`, `poetry install`, `poetry sync`, `uv sync`); the latter trigger a project
// manifest scan instead of falling through unchecked (OSS-1284).
var managers = map[string]*Manager{
	"npm": {Bin: "npm", Ecosystem: "npm", Lockfile: true, installAt: npmInstallAt,
		toolRunAt: npmExecAt, parseRun: npmExecRun},
	// npx is `npm exec` under its own name: every invocation fetches and runs.
	"npx": {Bin: "npx", Ecosystem: "npm", installAt: noInstall,
		toolRunAt: func([]string) (int, bool) { return 0, true }, parseRun: npxRun},
	// bun writes bun.lock, which the catalogue cannot read yet, so it has no
	// Lockfile: a passive install submits what it names, or the declaring
	// scan, alongside the install. `bun install -g` is an add.
	"bun": {Bin: "bun", Ecosystem: "npm", installAt: verbAt("bun", "install", "i", "ci", "add", "a", "update", "up"),
		toolRunAt: verbAt("bun", "x"), parseRun: bunxRun},
	"bunx": {Bin: "bunx", Ecosystem: "npm", installAt: noInstall,
		toolRunAt: func([]string) (int, bool) { return 0, true }, parseRun: bunxRun},
	"pnpm": {Bin: "pnpm", Ecosystem: "npm", Lockfile: true, installAt: verbAt("pnpm", "install", "i", "add", "update", "up",
		"upgrade", "install-test", "it")},
	"yarn":   {Bin: "yarn", Ecosystem: "npm", Lockfile: true, installAt: yarnInstallAt},
	"pip":    {Bin: "pip", Ecosystem: "pypi", installAt: verbAt("pip", "install")},
	"pip3":   {Bin: "pip3", Ecosystem: "pypi", installAt: verbAt("pip3", "install")},
	"poetry": {Bin: "poetry", Ecosystem: "pypi", Lockfile: true, installAt: verbAt("poetry", "add", "install", "sync", "update", "lock")},
	// uv: `uv add <pkg>`, `uv sync`, `uv lock`, `uv pip install <pkg>`,
	// `uv pip sync <req.txt>` and `uv tool install <pkg>`.
	"uv": {Bin: "uv", Ecosystem: "pypi", Lockfile: true, installAt: uvInstallAt, reqFileArgs: uvPipSync,
		toolRunAt: uvToolRunAt},
	// uvx is `uv tool run` under its own name: every invocation fetches and runs.
	"uvx": {Bin: "uvx", Ecosystem: "pypi", installAt: noInstall,
		toolRunAt: func([]string) (int, bool) { return 0, true }},
}

func noInstall([]string) (int, bool) { return 0, false }

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

// yarnInstallAt matches yarn's installs: `yarn add/install/upgrade`, bare
// `yarn` (which is `yarn install`), `yarn global add/upgrade`, and any of
// those run in a workspace (`yarn workspace web add x`).
func yarnInstallAt(args []string) (int, bool) {
	idx := verbIndex("yarn", args)
	if idx < 0 {
		// No command, only options: an install of the manifest, unless all it
		// asks for is help or the version.
		for _, a := range args {
			switch a {
			case "-v", "--version", "-h", "--help", "--":
				return 0, false
			}
		}
		return len(args), true
	}
	rest := args[idx:]
	switch {
	case slices.Contains([]string{"add", "install", "upgrade", "up"}, rest[0]):
		return idx + 1, true
	case rest[0] == "global" && len(rest) > 1 && (rest[1] == "add" || rest[1] == "upgrade"):
		return idx + 2, true
	case rest[0] == "workspace" && len(rest) > 2:
		// `yarn workspace <name> <command...>` runs that command in the
		// workspace. Bare `yarn workspace web` names no command.
		sub := rest[2:]
		if verbIndex("yarn", sub) < 0 {
			return 0, false
		}
		if start, ok := yarnInstallAt(sub); ok {
			return idx + 2 + start, true
		}
	}
	return 0, false
}

// uvInstallAt matches `uv add ...`, `uv sync`, `uv lock`, `uv pip install
// ...`, `uv pip sync ...` and `uv tool install ...`, with uv's global flags
// allowed before the verb.
//
// `uv tool run` is deliberately absent: it is fetch-and-execute, where only the
// first token is a package and the rest is the program's own argv.
func uvInstallAt(args []string) (int, bool) {
	idx := verbIndex("uv", args)
	if idx < 0 {
		return 0, false
	}
	rest := args[idx:]
	if len(rest) >= 1 && (rest[0] == "add" || rest[0] == "sync" || rest[0] == "lock") {
		return idx + 1, true
	}
	if len(rest) >= 2 && rest[0] == "pip" && (rest[1] == "install" || rest[1] == "sync") {
		return idx + 2, true
	}
	if len(rest) >= 2 && rest[0] == "tool" && rest[1] == "install" {
		return idx + 2, true
	}
	return 0, false
}

// uvToolRunAt matches `uv tool run ...`, the long form of uvx.
func uvToolRunAt(args []string) (int, bool) {
	idx := verbIndex("uv", args)
	if idx >= 0 && idx+1 < len(args) && args[idx] == "tool" && args[idx+1] == "run" {
		return idx + 2, true
	}
	return 0, false
}

// uvPipSync reports whether args are `uv pip sync`, whose positional arguments
// are requirements files: it installs exactly what they list, so it is a
// manifest install like `pip install -r`, not a named one.
func uvPipSync(args []string) bool {
	idx := verbIndex("uv", args)
	return idx >= 0 && idx+1 < len(args) && args[idx] == "pip" && args[idx+1] == "sync"
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
	// bun has no entry: it finds its command by skipping options without
	// reading values, so in `bun --cwd web add x` the command is "web".
	"pip": flagSet("--log", "--proxy", "--timeout", "--retries", "--cache-dir",
		"--python", "-i", "--index-url", "--keyring-provider", "--exists-action",
		"--trusted-host", "--cert", "--client-cert", "--use-feature", "--use-deprecated"),
	"poetry": flagSet("-C", "--directory", "--project", "-P"),
	"uv": flagSet("--directory", "--project", "--cache-dir", "--python", "-p",
		"--config-file", "--color", "--allow-insecure-host"),
}

// Options configures a forwarder Run.
type Options struct {
	Bin    string
	Args   []string
	APIURL string
	APIKey string
	// ResolveLatest fills a concrete version for unpinned packages, ignoring any
	// range or tag; overridable in tests. Resolve, when set, is used instead.
	ResolveLatest func(ctx context.Context, ecosystem, name string) (string, error)
	// Resolve fills a concrete version for an unpinned package from the range
	// or dist-tag it was named with (check.Spec.Constraint). Defaults to
	// registry.Resolve.
	Resolve func(ctx context.Context, ecosystem, name, constraint string) (string, error)
	SkipCI  bool
	// Passive submits the scan and forwards the install without waiting for a
	// verdict. This is what the watchdog and monitor shims run in.
	Passive bool
	// MonitorID sends a passive submission through a monitor's ingest token, so
	// the machine needs no login and no API key. Ignored unless Passive.
	MonitorID string
	// Trust names sources whose packages are neither checked nor sent. A named
	// install applies its npm scopes to the names typed, and both rules to
	// the tree the resolver's dry run reports, with the registry that dry run
	// recorded for each package (uv records none). Project scans apply all
	// of it, from the lockfile.
	Trust trust.Policy
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
		flushWarnings(ctx)
		return execFn(ctx, m.Bin, opts.Args)
	}

	// coverage is what a named install's verdict covered, for the verbose
	// clean line; a manifest scan has none.
	coverage := ""
	finish := func(sbom *ossbom.SBOM, err error) error {
		if err != nil {
			// Main prints the error; drain here so its safety-net drain does
			// not print the warnings too, which quiet mode keeps hidden.
			flushWarnings(ctx)
			return err
		}
		return reportAndForward(ctx, m, opts, sbom, coverage)
	}

	resolve := opts.Resolve
	if resolve == nil {
		resolve = registry.Resolve
		if latest := opts.ResolveLatest; latest != nil {
			resolve = func(ctx context.Context, eco, name, _ string) (string, error) {
				return latest(ctx, eco, name)
			}
		}
	}

	start, isInstall := m.installAt(opts.Args)
	toolRun := false
	if !isInstall && m.toolRunAt != nil {
		start, toolRun = m.toolRunAt(opts.Args)
		isInstall = toolRun
	}
	if !isInstall {
		// Not an install (e.g. `npm run`, `pip list`) — nothing to check.
		return forwardTo()
	}

	if opts.SkipCI {
		note("ossprey: skip-ci set; forwarding `%s %s` without checking\n",
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
	// A tool run writes no lockfile here, whatever its manager can do: `npm
	// exec` installs into npm's cache.
	if opts.Passive && !toolRun && writesLocalLockfile(m, opts.Args) {
		return passiveAfterInstall(ctx, m, opts)
	}

	var parsed installArgs
	if toolRun {
		if m.parseRun != nil {
			parsed = m.parseRun(opts.Args[start:])
		} else {
			parsed = parseToolRun(m, opts.Args[start:])
		}
		parsed.ToolRun = true
		if parsed.LocalCommand != "" && localBinFn(parsed.LocalCommand) {
			// npx and bunx run the project's own binary and fetch nothing.
			// Checking the registry package of that name would check
			// something else, and could block a run that installs nothing.
			note("ossprey: `%s` is the project's own binary; forwarding `%s %s` unchecked\n",
				parsed.LocalCommand, m.Bin, strings.Join(opts.Args, " "))
			return forwardTo()
		}
	} else {
		parsed = parseInstallArgs(m, opts.Args[start:], m.reqFileArgs != nil && m.reqFileArgs(opts.Args))
	}
	if kept := dropTrusted(ctx, opts.Trust, parsed.Specs); len(kept) < len(parsed.Specs) {
		parsed.Specs = kept
		// Every named package was trusted. Without this the empty spec list
		// would read as a bare install and scan the whole project instead —
		// which is still right when a requirements file is installed too.
		if len(kept) == 0 && len(parsed.ReqFiles) == 0 {
			// What was trusted first, then what that means for the install.
			flushWarnings(ctx)
			note("ossprey: every package named is from a trusted source; forwarding `%s %s` unchecked\n",
				m.Bin, strings.Join(opts.Args, " "))
			return forwardTo()
		}
	}

	if toolRun && len(parsed.Specs) == 0 {
		// A tool run with no registry package (`uvx --from git+https://… cmd`,
		// `uvx --help`) has nothing to check, and it is not a manifest install:
		// scanning the project here would check something it never runs.
		note("ossprey: no registry package to check; forwarding `%s %s` unchecked\n",
			m.Bin, strings.Join(opts.Args, " "))
		return forwardTo()
	}

	switch {
	case len(parsed.Specs) > 0 && len(parsed.ReqFiles) > 0:
		// Packages named *and* a requirements file (`pip install -r req.txt
		// flask`, `uvx --with-requirements r.txt ruff`): both are installed, so
		// both are checked, in one submission — the files named, plus the
		// packages. Checking only the names left everything in the file
		// unchecked.
		req := scanRequest{
			APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID,
			Trust: opts.Trust,
		}
		if opts.Passive {
			req.SubmitOnly = true
			var set checkSet
			return passiveAlongside(ctx, m, opts, len(parsed.Specs), func(ctx context.Context) (*ossbom.SBOM, error) {
				dir, cleanup := reqFilesDir(parsed.ReqFiles)
				defer cleanup()
				req.Dir = dir
				set = resolveNamed(ctx, m, opts, start, parsed, resolve)
				req.Specs = set.specs
				return scanProjectFn(ctx, req)
			}, func() { reportUnresolved(ctx, parsed.Specs, set) })
		}
		note("ossprey: scanning %s and %s before `%s %s`\n", strings.Join(parsed.ReqFiles, ", "),
			countPackages(len(parsed.Specs)), m.Bin, strings.Join(opts.Args, " "))
		set := resolveWithProgress(ctx, m, opts, start, parsed, resolve)
		req.Specs = set.specs
		stop := progress.Start(progressTo(), "ossprey: scan in progress")
		dir, cleanup := reqFilesDir(parsed.ReqFiles)
		defer cleanup()
		req.Dir = dir
		sbom, err := scanProjectFn(ctx, req)
		stop()
		return finish(sbom, err)

	case len(parsed.Specs) > 0:
		// Explicit packages named — check those and what they bring in.
		if other := slices.Concat(parsed.NonPackages, parsed.ReqFiles); len(other) > 0 {
			note("ossprey: not checking non-registry install targets: %s (run `ossprey scan` for full coverage)\n",
				strings.Join(other, ", "))
		}
		if opts.Passive {
			// This invocation leaves no lockfile here to read afterwards (pip,
			// `uv pip install`, a global or redirected install), so the names
			// on the command line, and what the resolver says they bring in,
			// are all we will ever know. Resolve and submit them beside the
			// install rather than ahead of it.
			var set checkSet
			return passiveAlongside(ctx, m, opts, len(parsed.Specs), func(ctx context.Context) (*ossbom.SBOM, error) {
				set = resolveNamed(ctx, m, opts, start, parsed, resolve)
				if len(set.specs) == 0 {
					return nil, errNothingToCheck
				}
				return checkFn(ctx, check.Options{
					Specs:      set.specs,
					APIURL:     opts.APIURL,
					APIKey:     opts.APIKey,
					SubmitOnly: true,
					MonitorID:  opts.MonitorID,
				})
			}, func() { reportUnresolved(ctx, parsed.Specs, set) })
		}
		set := resolveWithProgress(ctx, m, opts, start, parsed, resolve)
		if len(set.specs) == 0 {
			note("ossprey: nothing left to check after version resolution; forwarding\n")
			return forwardTo()
		}
		coverage = set.coverage()
		// The scan is the one part of a forwarded install that takes visible
		// time, and until it prints something the terminal looks hung.
		stop := progress.Scan(progressTo(), len(set.specs))
		sbom, err := checkFn(ctx, check.Options{
			Specs:     set.specs,
			APIURL:    opts.APIURL,
			APIKey:    opts.APIKey,
			MonitorID: opts.MonitorID,
		})
		stop()
		return finish(sbom, err)

	case manifestInstall(parsed):
		// No packages named — the manager installs from the project manifest /
		// lockfile. Scan the project and check every declared dependency rather
		// than falling through unchecked.
		if opts.Passive {
			// As above: nothing will be written here for us to read, so the
			// project's own manifest is the best description of this install,
			// and it exists before it as well as after. Scan beside the
			// install rather than in front of it.
			note("ossprey: no packages named; scanning project manifest alongside `%s %s`\n",
				m.Bin, strings.Join(opts.Args, " "))
			return passiveAlongside(ctx, m, opts, 0, func(ctx context.Context) (*ossbom.SBOM, error) {
				dir, cleanup := reqFilesDir(parsed.ReqFiles)
				defer cleanup()
				return scanProjectFn(ctx, scanRequest{
					Dir: dir, APIURL: opts.APIURL, APIKey: opts.APIKey,
					MonitorID: opts.MonitorID, SubmitOnly: true, Trust: opts.Trust,
				})
			}, nil)
		}
		note("ossprey: no packages named; scanning project manifest before `%s %s`\n",
			m.Bin, strings.Join(opts.Args, " "))
		// Cataloguing a whole project can take longer than the API scan itself
		// (npm range resolution, uv), so the indicator wraps both.
		stop := progress.Start(progressTo(), "ossprey: scan in progress")
		dir, cleanup := reqFilesDir(parsed.ReqFiles)
		defer cleanup()
		sbom, err := scanProjectFn(ctx, scanRequest{
			Dir: dir, APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID,
			Trust: opts.Trust,
		})
		stop()
		return finish(sbom, err)

	default:
		// Only un-checkable explicit targets (local paths, archives, URLs, VCS
		// refs). Can't verify them against a registry — forward with a warning.
		note("ossprey: not checking non-registry install targets: %s; forwarding (run `ossprey scan` after install)\n",
			strings.Join(parsed.NonPackages, ", "))
		return forwardTo()
	}
}

// dropTrusted removes the specs the policy trusts by name, recording each. It
// runs before version resolution so a private package is never looked up on
// the public registry, which is where the noise it exists to remove came from.
//
// Only the npm scope rule can apply here, before anything is resolved; the
// registry rule applies to the resolved tree in resolveNamed. See Options.Trust.
func dropTrusted(ctx context.Context, policy trust.Policy, specs []check.Spec) []check.Spec {
	if policy.Empty() {
		return specs
	}
	kept := make([]check.Spec, 0, len(specs))
	for _, s := range specs {
		if policy.Trusts(s.Ecosystem, s.Name, nil) {
			warn.Add(ctx, scan.TrustedEntry(s.Ecosystem, s.Name, s.Version))
			continue
		}
		kept = append(kept, s)
	}
	return kept
}

// resolveSpecs fills concrete versions for unpinned specs. Fail open: a registry
// outage must not block the developer — warn and drop that one from the check.
func resolveSpecs(ctx context.Context, resolve func(context.Context, string, string, string) (string, error), specs []check.Spec) []check.Spec {
	resolved := make([]check.Spec, 0, len(specs))
	for _, s := range specs {
		if s.Version == "" {
			v, err := resolve(ctx, s.Ecosystem, s.Name, s.Constraint)
			if err != nil {
				// Different consequence from the scan path, so a different
				// class: here the package is not checked at all, which is
				// worse than being submitted unversioned.
				warn.Add(ctx, registry.UnresolvedEntry(s.Ecosystem, s.Name, err,
					"skipping its check"))
				continue
			}
			s.Version, s.Constraint = v, ""
		}
		resolved = append(resolved, s)
	}
	return resolved
}

// reportAndForward blocks (ErrBlocked) if sbom carries malware, else execs the
// real manager with the original args. coverage, when set, says what the
// verdict covered ("1 requested + 64 dependencies").
func reportAndForward(ctx context.Context, m *Manager, opts Options, sbom *ossbom.SBOM, coverage string) error {
	// Warnings gathered while cataloguing and resolving go out first, so the
	// verdict is the last thing on screen rather than the first thing scrolled
	// past (OSS-2001).
	flushWarnings(ctx)

	// The forwarders parse no flags of their own (DisableFlagParsing), so there
	// is nowhere to opt into a stricter floor; the default applies.
	summary, hasMalware := scan.MalwareReports(sbom, severity.FailingFloor)
	for _, msg := range summary.Informational {
		note("ossprey: %s\n", msg)
	}
	if hasMalware {
		// The full report even when quiet: a block is the one outcome worth
		// more than a line.
		profile := ansi.Detect(errOut)
		fmt.Fprint(errOut, alert.Malware(summary.Alert(), "Installation blocked.", profile))
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
		note("ossprey: found no dependencies to check; forwarding `%s %s` unchecked\n",
			m.Bin, strings.Join(opts.Args, " "))
	} else {
		// The count is load-bearing: "no malware found" alone read the same
		// whether 40 packages were checked or none were — and whether the
		// named package's dependencies were among them.
		note("ossprey: no malware found in %s%s, forwarding to %s\n",
			countPackages(n), coverage, m.Bin)
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
// reqFilesDir is where a requirements-file install is scanned from: a fresh
// dir holding each file it names as requirements.txt, nested -r includes
// inlined. Scanning "." instead missed a file the catalogue's glob does not
// match (requirements/prod.txt, deps.txt, ../shared/reqs.txt) and checked
// unrelated manifests beside it. With no files named, or none readable (pip
// then fails on its own), it is the project dir.
func reqFilesDir(files []string) (string, func()) {
	noop := func() {}
	if len(files) == 0 {
		return ".", noop
	}
	dir, err := os.MkdirTemp("", "ossprey-reqs-")
	if err != nil {
		return ".", noop
	}
	cleanup := func() { os.RemoveAll(dir) }
	wrote := 0
	for i, f := range files {
		data, err := flattenRequirements(f, map[string]bool{})
		if err != nil {
			continue
		}
		sub := filepath.Join(dir, strconv.Itoa(i))
		if os.MkdirAll(sub, 0o700) != nil || os.WriteFile(filepath.Join(sub, "requirements.txt"), data, 0o600) != nil {
			continue
		}
		wrote++
	}
	if wrote == 0 {
		cleanup()
		return ".", noop
	}
	return dir, cleanup
}

// flattenRequirements reads a requirements file with its -r includes inlined
// (relative to the including file, as pip resolves them). Constraint files are
// dropped: they install nothing, and a relative path would not resolve from
// the copy.
func flattenRequirements(path string, seen map[string]bool) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if seen[abs] {
		return nil, nil
	}
	seen[abs] = true
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if inc, ok := requirementInclude(trimmed, "-r", "--requirement"); ok {
			if !filepath.IsAbs(inc) {
				inc = filepath.Join(filepath.Dir(path), inc)
			}
			nested, err := flattenRequirements(inc, seen)
			if err == nil {
				out = append(out, nested...)
			}
			continue
		}
		if _, ok := requirementInclude(trimmed, "-c", "--constraint"); ok {
			continue
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out, nil
}

// requirementInclude reads "-r f", "-rf", "--requirement f" or "--requirement=f".
func requirementInclude(line, short, long string) (string, bool) {
	for _, p := range []string{long + "=", long + " ", long + "\t", short} {
		if v, ok := strings.CutPrefix(line, p); ok {
			if v = strings.TrimSpace(v); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

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
	// Trust is passed to the scan; trusted packages are not sent.
	Trust trust.Policy
	// Specs are packages named on the command line beside a requirements
	// file. They are submitted with the scan, so one verdict covers both.
	Specs []check.Spec
}

func scanProject(ctx context.Context, req scanRequest) (*ossbom.SBOM, error) {
	sbom, err := scan.Run(ctx, scan.Options{Path: req.Dir, NoExec: req.Installed, Trust: req.Trust})
	if err != nil {
		return nil, err
	}
	if req.Installed && len(sbom.Components) == 0 {
		// The install wrote no lockfile we can read (an unsupported layout, or
		// a failed install). Fall back to the declaring scan rather than
		// reporting a project with no dependencies: passive mode's whole job is
		// to see this machine's installs.
		if sbom, err = scan.Run(ctx, scan.Options{Path: req.Dir, Trust: req.Trust}); err != nil {
			return nil, err
		}
	}
	for _, s := range req.Specs {
		sbom.AddComponent(ossbom.Component{Name: s.Name, Version: s.Version, Type: s.Ecosystem,
			Source: []string{"check"}})
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
	flushWarnings(ctx)
	execErr := execFn(ctx, m.Bin, opts.Args)

	// Only now is there a wait to announce, and it is a short one: parsing a
	// lockfile and posting it, with no resolver in the way.
	stop := progress.Submit(progressTo(), 0)
	sbom, err := scanProjectFn(ctx, scanRequest{
		Dir:        ".",
		APIURL:     opts.APIURL,
		APIKey:     opts.APIKey,
		MonitorID:  opts.MonitorID,
		SubmitOnly: true,
		Installed:  true,
		Trust:      opts.Trust,
	})
	stop()

	flushWarnings(ctx)
	reportPassive(opts, sbom, err)
	return execErr
}

// passiveAlongside runs work concurrently with the real package manager, for
// the one manager that leaves nothing to read afterwards (pip). The install
// starts immediately; the submission catches up with it. late, if set, runs
// once the manager has exited and work is done, for anything that must print
// but must not print from beside the manager.
func passiveAlongside(ctx context.Context, m *Manager, opts Options, n int, work func(context.Context) (*ossbom.SBOM, error), late func()) error {
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
		stop := progress.Submit(progressTo(), n)
		res = <-done
		stop()
	}

	if late != nil {
		late()
	}
	flushWarnings(ctx)
	reportPassive(opts, res.sbom, res.err)
	return execErr
}

// resolveWithProgress is resolveNamed for a gating install: the resolution is
// the first visible wait, announced before there is a count to report, and
// its failure is reported only after that animation has stopped, never on
// top of it.
func resolveWithProgress(ctx context.Context, m *Manager, opts Options, start int, parsed installArgs,
	resolve func(context.Context, string, string, string) (string, error)) checkSet {
	stop := progress.Start(progressTo(), "ossprey: resolving dependencies")
	set := resolveNamed(ctx, m, opts, start, parsed, resolve)
	stop()
	reportUnresolved(ctx, parsed.Specs, set)
	return set
}

// reportUnresolved prints the fallback line for a set whose tree was not
// resolved, and nothing for one whose tree was.
func reportUnresolved(ctx context.Context, specs []check.Spec, set checkSet) {
	if set.unresolved != nil {
		reportUnexpanded(ctx, specs, set.unresolved)
	}
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
		note("ossprey: nothing left to check after version resolution; nothing posted (%s)\n", mode)
	case err != nil:
		fmt.Fprintf(errOut, "ossprey: warning: could not post scan (%v); the install was not blocked (%s)\n", err, mode)
	case sbom != nil && len(sbom.Components) == 0:
		// "Scan posted" would claim coverage of an install we catalogued
		// nothing from.
		note("ossprey: found no dependencies to report; nothing posted (%s)\n", mode)
	default:
		note("ossprey: scan posted to the Ossprey dashboard; the install was not blocked (%s)\n", mode)
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
	// LocalCommand is the bare command of an npm-side tool run, which npx and
	// bunx take from the project's node_modules/.bin when it is there instead
	// of fetching the package of that name.
	LocalCommand string
	// Tokens are the Specs as the command line spelled them, for a resolver
	// that reads the manager's own syntax (a range, extras, a marker).
	Tokens map[check.Spec]string
	// ToolRun marks a fetch-and-execute: the package goes into the tool's
	// own cache, and everything after the command is the program's argv.
	ToolRun bool
	// Registry is the registry an npm-side tool run names on its command line
	// (`npx --registry …`), taken from npm's own parse of the argv so the
	// program's arguments can never supply it.
	Registry string
	// Userconfig is the --userconfig npm reads, from the same parse.
	Userconfig string
	// NpmFlags are the other resolution options npm attributes to itself in
	// a tool run (`--before`, `--tag`, `--omit`, the peer rules), rendered
	// for the dry run; NpmGlobal and NpmPrefix are its global mode and
	// --prefix, which decide the .npmrc npm reads.
	NpmFlags  []string
	NpmGlobal bool
	NpmPrefix string
	// NpmOmits are the dependency kinds npm's effective omit policy leaves
	// out of the install (npmArgv.omits).
	NpmOmits map[string]bool
	// NpmCache is the --cache npm was given, if any, and NpxPackages the
	// specs a tool run installs into the npx cache, as typed: together they
	// locate the tree an earlier run of the same packages left there.
	NpmCache    string
	NpxPackages []string
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
	return parseInstallArgs(m, args, false)
}

// parseInstallArgs is ParseSpecs, except that with positionalReqFiles every
// positional argument is a requirements file (`uv pip sync req.txt`).
func parseInstallArgs(m *Manager, args []string, positionalReqFiles bool) installArgs {
	valFlags := valueFlags[m.Bin]
	if m.Ecosystem == "pypi" {
		args = splitAttachedShorts(args, valFlags)
	}
	reqFlags := requirementFileFlags[m.Bin]
	pkgFlags := packageValueFlags[m.Bin]
	srcFlags := sourceFlags[m.Bin]
	var out installArgs
	var positional []string
	sourceNamed := false
	classify := func(a string) { out.addTarget(m.Ecosystem, a) }

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
			case srcFlags[flag]:
				// The value is the package installed; the positional only names it.
				sourceNamed = true
				if hasInline {
					classify(inlineVal)
				} else if i+1 < len(args) {
					classify(args[i+1])
					i++
				}
			case pkgFlags[flag]:
				// The value is more packages being installed: check them too.
				value := inlineVal
				if !hasInline && i+1 < len(args) {
					value = args[i+1]
					i++
				}
				for _, p := range splitRequirements(value) {
					classify(p)
				}
			case valFlags[flag] && !hasInline && i+1 < len(args):
				i++ // consume the flag's value so it isn't read as a package
			}
			continue
		}

		positional = append(positional, a)
	}
	if sourceNamed {
		return out // a source flag named the package; positionals are not packages
	}
	for _, a := range positional {
		if positionalReqFiles {
			out.ReqFiles = append(out.ReqFiles, a)
			continue
		}
		classify(a)
	}
	return out
}

// addTarget sorts one package-or-target token into Specs or NonPackages.
func (p *installArgs) addTarget(ecosystem, token string) {
	// Local paths, archives, URLs and VCS refs aren't registry packages.
	if isNonPackageToken(token) {
		p.NonPackages = append(p.NonPackages, token)
		return
	}
	s, err := check.ParseSpec(ecosystem, token)
	if err != nil {
		p.NonPackages = append(p.NonPackages, token)
		return
	}
	p.Specs = append(p.Specs, s)
	if p.Tokens == nil {
		p.Tokens = map[check.Spec]string{}
	}
	p.Tokens[s] = token
}

// parseToolRun classifies fetch-and-execute arguments (`uvx [opts] <cmd>
// [args...]`). Unlike an install, only the first positional is a package — the
// command, which uv takes as the package name unless --from names one — and
// everything after it is the program's own argv: `uvx cowsay moo` must not
// check a package called "moo". --with adds packages to the run's environment,
// so those are checked too.
//
// The flag table here is not the install one, and the asymmetry is worse than
// it is for installs: a value-taking flag left out makes its value read as the
// command, so the real package goes unchecked, and a boolean wrongly listed
// swallows the command the same way. toolRunValueFlags is therefore taken
// verbatim from `uv tool run --help`, not guessed.
func parseToolRun(m *Manager, args []string) installArgs {
	args = splitAttachedShorts(args, toolRunValueFlags)
	var out installArgs
	sourceNamed := false
	addPkg := func(tok string) {
		// uvx's `ruff@latest` means "the newest release", which is what an
		// unpinned spec already resolves to.
		out.addTarget(m.Ecosystem, strings.TrimSuffix(tok, "@latest"))
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a == "--" {
			if i+1 < len(args) && !sourceNamed {
				addPkg(args[i+1])
			}
			break
		}
		if strings.HasPrefix(a, "-") {
			flag, inlineVal, hasInline := splitFlagValue(a)
			value := inlineVal
			if !hasInline && toolRunValueFlags[flag] && i+1 < len(args) {
				value = args[i+1]
				i++
			}
			switch flag {
			case "--from":
				sourceNamed = true
				addPkg(value)
			case "-w", "--with":
				for _, p := range splitRequirements(value) {
					addPkg(p)
				}
			case "--with-requirements":
				out.ReqFiles = append(out.ReqFiles, value)
			}
			continue
		}
		// The command. Without --from it is also the package; either way the
		// rest of args belongs to the program.
		if !sourceNamed {
			addPkg(a)
		}
		break
	}
	return out
}

// toolRunValueFlags are the options of `uv tool run` / uvx that take a value,
// from `uv tool run --help` (uv 0.11). Keep it complete; see parseToolRun.
var toolRunValueFlags = flagSet("--from", "-w", "--with", "--with-editable",
	"--with-requirements", "-c", "--constraints", "-b", "--build-constraints",
	"--overrides", "--env-file", "--python-platform", "--torch-backend", "--index",
	"--default-index", "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
	"--index-strategy", "--keyring-provider", "-P", "--upgrade-package",
	"--upgrade-group", "--resolution", "--prerelease", "--fork-strategy",
	"--exclude-newer", "--exclude-newer-package", "--no-sources-package",
	"--reinstall-package", "--link-mode", "-C", "--config-setting",
	"--config-settings-package", "--no-build-isolation-package", "--no-build-package",
	"--no-binary-package", "--cache-dir", "--refresh-package", "-p", "--python",
	"--color", "--allow-insecure-host", "--directory", "--project", "--config-file")

// splitRequirements splits uv's comma-separated requirement list (`--with
// a,b>=1,<2`) the way uv does: a comma starts a new requirement unless what
// follows it continues a version specifier. A PEP 440 clause always opens with
// an operator, so a leading digit is a new name (`3to2`), not a continuation.
func splitRequirements(value string) []string {
	// Commas inside extras ("black[d,jupyter]") belong to that requirement,
	// as in uv's CommaSeparatedRequirements.
	var parts []string
	depth, start := 0, 0
	for i, r := range value {
		switch r {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, value[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, value[start:])
	var out []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if len(out) > 0 && (trimmed == "" || strings.ContainsAny(trimmed[:1], "<>=!~")) {
			out[len(out)-1] += "," + part
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// splitFlagValue splits "--flag=value" into ("--flag", "value", true). A flag
// with no inline value returns (flag, "", false).
// splitAttachedShorts rewrites a short option with its value attached
// (`-cfile`, `-ihttps://…`, `-p3.12`), as clap and argparse both read it,
// into the option and the value as two tokens, for every short option in
// valFlags. A token that is not one of those is left alone, so a run of
// boolean shorts (`-qq`) stays what it was. The result is a new slice; args
// is untouched.
func splitAttachedShorts(args []string, valFlags map[string]bool) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) > 2 && a[0] == '-' && a[1] != '-' && valFlags[a[:2]] {
			out = append(out, a[:2], strings.TrimPrefix(a[2:], "="))
			continue
		}
		out = append(out, a)
	}
	return out
}

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
		"--globalconfig", "--tag", "--otp", "-w", "--workspace", "--omit", "--include",
		"--before", "--install-strategy"),
	// pnpm's own, deliberately not npm's: -w is --workspace-root here and takes
	// no value, and --filter is accepted after the verb as well as before it.
	"pnpm": flagSet("--filter", "-F", "--filter-prod", "--dir", "-C", "--registry",
		"--store-dir", "--virtual-store-dir", "--cache-dir", "--loglevel", "--reporter",
		"--resolution-mode", "--use-node-version", "--package-import-method",
		"--workspace-concurrency", "--network-concurrency"),
	"yarn": flagSet("--registry", "--cache-folder", "--modules-folder", "--cwd"),
	// From bun's install/add/update parameters. `-c/--config` and `--catalog`
	// are absent on purpose: their value is optional, so the token after them
	// may be the package.
	"bun": flagSet("--ca", "--cafile", "--cache-dir", "--cwd", "--backend", "--registry",
		"--concurrent-scripts", "--network-concurrency", "--omit", "--linker",
		"--minimum-release-age", "--cpu", "--os", "-F", "--filter"),
	"pip": flagSet("-t", "--target", "-e", "--editable", "-i", "--index-url",
		"--extra-index-url", "-f", "--find-links", "-c", "--constraint", "--prefix",
		"--root", "--src", "--python", "--cache-dir", "--log", "--no-binary",
		"--only-binary", "--platform", "--python-version", "--implementation",
		"--abi", "--progress-bar", "--report", "--upgrade-strategy", "-C", "--config-settings",
		"--global-option", "--root-user-action", "--keyring-provider", "--proxy", "--retries",
		"--timeout", "--exists-action", "--trusted-host", "--cert", "--client-cert",
		"--use-feature", "--use-deprecated",
		// pip 25+/26.
		"--group", "--requirements-from-script", "--build-constraint", "--refresh-package",
		"--all-releases", "--only-final", "--resume-retries", "--uploaded-prior-to"),
	// --with/--without/--only/-E are install/sync's group and extras selectors:
	// unlisted, `poetry sync --with dev` reads "dev" as a named package and
	// checks it instead of scanning the project.
	// `--optional` is absent: it takes a value in poetry 2 but is a switch in
	// poetry 1, where listing it would swallow the package after it.
	"poetry": flagSet("--source", "-G", "--group", "--python", "-P", "--project", "-C",
		"--with", "--without", "--only", "-E", "--extras", "--platform", "--markers"),
	// uv covers both `uv add` (uv-native flags) and `uv pip install` (pip-style flags).
	// `uv sync`/`uv lock` take no packages at all, so an unlisted value there
	// (`uv sync --package api`) turns a project scan into a check of one wrong
	// name; the workspace and group selectors below are listed for that reason.
	// TestUVInstallFlagTablesMatchUV holds it to `uv <command> --help`. `-e` /
	// `--editable` are absent: a path in `uv pip install`, but a switch in `uv
	// add` and `uv tool install`, where listing them swallowed the package.
	"uv": flagSet("-i", "--index-url", "--extra-index-url", "--index", "--default-index",
		"-f", "--find-links", "--cache-dir", "-p", "--python", "--project", "-c",
		"--constraint", "--constraints", "-o", "--override", "--overrides", "--group",
		"--index-strategy", "-t", "--target", "--prefix", "--optional", "--extra",
		"--package", "--no-group", "--only-group", "--tag", "--branch", "--rev",
		"-m", "--marker", "-P", "--upgrade-package", "--reinstall-package",
		"--no-install-package", "--prerelease", "--resolution", "--with-editable",
		"-b", "--build-constraint", "--build-constraints", "--exclude", "--excludes",
		"--bounds", "--script", "--no-extra", "--output-format", "--no-editable-package",
		"--only-binary", "--python-version", "--python-platform", "--torch-backend",
		"--keyring-provider", "--upgrade-group", "--fork-strategy", "--exclude-newer",
		"--exclude-newer-package", "--no-sources-package", "--link-mode", "-C",
		"--config-setting", "--config-settings-package", "--no-build-isolation-package",
		"--no-build-package", "--no-binary-package", "--refresh-package", "--color",
		"--allow-insecure-host", "--directory", "--config-file"),
}

// packageValueFlags name the flags whose value is itself a package being
// installed, so it is checked like a positional one: `uv tool install ruff
// --with ruff-lsp` installs both.
var packageValueFlags = map[string]map[string]bool{
	"uv": flagSet("-w", "--with", "--with-executables-from"),
}

// sourceFlags name the flags whose value is the package actually installed,
// leaving the positional as just the name of what it provides: `uv tool install
// --from 'ruff==0.6.0' ruff`. The value is checked in the positional's place —
// checking the positional too would resolve it to latest and check a release
// that is not being installed.
var sourceFlags = map[string]map[string]bool{
	"uv": flagSet("--from"),
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
	"uv":  flagSet("-r", "--requirement", "--requirements", "--with-requirements"),
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
