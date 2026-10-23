package forward

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/env"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Test seams: expandFn predicts what the named packages bring in; the two
// resolvers below are what it asks.
var (
	expandFn          = expandInstall
	resolveNpmFn      = catalog.ResolveNpmInstall
	resolvePythonFn   = catalog.ResolvePythonInstall
	resolveWithUVFn   = catalog.ResolvePythonInstallWithUV
	npmConfigOmitsFn  = catalog.NpmConfigOmits
	npmConfigGetFn    = catalog.NpmConfigGet
	npxCachedFn       = catalog.NpxCachedTree
	uvCacheDirFn      = catalog.UVCacheDir
	uvConfigNeedsUVFn = catalog.UVConfigShapesResolution
	uvCachedFn        = catalog.UVCachedTree
	uvToolDirFn       = catalog.UVToolDir
	uvInstalledFn     = catalog.UVInstalledTree
)

// A named install used to check exactly the packages typed. `npm install
// express` puts 65 packages on disk, and the forwarder checked one — the gap
// where real supply-chain attacks live, since the planted package is rarely
// the one you asked for (OSS-2481). So before the check, the manager's own
// kind of resolver is asked what the install would bring in, without
// installing anything, and the whole list is checked at once.
//
// It fails open, as the rest of the forwarder does: when the dry run cannot
// be had (no tool, offline, a package that needs building to resolve, the
// resolve timeout) the named packages are checked on their own and one line
// says so. A scanner that breaks `npm install` gets removed.

// checkSet is what a named install checks: the packages named, at the
// release the manager would install, and everything they bring in.
type checkSet struct {
	specs []check.Spec
	// named is how many of the command's packages are in specs; deps how many
	// of their dependencies are.
	named, deps int
	// expanded reports that the dependency tree was resolved, so deps is the
	// real count rather than a tree never looked at.
	expanded bool
	// unresolved is why it was not, for the caller to report once the
	// terminal is free: nothing here prints.
	unresolved error
}

// coverage states what a verdict covered, for the verbose clean line: a count
// alone read the same whether the tree was resolved or not.
func (c checkSet) coverage() string {
	switch {
	case c.named == 0 && c.deps == 0:
		return ""
	case c.expanded:
		return fmt.Sprintf(" (%d requested + %d dependencies)", c.named, c.deps)
	case c.deps > 0:
		return fmt.Sprintf(" (%d requested + %d dependencies from an earlier run; dependencies not resolved)", c.named, c.deps)
	default:
		return fmt.Sprintf(" (%d requested; dependencies not resolved)", c.named)
	}
}

// resolveNamed turns the packages named on a command line into the set to
// check. The tree they bring in is resolved first and every package in it is
// checked at the release the manager picked — the named ones included, which
// is a better answer than the registry's "latest" guess. When the resolution
// fails, the names alone are resolved as before. A tool run (`npx cowsay`)
// is a named install of one package into the tool's own cache, and is
// expanded the same way.
//
// A dependency the project's lockfile already pinned is not what this
// install brings in, so it is left to the project scan. Trusted sources
// apply to the whole tree, now that the resolver has said where each
// package comes from.
func resolveNamed(ctx context.Context, m *Manager, opts Options, start int, parsed installArgs,
	resolve func(context.Context, string, string, string) (string, error)) checkSet {
	var set checkSet
	tree, err := expandFn(ctx, m, opts.Args, start, parsed)
	set.expanded, set.unresolved = err == nil, err

	found := make([]bool, len(parsed.Specs))
	for _, r := range tree {
		i := namedIndex(m.Ecosystem, parsed.Specs, r.Name)
		if i < 0 && r.Locked {
			continue
		}
		var regs []string
		if r.Registry != "" {
			regs = []string{r.Registry}
		}
		if opts.Trust.Trusts(m.Ecosystem, r.Name, regs) {
			warn.Add(ctx, scan.TrustedEntry(m.Ecosystem, r.Name, r.Version))
			if i >= 0 {
				found[i] = true // not looked up publicly below either
			}
			continue
		}
		if i >= 0 {
			if !found[i] {
				set.named++
			}
			found[i] = true
		} else {
			set.deps++
		}
		set.specs = append(set.specs, check.Spec{Ecosystem: m.Ecosystem, Name: r.Name, Version: r.Version})
	}

	// A name the tree answered for is not resolved again — unless the
	// tree is only what an earlier run left on disk (err != nil), which
	// says nothing about what resolves today: `npx tool@latest` with
	// tool@1.0.0 cached may fetch 2.0.0, so the names are resolved as well,
	// each counted once and a release already in the set not repeated. A
	// cached copy's trusted provenance covers that copy, not today's
	// request, so it does not stand in for the lookup either; a name
	// trusted by scope never reached this point (dropTrusted).
	var missing []check.Spec
	for i, s := range parsed.Specs {
		if !found[i] || err != nil {
			missing = append(missing, s)
		}
	}
	have := map[check.Spec]bool{}
	for _, s := range set.specs {
		have[s] = true
	}
	for _, r := range resolveSpecs(ctx, resolve, missing) {
		if have[r] {
			continue
		}
		have[r] = true
		if i := namedIndex(m.Ecosystem, parsed.Specs, r.Name); i < 0 || !found[i] {
			set.named++
			if i >= 0 {
				found[i] = true
			}
		}
		set.specs = append(set.specs, r)
	}
	return set
}

// reportUnexpanded says, in one line even when quiet, that the install's
// dependencies were not resolved. Fail open, out loud: a clean verdict on
// the names alone must not read as a verdict on the install. The resolver's
// own output goes behind the verbose gutter, as a cataloger's does. deps
// is what an earlier run's tree on disk still contributed (a tool run's
// cache or installed environment), which the line then claims and no more.
//
// Callers print it only once the terminal is theirs: after the progress
// animation has stopped, and in passive mode after the manager has exited,
// never from beside either.
func reportUnexpanded(ctx context.Context, specs []check.Spec, err error, deps int) {
	headline, detail := catalog.ResolveFailure(err)
	covered := "the named packages only"
	if deps > 0 {
		covered = fmt.Sprintf("the named packages and %d dependencies from an earlier run", deps)
	}
	line := fmt.Sprintf("could not resolve the dependencies of %s (%s); checking %s",
		joinNames(specs), headline, covered)
	if env.Verbose() && len(detail) > 0 {
		warn.Add(ctx, warn.Entry{Class: "resolve-install", One: line, Many: "%d installs' dependencies could not be resolved",
			Item: line, Detail: detail, DetailLabel: "resolver"})
		return
	}
	fmt.Fprintf(errOut, "ossprey: warning: %s\n", line)
}

// namedIndex finds the command-line package a resolved name belongs to, or
// -1 for a dependency. PyPI names compare canonically (PEP 503); npm names
// are exact.
func namedIndex(ecosystem string, specs []check.Spec, name string) int {
	for i, s := range specs {
		if ecosystem == "pypi" {
			if canonicalPyPI(s.Name) == canonicalPyPI(name) {
				return i
			}
		} else if s.Name == name {
			return i
		}
	}
	return -1
}

var pep503Separators = regexp.MustCompile(`[-_.]+`)

func canonicalPyPI(name string) string {
	return pep503Separators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

func joinNames(specs []check.Spec) string {
	names := make([]string, 0, len(specs))
	for _, s := range specs {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}

// expandInstall asks the manager's own kind of resolver what installing the
// named packages brings in. args is the whole command line and start where
// its packages begin; parsed is their classification.
//
// A nil tree with no error means there is nothing beyond the names to look
// at: an install told not to resolve dependencies.
//
// A tool run (`npx cowsay moo`, `uvx ruff check .`) fetches its package into
// the tool's own cache, never into the project, so it resolves with no
// project context; and everything after the command is the program's own
// argv, so none of it is read as a flag for the resolver.
func expandInstall(ctx context.Context, m *Manager, args []string, start int, parsed installArgs) ([]catalog.Resolved, error) {
	rest := args[start:]
	tokens := specTokens(m, parsed)
	switch m.Ecosystem {
	case "npm":
		if parsed.ToolRun {
			// Everything npm's own parse attributed to npm, and nothing from
			// the program's argv.
			flags := append([]string(nil), parsed.NpmFlags...)
			if parsed.Registry != "" {
				flags = append(flags, "--registry", parsed.Registry)
			}
			if parsed.Userconfig != "" {
				flags = append(flags, "--userconfig", absPath(parsed.Userconfig))
			}
			// A relative npm_config_userconfig or _globalconfig is resolved
			// where npm runs; the dry run and the probes run elsewhere.
			flags = append(flags, npmEnvConfigFlags(flags)...)
			// The flags that make `npm config` read what this command
			// reads: its config files and location, asked from the
			// configuration's directory.
			configDir := npmConfigDirFor(parsed.NpmGlobal, parsed.NpmPrefix, parsed.NpmWorkspacesOff)
			configFlags := slices.Concat(flags, npmLocationFlags(parsed.NpmGlobal, parsed.NpmPrefix, parsed.NpmWorkspacesOff, configDir))
			// The cache the run reads, found once for the dry run and the
			// npx-cache lookup. A path npm resolves against the directory it
			// runs in (a relative npm_config_cache, or a relative cache= in
			// an .npmrc) is not the same from the dry run's scratch
			// directory, so the dry run is told it absolutely.
			var cache string
			if m.Bin == "npm" || m.Bin == "npx" {
				var moved bool
				if cache, moved = npmCacheDir(ctx, parsed.NpmCache, configFlags); moved {
					flags = append(flags, "--cache", cache)
				}
			}
			tree, err := resolveNpmFn(ctx, "", configDir, tokens, flags)
			if err == nil && len(tree) > 0 {
				// The omit policy shapes a fresh install only: a reused npx
				// installation is not pruned, so what it holds stays checked.
				tree = npmOmit(tree, npmEffectiveOmits(ctx, configFlags))
			}
			if m.Bin == "npm" || m.Bin == "npx" {
				// npm may reuse what an earlier run left in its npx cache,
				// dependencies and all, rather than what resolves today. That
				// tree is on disk whether or not today's dry run succeeds,
				// and a failed one may be exactly why npm reuses it, so it
				// is read either way and returned beside the error.
				tree = withNpxCached(ctx, tree, parsed, cache)
			}
			return tree, err
		}
		// npm reads its options on either side of the verb (`npm --offline
		// install x`), so the whole line is read, not rest.
		flags := npmResolveFlags(m, args)
		if m.Bin == "npm" {
			// A relative npm_config_cache, _userconfig or _globalconfig is
			// resolved where npm runs, and the dry run runs in a copy of
			// the project elsewhere.
			flags = append(flags, npmEnvCacheFlag(flags)...)
			flags = append(flags, npmEnvConfigFlags(flags)...)
		}
		configDir := npmConfigDir(m, args)
		tree, err := resolveNpmFn(ctx, npmProjectDir(m, args), configDir, tokens, flags)
		if err != nil || m.Bin != "npm" || len(tree) == 0 {
			return tree, err
		}
		// The omit policy is npm's own reading of the whole command and its
		// configuration; the flag list above is only what the dry run is
		// told, and npm reads the same flags to answer, from the
		// configuration's directory.
		a := parseNpmArgv(args)
		return npmOmit(tree, npmEffectiveOmits(ctx, slices.Concat(flags, npmLocationFlags(a.global(), a.prefix(), a.workspacesOff(), configDir)))), nil
	case "pypi":
		// A short option's value may be attached (`-ihttps://…`); read it
		// as the resolver will, from a copy, so args stays what the real
		// command gets.
		rest = splitAttachedShorts(rest, pythonOptionFlags(m), clapEquals(m))
		// uv's global options sit before the verb (`uv --config-file x tool
		// run …`), outside rest; the ones that change the resolution come
		// along, and can themselves make the command uv-only.
		if parsed.ToolRun {
			// No project: uv's tool commands read no project configuration,
			// so the resolver runs where there is none (dir ""), and paths in
			// the flags are made absolute — against the directory the run
			// changes to, if any — to survive the move.
			lead := toolRunLead(rest)
			base := uvDir(append(uvGlobalArgs(m, args), lead...), uvValueFlags())
			global, globalNeedsUV := uvGlobalFlags(m, args, base, true)
			uvFlags := append(global, toolRunLeadingFlags(rest, base)...)
			// UV_CONFIG_FILE names configuration pip does not read, and a
			// relative one is read where the run runs: the resolver and the
			// probes are told the file by its absolute path, as a flag,
			// which also keeps the run on the uv-only path.
			opts := slices.Concat(uvGlobalArgs(m, args), lead)
			envConfig := uvEnvConfigFlag(opts, base)
			uvFlags = append(uvFlags, envConfig...)
			opts = append(opts, envConfig...)
			// So are the files uv's path-valued variables name (UV_CONSTRAINT,
			// UV_OVERRIDE, …): relative to where the run runs, which in
			// scratch would be the resolver's own requirements file.
			uvFlags = append(uvFlags, uvEnvPathFlags(opts, base)...)
			// The cache the run reads, found once for the resolver and the
			// cached-environment lookup. A path uv reads against the
			// directory it runs in (a relative UV_CACHE_DIR, or a relative
			// cache-dir in its configuration) is one the resolver's scratch
			// directory does not have, so the resolver is told it absolutely;
			// an absolute path reads the same from anywhere.
			var cache string
			if uvReadsCache(opts) {
				var moved bool
				if cache, moved = uvCacheDir(ctx, opts, base); moved {
					uvFlags = append(uvFlags, "--cache-dir", cache)
				}
			}
			// --with-requirements files are installed into the same
			// environment, so they resolve together with the packages: a
			// release that satisfies each alone may not satisfy both.
			tokens = slices.Concat(tokens, reqFileTokens(parsed.ReqFiles, base))
			var tree []catalog.Resolved
			var err error
			// Configuration outside the line — a UV_INDEX_URL, an index in
			// the user's uv.toml — shapes the real run as a flag would, and
			// pip reads none of it: such a run resolves with uv or not at all.
			if globalNeedsUV || needsUV(lead, toolRunValueFlags) || len(envConfig) > 0 || uvConfigNeedsUVFn(opts, "") {
				tree, err = resolveWithUVFn(ctx, "", tokens, uvFlags)
			} else {
				tree, err = resolvePythonFn(ctx, "", tokens, uvFlags, toolRunPipFlags(rest, base))
			}
			// uv may reuse a tool environment it cached for an earlier run,
			// dependencies and all, rather than what resolves today; and a
			// bare request runs the installed tool without resolving at
			// all. Both are on disk whether or not today's resolution
			// succeeds, so they are read either way, beside the error.
			return withUVCached(ctx, tree, parsed, opts, base, cache), err
		}
		if hasFlag(rest, "--no-deps") {
			return nil, nil
		}
		dir := "."
		if m.Bin == "uv" {
			dir = uvDir(args, uvValueFlags())
		}
		global, globalNeedsUV := uvGlobalFlags(m, args, dir, false)
		uvFlags := append(global, absFlagValues(uvResolveFlags(m, rest), flagSet("--project"), dir)...)
		if m.Bin == "uv" {
			// Configuration UV_CONFIG_FILE names is uv's alone: pip would
			// resolve without it, from indexes the run does not use.
			envConfig := uvEnvConfigFlag(args, dir)
			uvFlags = append(uvFlags, envConfig...)
			if globalNeedsUV || needsUV(rest, valueFlags[m.Bin]) || len(envConfig) > 0 || uvConfigNeedsUVFn(args, dir) {
				return resolveWithUVFn(ctx, dir, tokens, uvFlags)
			}
		}
		return resolvePythonFn(ctx, dir, tokens, uvFlags, pipResolveFlags(m, rest))
	}
	return nil, nil
}

// uvGlobalPass are uv's global options (valid before the verb) that change
// what a resolve finds: which configuration it reads, and whether it may go
// to the network. --directory and --project change where it runs instead;
// see uvDir.
var uvGlobalPass = flagSet("--config-file", "--no-config", "--offline", "--allow-insecure-host", "--project",
	"--cache-dir", "-n", "--no-cache", "--refresh", "--refresh-package", "--reinstall", "--reinstall-package")

// uvRenames are uv flags the resolver reads under another name: --reinstall
// "implies --refresh" (uv's own words), and the refresh is what changes the
// resolution.
var uvRenames = map[string]string{"--reinstall": "--refresh", "--reinstall-package": "--refresh-package"}

// toolRunNoPass are uvGlobalPass flags a tool run must not pass on: uvx
// reads no project configuration, so handing --project to `uv pip compile`
// would make it read one the real command does not.
var toolRunNoPass = flagSet("--project")

func without(set, drop map[string]bool) map[string]bool {
	out := union(set)
	for k := range drop {
		delete(out, k)
	}
	return out
}

// uvGlobalArgs are the tokens before a uv command's verb, where its global
// options sit, attached short values split; uvx and pip have no such part.
// A copy, never a prefix slice of args: a caller appends to it, and an
// append into args's own backing array would overwrite the verb and
// arguments the real uv is about to get.
func uvGlobalArgs(m *Manager, args []string) []string {
	if m.Bin != "uv" {
		return nil
	}
	if idx := verbIndex("uv", args); idx > 0 {
		return splitAttachedShorts(args[:idx], globalValueFlags["uv"], true)
	}
	return nil
}

// pythonOptionFlags are every value-taking option a Python manager's parser
// knows — its resolution flags, requirements-file, package and source
// flags, and for uv the tool-run flags — the set splitAttachedShorts needs
// to tell an attached short value from a token owed to the option before.
func pythonOptionFlags(m *Manager) map[string]bool {
	sets := []map[string]bool{valueFlags[m.Bin], requirementFileFlags[m.Bin], packageValueFlags[m.Bin], sourceFlags[m.Bin]}
	if m.Bin == "uv" || m.Bin == "uvx" {
		sets = append(sets, valueFlags["uv"], requirementFileFlags["uv"], packageValueFlags["uv"], sourceFlags["uv"], toolRunValueFlags)
	}
	return union(sets...)
}

// withNpxCached adds to a fresh resolution of a tool run whatever an earlier
// run of the same packages left in npm's npx cache: npm reuses that
// installation when the package it holds still satisfies the request, with
// the dependencies resolved back then, so the run may execute either tree.
// A release both report is one sighting with two provenances, merged so
// that neither can hide the other (mergeSighting). An unreadable cache adds
// nothing.
func withNpxCached(ctx context.Context, tree []catalog.Resolved, parsed installArgs, cache string) []catalog.Resolved {
	cached, err := npxCachedFn(cache, parsed.NpxPackages)
	if err != nil || len(cached) == 0 {
		return tree
	}
	seen := map[string]int{}
	for i, r := range tree {
		seen[r.Name+"@"+r.Version] = i
	}
	for _, r := range cached {
		if i, ok := seen[r.Name+"@"+r.Version]; ok {
			tree[i] = mergeSighting(tree[i], r)
			continue
		}
		tree = append(tree, r)
	}
	return tree
}

// withUVCached adds to a fresh resolution of a uv tool run whatever uv may
// run instead of it: a tool environment cached by an earlier run holding
// the named packages, which uv reuses when it satisfies the request, and
// the environment `uv tool install` keeps for a bare request
// (parsed.InstalledTool), which uvx runs as installed. Either carries the
// dependencies resolved back then. opts are uv's options for the run,
// before and after the verb: a run that reads no cache (--no-cache) or
// resolves afresh (--refresh, --reinstall) reuses no cached environment,
// and --cache-dir names the cache, relative to base, the directory the
// run changes to. An unreadable cache or tool directory adds nothing.
func withUVCached(ctx context.Context, tree []catalog.Resolved, parsed installArgs, opts []string, base, cache string) []catalog.Resolved {
	if uvReadsCache(opts) && cache != "" {
		// A requirement with a marker is installed only where the marker
		// holds, which the resolver decides; an environment is not asked
		// to hold it — unless the same package is also requested without
		// one (`--with 'rich; sys_platform == "win32"' --with rich`), in
		// which case it is installed regardless.
		want := map[string]string{}
		for _, s := range parsed.Specs {
			toks := parsed.Tokens[s]
			conditional := func(tok string) bool { return strings.Contains(tok, ";") }
			if len(toks) > 0 && !slices.ContainsFunc(toks, func(tok string) bool { return !conditional(tok) }) {
				continue
			}
			want[canonicalPyPI(s.Name)] = s.Version
		}
		if cached, err := uvCachedFn(cache, want); err == nil {
			tree = unionSightings(tree, cached)
		}
	}
	// The cache flags govern the cache; an installed tool runs regardless.
	if parsed.InstalledTool != "" {
		if installed, err := uvInstalledFn(uvToolDir(ctx, opts, base), parsed.InstalledTool); err == nil {
			tree = unionSightings(tree, installed)
		}
	}
	return tree
}

// uvReadsCache says whether a uv command may reuse what its cache holds:
// not with --no-cache (a temporary directory instead), nor when --refresh
// or --reinstall resolves afresh.
func uvReadsCache(opts []string) bool {
	for _, a := range opts {
		if a == "-n" || a == "--no-cache" || a == "--refresh" || a == "--reinstall" {
			return false
		}
	}
	// UV_NO_CACHE is --no-cache from the environment (verified: uv reports
	// no_cache with it set); the installed-tool lookup is not governed by
	// it, and stays with the caller.
	return !envTrue("UV_NO_CACHE")
}

// envTrue reads a boolean variable as clap does: set to anything but an
// explicit false.
func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}

// uvEnvPathVars are uv's variables naming files, with the flag each is
// equivalent to (from `uv tool run --help`): space-separated lists of
// paths, read against the directory uv runs in.
var uvEnvPathVars = []struct {
	env, flag string
	aliases   []string
}{
	{"UV_CONSTRAINT", "--constraints", []string{"-c", "--constraint"}},
	{"UV_OVERRIDE", "--overrides", []string{"--override"}},
	{"UV_BUILD_CONSTRAINT", "--build-constraints", []string{"-b", "--build-constraint"}},
	{"UV_FIND_LINKS", "--find-links", []string{"-f"}},
	{"UV_PYTHON", "--python", []string{"-p"}},
}

// flagPresent reports whether any of the flags is among opts, as a token
// or with an attached value (`--constraints=c.txt`).
func flagPresent(opts []string, flags ...string) bool {
	for _, a := range opts {
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}

// uvEnvPathFlags names the files uv's path-valued variables name by their
// absolute paths, as the equivalent flags, for a resolver that runs in a
// scratch directory: uv reads a relative value against the directory it
// runs in (verified: uvx and `uv pip compile` both honour UV_CONSTRAINT,
// and `--directory sub` reads sub/c.txt), and in scratch
// UV_CONSTRAINT=requirements.txt would name the resolver's own input. A
// flag on the line already replaces the variable, as the flag does for
// uv, and a variable whose every entry is absolute or a URL reads the
// same from anywhere. Each entry becomes one flag, since the flag replaces
// the whole variable.
func uvEnvPathFlags(opts []string, base string) []string {
	var out []string
	for _, v := range uvEnvPathVars {
		if flagPresent(opts, append([]string{v.flag}, v.aliases...)...) {
			continue
		}
		value := os.Getenv(v.env)
		if value == "" {
			continue
		}
		// Every entry of a file- or directory-valued variable is a path
		// unless it is a URL (`constraints`, `constraints.lock` and
		// `wheels` are paths); UV_PYTHON also takes a version or a name,
		// so only a path-shaped value of it is one.
		entries := strings.Fields(value)
		isPath := func(e string) bool { return !strings.Contains(e, "://") }
		if v.env == "UV_PYTHON" {
			entries = []string{strings.TrimSpace(value)}
			isPath = looksLikePath
		}
		moved := false
		for _, e := range entries {
			if isPath(e) && !filepath.IsAbs(e) {
				moved = true
			}
		}
		if !moved {
			continue
		}
		for _, e := range entries {
			if isPath(e) {
				e = absIn(base, e)
			}
			out = append(out, v.flag, e)
		}
	}
	return out
}

// looksLikePath says a UV_PYTHON value is an interpreter path rather than
// a version or a name.
func looksLikePath(e string) bool {
	if strings.Contains(e, "://") {
		return false
	}
	return strings.ContainsAny(e, `/\`) || strings.HasPrefix(e, ".")
}

// unionSightings adds to tree the releases in extra it does not name, and
// merges those it does (mergeSighting). PyPI names match as PyPI matches
// them, which is also fine for npm's, where the spelling is the name.
func unionSightings(tree, extra []catalog.Resolved) []catalog.Resolved {
	if len(extra) == 0 {
		return tree
	}
	seen := map[string]int{}
	for i, r := range tree {
		seen[canonicalPyPI(r.Name)+"@"+r.Version] = i
	}
	for _, r := range extra {
		if i, ok := seen[canonicalPyPI(r.Name)+"@"+r.Version]; ok {
			tree[i] = mergeSighting(tree[i], r)
			continue
		}
		seen[canonicalPyPI(r.Name)+"@"+r.Version] = len(tree)
		tree = append(tree, r)
	}
	return tree
}

// uvEnvConfigFlag names the file UV_CONFIG_FILE names as --config-file for
// the resolver and the probes, which run elsewhere than the real command: a
// relative value is read against the directory uv runs in (verified), so
// it is made absolute against the run's directory first. The flag is also
// what keeps the run on the uv-only path, since pip reads none of that
// configuration and would resolve from indexes the run does not use. A
// --config-file or --no-config on the line already decides the file.
func uvEnvConfigFlag(opts []string, base string) []string {
	for _, a := range opts {
		if a == "--no-config" || a == "--config-file" || strings.HasPrefix(a, "--config-file=") {
			return nil
		}
	}
	v := os.Getenv("UV_CONFIG_FILE")
	if v == "" {
		return nil
	}
	return []string{"--config-file", absIn(base, v)}
}

// uvToolDir is where uv keeps installed tools for this run: UV_TOOL_DIR,
// else what uv says (`uv tool dir` with the run's configuration
// selectors), else uv's platform default when it cannot be asked, a
// relative answer resolved against base.
func uvToolDir(ctx context.Context, opts []string, base string) string {
	if v := os.Getenv("UV_TOOL_DIR"); v != "" {
		return absIn(base, v)
	}
	selectors := absFlagValues(pickFlags(opts, uvValueFlags(), uvCacheSelectors, nil), pythonPathFlags, base)
	if v, err := uvToolDirFn(ctx, selectors); err == nil && v != "" {
		return absIn(base, v)
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, "uv", "tools")
		}
		return ""
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "uv", "tools")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "uv", "tools")
}

// uvCacheDir is where uv keeps its cache for this run: --cache-dir among
// opts, else UV_CACHE_DIR, else what uv says (`uv cache dir` with the run's
// own configuration selectors, --config-file and --no-config, since a
// cache-dir in an explicitly named file is where uv reuses from), else uv's
// platform default when it cannot be asked. Every relative answer is
// uv's, resolved against base, the directory the run changes to: for
// `uvx --directory sub --cache-dir c` uv uses sub/c (verified, as is a
// relative cache-dir in a config file, which uv resolves against the
// directory it runs in, not the file's). moved says the path is one uv
// reads against the directory it runs in — a relative UV_CACHE_DIR, or a
// relative answer — so a resolver running elsewhere must be told it.
func uvCacheDir(ctx context.Context, opts []string, base string) (dir string, moved bool) {
	for i, a := range opts {
		if flag, value, inline := splitFlagValue(a); flag == "--cache-dir" {
			if inline {
				return absIn(base, value), false
			}
			if i+1 < len(opts) {
				return absIn(base, opts[i+1]), false
			}
		}
	}
	if v := os.Getenv("UV_CACHE_DIR"); v != "" {
		return absIn(base, v), !filepath.IsAbs(v)
	}
	selectors := absFlagValues(pickFlags(opts, uvValueFlags(), uvCacheSelectors, nil), pythonPathFlags, base)
	if v, err := uvCacheDirFn(ctx, selectors); err == nil && v != "" {
		return absIn(base, v), !filepath.IsAbs(v)
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", false
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "uv", "cache"), false
	}
	return filepath.Join(dir, "uv"), false
}

// uvCacheSelectors are the uv options that change which configuration
// names the cache, and so travel to `uv cache dir`.
var uvCacheSelectors = flagSet("--config-file", "--no-config")

// mergeSighting folds two reports of the same release into one that is
// checked unless both would be left alone: a dependency kind survives only
// when both carry it (the install omits the release only if it omits every
// copy), the registry only when both agree (a trusted fresh fetch must not
// cover a cached copy fetched publicly, and no registry means checked), and
// the project lock covers it only if both say so.
func mergeSighting(a, b catalog.Resolved) catalog.Resolved {
	if a.Registry != b.Registry {
		a.Registry = ""
	}
	a.Locked = a.Locked && b.Locked
	a.Dev = a.Dev && b.Dev
	a.Optional = a.Optional && b.Optional
	a.DevOptional = a.DevOptional && b.DevOptional
	a.Peer = a.Peer && b.Peer
	a.Copies = append(append([]catalog.DependencyKinds(nil), a.Copies...), b.Copies...)
	return a
}

// npmCacheDir is where npm keeps its cache for this run: --cache as parsed,
// npm_config_cache, else what npm's configuration files say (`npm config get
// cache`, read with the command's own config-file and location flags, which
// also yields npm's platform default), else that default worked out here
// when npm cannot be asked.
func npmCacheDir(ctx context.Context, flag string, configFlags []string) (dir string, moved bool) {
	if flag != "" {
		return absPath(expandHome(flag)), false
	}
	for _, name := range []string{"npm_config_cache", "NPM_CONFIG_CACHE"} {
		if v := os.Getenv(name); v != "" {
			v = expandHome(v)
			return absPath(v), !filepath.IsAbs(v)
		}
	}
	if v, err := npmConfigGetFn(ctx, ".", "cache", configFlags); err == nil && v != "" {
		// npm answers absolutely, resolved where it was asked; a relative
		// cache= in an .npmrc would resolve elsewhere from scratch.
		return absPath(expandHome(v)), true
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, "npm-cache"), false
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "npm-cache"), false
	}
	return filepath.Join(home, ".npm"), false
}

// npmEnvConfigFlags name a relative npm_config_userconfig or
// npm_config_globalconfig absolutely, as the flag, for a dry run and the
// probes that run elsewhere than the command: nopt resolves the variable
// against the directory npm runs in (verified: `npm config list -l` answers
// under the cwd), so from scratch the dry run would read another file, or
// none, and resolve against the default registry. A flag among flags
// already names the file, and an absolute path reads the same from
// anywhere.
func npmEnvConfigFlags(flags []string) []string {
	var out []string
	for _, c := range []struct {
		flag string
		envs []string
	}{
		{"--userconfig", []string{"npm_config_userconfig", "NPM_CONFIG_USERCONFIG"}},
		{"--globalconfig", []string{"npm_config_globalconfig", "NPM_CONFIG_GLOBALCONFIG"}},
	} {
		if flagPresent(flags, c.flag) {
			continue
		}
		for _, name := range c.envs {
			if v := os.Getenv(name); v != "" {
				if v = expandHome(v); !filepath.IsAbs(v) {
					out = append(out, c.flag, absPath(v))
				}
				break
			}
		}
	}
	return out
}

// npmEnvCacheFlag names a relative npm_config_cache absolutely, as --cache,
// for a dry run that runs elsewhere than the command: nopt resolves the
// variable against the directory npm runs in (verified: `npm config list
// -l` answers under the cwd). A --cache among flags already names it, and
// an absolute path reads the same from anywhere.
func npmEnvCacheFlag(flags []string) []string {
	for _, f := range flags {
		if f == "--cache" || strings.HasPrefix(f, "--cache=") {
			return nil
		}
	}
	for _, name := range []string{"npm_config_cache", "NPM_CONFIG_CACHE"} {
		if v := os.Getenv(name); v != "" {
			if v = expandHome(v); filepath.IsAbs(v) {
				return nil
			}
			return []string{"--cache", absPath(v)}
		}
	}
	return nil
}

// npmLocationFlags are the flags that make `npm config` read the same
// project configuration as the command, from the command's own directory:
// global mode reads none; --prefix names the project — the command's, else
// the configuration directory the command would discover (configDir),
// since named explicitly npm neither walks for it nor, from a workspace
// member, fails with ENOWORKSPACES (verified) — and --workspaces=false
// stops npm at the nearest package.json rather than a workspace root. The
// probes stay in the cwd because a relative path in the configuration
// (`cache=./cache`) is resolved against it, not the file's directory
// (verified: from a subdirectory npm answers sub/cache).
func npmLocationFlags(global bool, prefix string, workspacesOff bool, configDir string) []string {
	var out []string
	switch {
	case global:
		out = []string{"-g"}
	case prefix != "":
		out = []string{"--prefix", absPath(prefix)}
	case configDir != "":
		out = []string{"--prefix", absPath(configDir)}
	}
	if workspacesOff {
		out = append(out, "--workspaces=false")
	}
	return out
}

// npmEffectiveOmits is npm's own omit policy for the install: the kinds
// `npm config get omit` reports for the dry run's flags and location, which
// is the command line, the environment and every .npmrc read together,
// include winning over omit and optional=false counted as an omit. One
// subprocess, asked only for a fresh tree with something to prune; when
// npm cannot answer nothing is dropped, which errs toward checking.
func npmEffectiveOmits(ctx context.Context, flags []string) map[string]bool {
	kinds, err := npmConfigOmitsFn(ctx, ".", flags)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, kind := range kinds {
		out[kind] = true
	}
	return out
}

// npmOmit drops from a resolved npm tree the dependencies the install
// leaves out under npm's omit policy (the kinds in omits: dev, optional,
// peer), which the lockfile records regardless. A devOptional package is
// reached both ways and goes only when both are omitted. Checking an
// omitted package would block a run on something it never installs.
func npmOmit(tree []catalog.Resolved, omits map[string]bool) []catalog.Resolved {
	if len(omits) == 0 {
		return tree
	}
	kept := tree[:0:0]
	for _, r := range tree {
		if npmOmitted(r, omits) {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

// npmOmitted says the install leaves the release out: every copy of it is
// of a kind the policy omits. The copies are judged one by one (a dev-only
// copy beside an optional-only one goes under --omit=dev --omit=optional,
// which their ANDed kinds could not say); a release without them is judged
// by its flags.
func npmOmitted(r catalog.Resolved, omits map[string]bool) bool {
	omitted := func(k catalog.DependencyKinds) bool {
		return k.Dev && omits["dev"] || k.Optional && omits["optional"] || k.Peer && omits["peer"] ||
			k.DevOptional && omits["dev"] && omits["optional"]
	}
	if len(r.Copies) == 0 {
		return omitted(catalog.DependencyKinds{Dev: r.Dev, Optional: r.Optional, DevOptional: r.DevOptional, Peer: r.Peer})
	}
	for _, k := range r.Copies {
		if !omitted(k) {
			return false
		}
	}
	return true
}

// uvGlobalFlags are the uvGlobalPass flags given before a uv command's
// verb (less toolRunNoPass for a tool run), with paths made absolute
// against base, and whether one of them makes the command uv-only.
func uvGlobalFlags(m *Manager, args []string, base string, toolRun bool) ([]string, bool) {
	lead := uvGlobalArgs(m, args)
	valFlags := globalValueFlags["uv"]
	allowed := uvGlobalPass
	if toolRun {
		allowed = without(uvGlobalPass, toolRunNoPass)
	}
	return absFlagValues(pickFlags(lead, valFlags, allowed, uvRenames), pythonPathFlags, base),
		needsUV(lead, valFlags)
}

// uvDir is the directory a uv command runs in: the last --directory among
// the tokens given, which uv changes to before anything else, so the
// command's relative paths and a project command's configuration are read
// there; else the working directory. For a tool run only uv's own tokens
// are passed, never the program's. --project is not a directory change: it
// names where a project is discovered, and is passed on as a flag.
func uvDir(tokens []string, valFlags map[string]bool) string {
	dir := "."
	for i := 0; i < len(tokens); i++ {
		flag, value, hasInline := splitFlagValue(tokens[i])
		if !hasInline && valFlags[flag] && i+1 < len(tokens) {
			value = tokens[i+1]
			i++
		}
		if flag == "--directory" && value != "" {
			dir = absIn(dir, value)
		}
	}
	return dir
}

// uvValueFlags is every uv flag that takes a value, before or after the verb.
var uvValueFlags = func() map[string]bool {
	return union(globalValueFlags["uv"], valueFlags["uv"], toolRunValueFlags)
}

// toolRunLeadingFlags are the resolver flags of a `uvx` / `uv tool run`
// command: those before the command, read with the tool run's own value
// table so a value is never taken for the command, and kept only when uv's
// resolver reads them the same way (`uvx --index-url … ruff`).
func toolRunLeadingFlags(rest []string, base string) []string {
	allowed := without(union(pythonCommonFlags, uvOnlyFlags), toolRunNoPass)
	return absFlagValues(pickFlags(toolRunLead(rest), toolRunValueFlags, allowed, uvRenames), pythonPathFlags, base)
}

// toolRunPipFlags are the same leading flags as pip's resolver reads them,
// for a host with no working uv: the index a uvx run names must reach the
// fallback too, or it would resolve against a different one. A flag pip
// cannot honour never does; see needsUV.
func toolRunPipFlags(rest []string, base string) []string {
	return absFlagValues(pickFlags(toolRunLead(rest), toolRunValueFlags, pipFallbackFlags, pipFallbackRenames), pythonPathFlags, base)
}

// uvOnlyResolution are the uv flags that change which release is picked and
// that pip's dry run cannot be given. --index and --extra-index-url add an
// index: uv takes a package from the first index that has it, pip the best
// version across every index, so pip could check a release uv does not
// install, and a name that exists only on the private index would resolve
// publicly, where a squatted copy may be waiting. --overrides, --resolution,
// --prerelease, --exclude-newer, --index-strategy and the interpreter flags
// have no pip spelling with the same effect. A uv command carrying any of
// them is resolved by uv alone, or not at all.
var uvOnlyResolution = flagSet("--index", "--extra-index-url", "--overrides", "--resolution",
	"--prerelease", "--exclude-newer", "--exclude-newer-package", "--index-strategy",
	"-p", "--python", "--python-platform", "--config-file", "--offline",
	// Building from source is what pip's dry run is told never to do
	// (--only-binary=:all:), so it would pick the newest release with a
	// wheel where uv builds the newest of all.
	"--no-binary", "--no-binary-package",
	// The PyTorch index uv picks for the backend; pip has no such switch.
	"--torch-backend",
	// The cache uv reads offline or prefers, and whether it reads or
	// refreshes it, decide what it resolves against; pip has no such cache.
	"--cache-dir", "-n", "--no-cache", "--refresh", "--refresh-package", "--reinstall", "--reinstall-package")

// needsUV reports whether a uv command carries a flag only uv can honour
// (uvOnlyResolution).
func needsUV(rest []string, valFlags map[string]bool) bool {
	return len(pickFlags(rest, valFlags, uvOnlyResolution, nil)) > 0
}

// pipFallbackFlags are the uv flags pip's dry run reads the same way, for a
// uv command resolved by pip, with pipFallbackRenames giving pip's spelling:
// uv's --default-index replaces the default index, as pip's --index-url
// does, and uv's --constraints is pip's --constraint.
var pipFallbackFlags = func() map[string]bool {
	out := union(pythonCommonFlags, flagSet("--default-index", "--constraints"))
	for f := range uvOnlyResolution {
		delete(out, f)
	}
	return out
}()

var pipFallbackRenames = map[string]string{"--default-index": "--index-url", "--constraints": "--constraint"}

// pythonPathFlags take a file or directory, which the resolver must be able
// to find from wherever it runs. --find-links may be a URL instead, which
// absFlagValues leaves alone; -p/--python is a path only when it looks like
// one (`.venv/bin/python`), else a version or a name (`3.12`, `pypy`).
var pythonPathFlags = flagSet("-c", "--constraint", "--constraints", "--overrides",
	"-f", "--find-links", "--config-file", "-p", "--python", "--project", "--cache-dir")

var pathLikeOnlyFlags = flagSet("-p", "--python")

// toolRunLead is the part of a tool run's arguments before the command: the
// flags uv reads, with their values.
func toolRunLead(rest []string) []string {
	var lead []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "" {
			continue
		}
		if !strings.HasPrefix(a, "-") || a == "--" {
			break
		}
		lead = append(lead, a)
		if _, _, inline := splitFlagValue(a); !inline && toolRunValueFlags[a] && i+1 < len(rest) {
			lead = append(lead, rest[i+1])
			i++
		}
	}
	return lead
}

// specTokens gives the resolver the packages as the user wrote them, so a
// range (`django>=4,<5`, `express@^4`), extras (`requests[socks]`) and
// markers reach it intact — the parsed Spec keeps only a name and an exact
// pin. npm reads npm's syntax, which pnpm and yarn share. Python's
// resolvers read PEP 508, so poetry's and uv's `name@version` is rewritten.
func specTokens(m *Manager, parsed installArgs) []string {
	out := make([]string, 0, len(parsed.Specs))
	for _, s := range parsed.Specs {
		toks := parsed.Tokens[s]
		if len(toks) == 0 {
			out = append(out, reconstructToken(s))
			continue
		}
		for _, tok := range toks {
			if m.Ecosystem == "pypi" && strings.Contains(tok, "@") {
				out = append(out, pep508FromAt(tok, s))
			} else {
				out = append(out, tok)
			}
		}
	}
	return out
}

// pep508FromAt rewrites uv's and poetry's `name[extras]@version` shorthand
// as the PEP 508 requirement a resolver reads, keeping the extras and any
// marker: `httpx[cli]@0.28.1` is `httpx[cli]==0.28.1`. Only an exact pin
// is a version (s.Version, as ParseSpec read it): `@latest` and a range
// (`flask@^3.0`) are the bare requirement.
func pep508FromAt(tok string, s check.Spec) string {
	req, marker, hasMarker := strings.Cut(tok, ";")
	req = strings.TrimSpace(req)
	if i := strings.LastIndex(req, "@"); i >= 0 {
		req = strings.TrimSpace(req[:i])
		if s.Version != "" {
			req += "==" + s.Version
		}
	}
	if hasMarker {
		return req + "; " + strings.TrimSpace(marker)
	}
	return req
}

// reqFileTokens are the requirements files of a tool run as the resolver
// reads them: one "-r <path>" spec each, the path absolute against the
// directory the run changes to.
func reqFileTokens(files []string, base string) []string {
	var out []string
	for _, f := range files {
		out = append(out, "-r "+absIn(base, f))
	}
	return out
}

func reconstructToken(s check.Spec) string {
	switch {
	case s.Ecosystem == "pypi" && s.Version != "":
		return s.Name + "==" + s.Version
	case s.Ecosystem == "pypi":
		return s.Name
	case s.Version != "":
		return s.Name + "@" + s.Version
	case s.Constraint != "":
		return s.Name + "@" + s.Constraint
	}
	return s.Name
}

// npmProjectDir is the project an npm-side install resolves against: the
// current directory when the install will update its lockfile and npm can
// read it. A global or redirected install has no project here, and a
// yarn.lock or pnpm-lock.yaml is one npm cannot read, so those resolve the
// named packages on their own.
func npmProjectDir(m *Manager, args []string) string {
	if !writesLocalLockfile(m, args) {
		return ""
	}
	if _, err := os.Stat("package.json"); err != nil {
		return ""
	}
	for _, foreign := range []string{"yarn.lock", "pnpm-lock.yaml"} {
		if _, err := os.Stat(filepath.Join(".", foreign)); err == nil {
			return ""
		}
	}
	return "."
}

// The flags handed on to the resolver are the ones that change what gets
// resolved. Nothing else is passed: an unknown flag is at best ignored and
// at worst fails the dry run, which only costs the fallback.

// npmResolveFlags are the options an npm install hands the resolving npm:
// npm's own parse of the whole line (`parseNpmArgv`, options before the
// verb included), rendered as nopt normalised them, so `--no-no-optional`
// reaches the dry run as `--optional` and the last of two --userconfig
// values is the one passed — a filter by flag name dropped spellings nopt
// reads and kept both values. The registry and --userconfig travel as they
// do for a tool run, the path made absolute since the dry run runs
// elsewhere. pnpm and yarn spell theirs differently, so nothing of theirs
// is passed.
func npmResolveFlags(m *Manager, args []string) []string {
	if m.Bin != "npm" {
		return nil
	}
	a := parseNpmArgv(args)
	flags := a.resolveFlags()
	if a.Registry != "" {
		flags = append(flags, "--registry", a.Registry)
	}
	if a.Userconfig != "" {
		flags = append(flags, "--userconfig", absPath(a.Userconfig))
	}
	return flags
}

// absFlagValues makes the values of the flags in paths absolute, in both
// `--flag value` and `--flag=value` form, leaving a URL as it is. The
// command resolves its relative paths against base (its own directory,
// which uv's --directory may have moved); the dry run runs in another.
func absFlagValues(flags []string, paths map[string]bool, base string) []string {
	for i := 0; i < len(flags); i++ {
		flag, inline, hasInline := splitFlagValue(flags[i])
		if !paths[flag] {
			continue
		}
		abs := func(v string) string {
			if strings.Contains(v, "://") || (pathLikeOnlyFlags[flag] && !strings.ContainsAny(v, `/\`)) {
				return v
			}
			return absIn(base, v)
		}
		switch {
		case hasInline:
			flags[i] = flag + "=" + abs(inline)
		case i+1 < len(flags):
			flags[i+1] = abs(flags[i+1])
			i++
		}
	}
	return flags
}

// absIn is v as an absolute path, relative paths taken from base.
func absIn(base, v string) string {
	if filepath.IsAbs(v) {
		return v
	}
	return absPath(filepath.Join(base, v))
}

// npmConfigDir is the directory whose .npmrc npm reads as this install's
// project configuration: none in global mode, where npm ignores the project
// file; the --prefix given, which is the project there; else npm's local
// prefix. The dry run stages that file so it resolves against the registries
// the install will use.
func npmConfigDir(m *Manager, args []string) string {
	if m.Bin != "npm" {
		return npmLocalPrefix()
	}
	// npm's own parse decides the mode, with its last-wins and negation
	// rules: `--global --no-global` and `--global=false` are local installs,
	// and -C is --prefix.
	a := parseNpmArgv(args)
	return npmConfigDirFor(a.global(), a.prefix(), a.workspacesOff())
}

// npmConfigDirFor is npmConfigDir once global mode, the --prefix and
// whether workspaces are off are known, as a tool run's npm parse reports
// them.
func npmConfigDirFor(global bool, prefix string, workspacesOff bool) string {
	switch {
	case global:
		return ""
	case prefix != "":
		return absPath(prefix)
	}
	return npmConfigPrefix(workspacesOff)
}

// npmConfigPrefix is the directory whose .npmrc npm reads from the working
// directory: its local prefix, or the workspace root when that prefix is a
// declared member. npm's config loader walks on past the nearest
// package.json looking for an ancestor whose workspaces name it, takes that
// as the prefix and ignores the member's own .npmrc with a warning
// (verified against npm 11.19.1: `npm prefix` from a member answers the
// root, and --workspaces=false stops the walk).
func npmConfigPrefix(workspacesOff bool) string {
	prefix := npmLocalPrefix()
	if workspacesOff {
		return prefix
	}
	if _, err := os.Stat(filepath.Join(prefix, "package.json")); err != nil {
		return prefix
	}
	if root := catalog.NpmWorkspaceRoot(prefix); root != "" {
		return root
	}
	return prefix
}

// npmLocalPrefix is npm's local prefix for the working directory: the
// nearest directory, here or above, with a package.json or a node_modules
// directory, else the working directory itself. It is where npm reads
// project configuration and looks for the project's binaries.
func npmLocalPrefix() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for dir := cwd; ; {
		if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
			return dir
		}
		if fi, err := os.Stat(filepath.Join(dir, "node_modules")); err == nil && fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cwd
		}
		dir = parent
	}
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// Flags the pip and uv resolvers read the same way.
var pythonCommonFlags = flagSet("--pre", "--no-index", "-i", "--index-url", "--extra-index-url",
	"-f", "--find-links", "-c", "--constraint", "--python-version", "--keyring-provider")

// uvOnlyFlags are uv's own, passed when uv resolves a uv command.
var uvOnlyFlags = flagSet("--index", "--default-index", "--prerelease", "--resolution",
	"--exclude-newer", "--exclude-newer-package", "-p", "--python", "--python-platform",
	"--allow-insecure-host", "--index-strategy", "--only-binary", "--no-binary", "--no-binary-package", "--torch-backend",
	"--constraints", "--overrides", "--no-config", "--config-file", "--offline", "--project",
	"--cache-dir", "-n", "--no-cache", "--refresh", "--refresh-package", "--reinstall", "--reinstall-package")

// pipOnlyFlags are pip's own, passed when pip resolves a pip command.
var pipOnlyFlags = flagSet("--trusted-host", "--platform", "--implementation", "--abi",
	"--prefer-binary", "--use-feature", "--use-deprecated")

// uvResolveFlags are passed to `uv pip compile`. pip's index flags are
// uv's too; its --trusted-host is uv's --allow-insecure-host.
func uvResolveFlags(m *Manager, rest []string) []string {
	switch m.Bin {
	case "uv":
		return pickFlags(rest, valueFlags[m.Bin], union(pythonCommonFlags, uvOnlyFlags), uvRenames)
	case "pip", "pip3":
		return pickFlags(rest, valueFlags[m.Bin], union(pythonCommonFlags, flagSet("--trusted-host")),
			map[string]string{"--trusted-host": "--allow-insecure-host"})
	}
	return nil
}

// pipResolveFlags are passed to `pip install --dry-run`. For a uv command
// only pipFallbackFlags are read, and one with a flag pip cannot honour
// never reaches pip at all (needsUV).
func pipResolveFlags(m *Manager, rest []string) []string {
	switch m.Bin {
	case "pip", "pip3":
		return pickFlags(rest, valueFlags[m.Bin], union(pythonCommonFlags, pipOnlyFlags), nil)
	case "uv":
		return pickFlags(rest, valueFlags[m.Bin], pipFallbackFlags, pipFallbackRenames)
	}
	return nil
}

// pickFlags walks a command's arguments with the manager's own value-flag
// table, keeping the flags in allowed with their values and renaming those
// in rename. The table decides which token is a value, so a kept flag's
// value is the one the manager would read.
func pickFlags(rest []string, valFlags, allowed map[string]bool, rename map[string]string) []string {
	var out []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if !strings.HasPrefix(a, "-") || a == "--" {
			continue
		}
		flag, inline, hasInline := splitFlagValue(a)
		takesValue := valFlags[flag] && !hasInline
		if !allowed[flag] {
			if takesValue {
				i++
			}
			continue
		}
		name := flag
		if r, ok := rename[flag]; ok {
			name = r
		}
		switch {
		case hasInline:
			out = append(out, name+"="+inline)
		case takesValue && i+1 < len(rest):
			out = append(out, name, rest[i+1])
			i++
		default:
			out = append(out, name)
		}
	}
	return out
}

func hasFlag(rest []string, flag string) bool {
	for _, a := range rest {
		if a == flag {
			return true
		}
	}
	return false
}

func union(sets ...map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, s := range sets {
		for k := range s {
			out[k] = true
		}
	}
	return out
}
