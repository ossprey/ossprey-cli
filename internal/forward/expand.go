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
	expandFn            = expandInstall
	resolveNpmFn        = catalog.ResolveNpmInstall
	resolvePythonFn     = catalog.ResolvePythonInstall
	resolveWithUVFn     = catalog.ResolvePythonInstallWithUV
	npmConfigIncludesFn = catalog.NpmConfigIncludes
	npmConfigGetFn      = catalog.NpmConfigGet
	npxCachedFn         = catalog.NpxCachedTree
	uvCacheDirFn        = catalog.UVCacheDir
	uvCachedFn          = catalog.UVCachedTree
	uvToolDirFn         = catalog.UVToolDir
	uvInstalledFn       = catalog.UVInstalledTree
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
				found[i] = true // trusted: not looked up publicly below either
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

	var missing []check.Spec
	for i, s := range parsed.Specs {
		if !found[i] {
			missing = append(missing, s)
		}
	}
	resolved := resolveSpecs(ctx, resolve, missing)
	set.named += len(resolved)
	set.specs = append(set.specs, resolved...)
	return set
}

// reportUnexpanded says, in one line even when quiet, that the install's
// dependencies were not resolved. Fail open, out loud: a clean verdict on
// the names alone must not read as a verdict on the install. The resolver's
// own output goes behind the verbose gutter, as a cataloger's does.
//
// Callers print it only once the terminal is theirs: after the progress
// animation has stopped, and in passive mode after the manager has exited,
// never from beside either.
func reportUnexpanded(ctx context.Context, specs []check.Spec, err error) {
	headline, detail := catalog.ResolveFailure(err)
	line := fmt.Sprintf("could not resolve the dependencies of %s (%s); checking the named packages only",
		joinNames(specs), headline)
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
			tree, err := resolveNpmFn(ctx, "", npmConfigDirFor(parsed.NpmGlobal, parsed.NpmPrefix), tokens, flags)
			if err != nil {
				return tree, err
			}
			// The flags that make `npm config get` read what this command
			// reads: its config files and location.
			configFlags := slices.Concat(flags, npmLocationFlags(parsed.NpmGlobal, parsed.NpmPrefix))
			// The omit policy shapes a fresh install only: a reused npx
			// installation is not pruned, so what it holds stays checked.
			tree = npmOmit(tree, npmEffectiveOmits(ctx, parsed.NpmOmits, configFlags))
			if m.Bin == "npm" || m.Bin == "npx" {
				// npm may reuse what an earlier run left in its npx cache,
				// dependencies and all, rather than what resolves today.
				tree = withNpxCached(ctx, tree, parsed, configFlags)
			}
			return tree, nil
		}
		// npm reads its options on either side of the verb (`npm --offline
		// install x`), so the whole line is read, not rest.
		flags := npmResolveFlags(m, args)
		tree, err := resolveNpmFn(ctx, npmProjectDir(m, args), npmConfigDir(m, args), tokens, flags)
		if err != nil || m.Bin != "npm" {
			return tree, err
		}
		// The omit policy comes from npm's own parse of the whole command,
		// options before the verb included, with its last-wins and negation
		// rules; the flag list above is only what the dry run is told.
		a := parseNpmArgv(args)
		omits := npmEffectiveOmits(ctx, a.omits(), slices.Concat(flags, npmLocationFlags(a.global(), a.prefix())))
		return npmOmit(tree, omits), nil
	case "pypi":
		// A short option's value may be attached (`-ihttps://…`); read it
		// as the resolver will, from a copy, so args stays what the real
		// command gets.
		rest = splitAttachedShorts(rest, pythonValueFlags(m))
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
			var tree []catalog.Resolved
			var err error
			if globalNeedsUV || needsUV(lead, toolRunValueFlags) {
				tree, err = resolveWithUVFn(ctx, "", tokens, uvFlags)
			} else {
				tree, err = resolvePythonFn(ctx, "", tokens, uvFlags, toolRunPipFlags(rest, base))
			}
			if err != nil {
				return tree, err
			}
			// uv may reuse a tool environment it cached for an earlier run,
			// dependencies and all, rather than what resolves today.
			return withUVCached(ctx, tree, parsed, slices.Concat(uvGlobalArgs(m, args), lead), base), nil
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
		if m.Bin == "uv" && (globalNeedsUV || needsUV(rest, valueFlags[m.Bin])) {
			return resolveWithUVFn(ctx, dir, tokens, uvFlags)
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
	"--cache-dir", "-n", "--no-cache", "--refresh", "--refresh-package")

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
		return splitAttachedShorts(args[:idx], globalValueFlags["uv"])
	}
	return nil
}

// pythonValueFlags are the value-taking flags of a Python manager's
// command, uv's tool-run table included since `uv tool run` shares the
// binary.
func pythonValueFlags(m *Manager) map[string]bool {
	if m.Bin == "uv" || m.Bin == "uvx" {
		return union(valueFlags["uv"], toolRunValueFlags)
	}
	return valueFlags[m.Bin]
}

// withNpxCached adds to a fresh resolution of a tool run whatever an earlier
// run of the same packages left in npm's npx cache: npm reuses that
// installation when the package it holds still satisfies the request, with
// the dependencies resolved back then, so the run may execute either tree.
// A release both report is one sighting with two provenances, merged so
// that neither can hide the other (mergeSighting). An unreadable cache adds
// nothing.
func withNpxCached(ctx context.Context, tree []catalog.Resolved, parsed installArgs, configFlags []string) []catalog.Resolved {
	cached, err := npxCachedFn(npmCacheDir(ctx, parsed.NpmCache, configFlags), parsed.NpxPackages)
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
func withUVCached(ctx context.Context, tree []catalog.Resolved, parsed installArgs, opts []string, base string) []catalog.Resolved {
	readsCache := true
	for _, a := range opts {
		if a == "-n" || a == "--no-cache" || a == "--refresh" || a == "--reinstall" {
			readsCache = false
		}
	}
	if readsCache {
		want := map[string]string{}
		for _, s := range parsed.Specs {
			want[canonicalPyPI(s.Name)] = s.Version
		}
		if cached, err := uvCachedFn(uvCacheDir(ctx, opts, base), want); err == nil {
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
// directory it runs in, not the file's).
func uvCacheDir(ctx context.Context, opts []string, base string) string {
	for i, a := range opts {
		if flag, value, inline := splitFlagValue(a); flag == "--cache-dir" {
			if inline {
				return absIn(base, value)
			}
			if i+1 < len(opts) {
				return absIn(base, opts[i+1])
			}
		}
	}
	if v := os.Getenv("UV_CACHE_DIR"); v != "" {
		return absIn(base, v)
	}
	selectors := absFlagValues(pickFlags(opts, uvValueFlags(), uvCacheSelectors, nil), pythonPathFlags, base)
	if v, err := uvCacheDirFn(ctx, selectors); err == nil && v != "" {
		return absIn(base, v)
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "uv", "cache")
	}
	return filepath.Join(dir, "uv")
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
	return a
}

// npmCacheDir is where npm keeps its cache for this run: --cache as parsed,
// npm_config_cache, else what npm's configuration files say (`npm config get
// cache`, read with the command's own config-file and location flags, which
// also yields npm's platform default), else that default worked out here
// when npm cannot be asked.
func npmCacheDir(ctx context.Context, flag string, configFlags []string) string {
	if flag != "" {
		return absPath(flag)
	}
	for _, name := range []string{"npm_config_cache", "NPM_CONFIG_CACHE"} {
		if v := os.Getenv(name); v != "" {
			return absPath(expandHome(v))
		}
	}
	if v, err := npmConfigGetFn(ctx, ".", "cache", configFlags); err == nil && v != "" {
		return absPath(expandHome(v))
	}
	if runtime.GOOS == "windows" {
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return filepath.Join(v, "npm-cache")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "npm-cache")
	}
	return filepath.Join(home, ".npm")
}

// npmLocationFlags are the flags that make `npm config get` read the same
// project configuration as the command: global mode reads none, --prefix
// names the project.
func npmLocationFlags(global bool, prefix string) []string {
	switch {
	case global:
		return []string{"-g"}
	case prefix != "":
		return []string{"--prefix", absPath(prefix)}
	}
	return nil
}

// npmEffectiveOmits is the command line's omit policy less whatever npm's
// configuration includes: an include in an .npmrc, the user or global
// config or the environment wins over an --omit on the line, and the dry
// run's lockfile cannot say, since it records omitted packages too. npm is
// asked only when the line omits something, so the common run pays nothing;
// when it cannot be asked, nothing is dropped, which can only check more.
func npmEffectiveOmits(ctx context.Context, omits map[string]bool, flags []string) map[string]bool {
	if len(omits) == 0 {
		return nil
	}
	included, err := npmConfigIncludesFn(ctx, ".", flags)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for kind := range omits {
		out[kind] = true
	}
	for _, kind := range included {
		delete(out, kind)
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
		switch {
		case r.Dev && omits["dev"], r.Optional && omits["optional"], r.Peer && omits["peer"],
			r.DevOptional && omits["dev"] && omits["optional"]:
			continue
		}
		kept = append(kept, r)
	}
	return kept
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
	return absFlagValues(pickFlags(lead, valFlags, allowed, nil), pythonPathFlags, base),
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
	return absFlagValues(pickFlags(toolRunLead(rest), toolRunValueFlags, allowed, nil), pythonPathFlags, base)
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
	// The cache uv reads offline or prefers, and whether it reads or
	// refreshes it, decide what it resolves against; pip has no such cache.
	"--cache-dir", "-n", "--no-cache", "--refresh", "--refresh-package")

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
				out = append(out, reconstructToken(s))
			} else {
				out = append(out, tok)
			}
		}
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

// npmResolveFlags are passed from an npm install to the resolving npm. pnpm
// and yarn spell theirs differently, so nothing of theirs is passed.
var npmPassFlags = flagSet("--legacy-peer-deps", "--strict-peer-deps", "--no-optional", "--optional",
	"--omit", "--include", "--registry", "--before", "--tag", "--userconfig", "--globalconfig",
	// The cache policy decides what npm resolves against: offline and
	// prefer-offline read the cache's metadata, which may be older than the
	// registry's, and --cache names which cache that is.
	"--cache", "--offline", "--prefer-offline")

func npmResolveFlags(m *Manager, rest []string) []string {
	if m.Bin != "npm" {
		return nil
	}
	return absUserconfig(pickFlags(rest, valueFlags[m.Bin], npmPassFlags, nil))
}

// absUserconfig makes npm's --userconfig, --globalconfig and --cache paths
// absolute: npm resolves them against the directory the command ran in, a
// leading `~/` against the home directory as nopt does, and the dry run
// runs in another.
func absUserconfig(flags []string) []string {
	paths := flagSet("--userconfig", "--globalconfig", "--cache")
	for i := 0; i < len(flags); i++ {
		flag, inline, hasInline := splitFlagValue(flags[i])
		if !paths[flag] {
			continue
		}
		switch {
		case hasInline:
			flags[i] = flag + "=" + expandHome(inline)
		case i+1 < len(flags):
			flags[i+1] = expandHome(flags[i+1])
			i++
		}
	}
	return absFlagValues(flags, paths, ".")
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
	return npmConfigDirFor(a.global(), a.prefix())
}

// npmConfigDirFor is npmConfigDir once global mode and the --prefix are
// known, as a tool run's npm parse reports them.
func npmConfigDirFor(global bool, prefix string) string {
	switch {
	case global:
		return ""
	case prefix != "":
		return absPath(prefix)
	}
	return npmLocalPrefix()
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
	"--allow-insecure-host", "--index-strategy", "--only-binary", "--no-binary",
	"--constraints", "--overrides", "--no-config", "--config-file", "--offline", "--project",
	"--cache-dir", "-n", "--no-cache", "--refresh", "--refresh-package")

// pipOnlyFlags are pip's own, passed when pip resolves a pip command.
var pipOnlyFlags = flagSet("--trusted-host", "--platform", "--implementation", "--abi",
	"--prefer-binary", "--use-feature", "--use-deprecated")

// uvResolveFlags are passed to `uv pip compile`. pip's index flags are
// uv's too; its --trusted-host is uv's --allow-insecure-host.
func uvResolveFlags(m *Manager, rest []string) []string {
	switch m.Bin {
	case "uv":
		return pickFlags(rest, valueFlags[m.Bin], union(pythonCommonFlags, uvOnlyFlags), nil)
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
