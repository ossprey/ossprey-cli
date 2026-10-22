package forward

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	expandFn        = expandInstall
	resolveNpmFn    = catalog.ResolveNpmInstall
	resolvePythonFn = catalog.ResolvePythonInstall
	resolveWithUVFn = catalog.ResolvePythonInstallWithUV
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
			var flags []string
			if parsed.Registry != "" {
				flags = append(flags, "--registry", parsed.Registry)
			}
			if parsed.Userconfig != "" {
				flags = append(flags, "--userconfig", absPath(parsed.Userconfig))
			}
			return resolveNpmFn(ctx, "", npmLocalPrefix(), tokens, flags)
		}
		return resolveNpmFn(ctx, npmProjectDir(m, args), npmConfigDir(m, args), tokens, npmResolveFlags(m, rest))
	case "pypi":
		if parsed.ToolRun {
			// No project: uv's tool commands read no project configuration,
			// so the resolver runs where there is none (dir ""), and paths in
			// the flags are made absolute to survive the move.
			if needsUV(toolRunLead(rest), toolRunValueFlags) {
				return resolveWithUVFn(ctx, "", tokens, toolRunLeadingFlags(rest))
			}
			return resolvePythonFn(ctx, "", tokens, toolRunLeadingFlags(rest), toolRunPipFlags(rest))
		}
		if hasFlag(rest, "--no-deps") {
			return nil, nil
		}
		if m.Bin == "uv" && needsUV(rest, valueFlags[m.Bin]) {
			return resolveWithUVFn(ctx, ".", tokens, uvResolveFlags(m, rest))
		}
		return resolvePythonFn(ctx, ".", tokens, uvResolveFlags(m, rest), pipResolveFlags(m, rest))
	}
	return nil, nil
}

// toolRunLeadingFlags are the resolver flags of a `uvx` / `uv tool run`
// command: those before the command, read with the tool run's own value
// table so a value is never taken for the command, and kept only when uv's
// resolver reads them the same way (`uvx --index-url … ruff`).
func toolRunLeadingFlags(rest []string) []string {
	return absFlagValues(pickFlags(toolRunLead(rest), toolRunValueFlags, union(pythonCommonFlags, uvOnlyFlags), nil), pythonPathFlags)
}

// toolRunPipFlags are the same leading flags as pip's resolver reads them,
// for a host with no working uv: the index a uvx run names must reach the
// fallback too, or it would resolve against a different one. A flag pip
// cannot honour never does; see needsUV.
func toolRunPipFlags(rest []string) []string {
	return absFlagValues(pickFlags(toolRunLead(rest), toolRunValueFlags, pipFallbackFlags, pipFallbackRenames), pythonPathFlags)
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
	"-p", "--python", "--python-platform", "--config-file")

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
// absFlagValues leaves alone.
var pythonPathFlags = flagSet("-c", "--constraint", "--constraints", "--overrides",
	"-f", "--find-links", "--config-file")

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
		tok := parsed.Tokens[s]
		switch {
		case tok == "":
			out = append(out, reconstructToken(s))
		case m.Ecosystem == "pypi" && strings.Contains(tok, "@"):
			out = append(out, reconstructToken(s))
		default:
			out = append(out, tok)
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
var npmPassFlags = flagSet("--legacy-peer-deps", "--strict-peer-deps", "--no-optional",
	"--omit", "--include", "--registry", "--before", "--tag", "--userconfig")

func npmResolveFlags(m *Manager, rest []string) []string {
	if m.Bin != "npm" {
		return nil
	}
	return absUserconfig(pickFlags(rest, valueFlags[m.Bin], npmPassFlags, nil))
}

// absUserconfig makes a --userconfig path absolute: npm resolves it against
// the directory the command ran in, and the dry run runs in another.
func absUserconfig(flags []string) []string {
	return absFlagValues(flags, flagSet("--userconfig"))
}

// absFlagValues makes the values of the flags in paths absolute, in both
// `--flag value` and `--flag=value` form, leaving a URL as it is. The
// command's relative paths are against its own directory; the dry run runs
// in another.
func absFlagValues(flags []string, paths map[string]bool) []string {
	for i := 0; i < len(flags); i++ {
		flag, inline, hasInline := splitFlagValue(flags[i])
		if !paths[flag] {
			continue
		}
		switch {
		case hasInline:
			flags[i] = flag + "=" + absIfPath(inline)
		case i+1 < len(flags):
			flags[i+1] = absIfPath(flags[i+1])
			i++
		}
	}
	return flags
}

func absIfPath(v string) string {
	if strings.Contains(v, "://") {
		return v
	}
	return absPath(v)
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
	valFlags := union(globalValueFlags[m.Bin], valueFlags[m.Bin])
	prefix := ""
	for i := 0; i < len(args); i++ {
		flag, value, hasInline := splitFlagValue(args[i])
		if !hasInline && valFlags[flag] && i+1 < len(args) {
			value = args[i+1]
			i++
		}
		switch flag {
		case "-g", "--global":
			return ""
		case "--location":
			// Not in npm's value table (its value is one of three words), so
			// read it here: `--location global` as well as `--location=global`.
			if !hasInline && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				value = args[i+1]
				i++
			}
			if value == "global" {
				return ""
			}
		case "--prefix", "-C":
			prefix = value
		}
	}
	if prefix != "" {
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
	"--constraints", "--overrides", "--no-config", "--config-file")

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
