package forward

import (
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
)

// npm-side fetch-and-execute: npx, `npm exec` / `npm x`, bunx and `bun x`.
// Like uvx, each one fetches a package and runs one of its binaries, and only
// the package is checked, never the program's own arguments: `npx cowsay moo`
// checks cowsay, not moo.
//
// Which token is the package is decided by the tool's own argument parser, and
// getting it wrong is the unsafe direction — the token we check is not the one
// that runs. So the npm side is a port of npm's parsers rather than a flag
// table guessed from its docs: npx's argv rewrite (bin/npx-cli.js) followed by
// nopt, typed by npm's own option definitions (npm_config.go). The tests diff
// both against the installed npm.

// npmFlagKind is how nopt treats the token after an option.
type npmFlagKind int

const (
	// npmValue takes the next token unless it is "--".
	npmValue npmFlagKind = iota
	// npmString takes the next token unless it looks like another option.
	npmString
	// npmBool takes the next token only when it is "true" or "false".
	npmBool
	// npmBoolOrString is a boolean that also takes a next token that does not
	// look like a short option (`--browser firefox`).
	npmBoolOrString
	// npmBoolOrAlways is a boolean that also takes "always" (`--color always`).
	npmBoolOrAlways
)

func (k npmFlagKind) isBool() bool {
	return k == npmBool || k == npmBoolOrString || k == npmBoolOrAlways
}

// npmArgv is what `npm exec` reads from its command line.
type npmArgv struct {
	// Packages are --package values: what is fetched when any are given, in
	// which case the first positional only names the binary to run.
	Packages []string
	// Call is set by --call / -c, which runs a shell command instead of a
	// positional one.
	Call bool
	// Positionals are the non-option tokens in order; the first is the command.
	Positionals []string
	// Registry is the --registry value npm will fetch from, when one is given
	// (the last wins, as in nopt). It is read by npm, not by the program run,
	// so the resolver must use it too.
	Registry string
	// Userconfig is the --userconfig path, cleaned but still relative to the
	// directory the command ran in, as nopt's path type resolves it; a
	// resolver running elsewhere must make it absolute first.
	Userconfig string
	// Config holds the other options npm attributes to itself that change
	// what a run fetches or where npm reads its configuration (npmRunConfig),
	// each value in order, booleans as "true"/"false". Nothing after the
	// command's own `--` boundary is ever recorded here.
	Config map[string][]string
}

// npmRunConfig names the npm options a tool run's dry run must be given to
// resolve what npm will: the peer and omit rules, a release ceiling, the
// dist-tag, and the global/prefix/location trio that decides which .npmrc
// npm reads.
var npmRunConfig = flagSet("legacy-peer-deps", "strict-peer-deps", "optional", "omit", "include",
	"before", "tag", "globalconfig", "global", "prefix", "location", "cache", "offline", "prefer-offline", "prefer-online", "workspaces",
	"min-release-age", "min-release-age-exclude")

// npmPathConfig are the npmRunConfig keys nopt types as paths: a leading
// `~/` is the home directory (nopt's validatePath), and the rest is read
// relative to the command's directory.
var npmPathConfig = flagSet("globalconfig", "prefix", "cache")

// expandHome is nopt's home expansion for a path-typed option: `~/x` is
// `<home>/x` (`~\x` as well on Windows); anything else is left as given.
func expandHome(v string) string {
	rest, ok := strings.CutPrefix(v, "~/")
	if !ok && runtime.GOOS == "windows" {
		rest, ok = strings.CutPrefix(v, `~\`)
	}
	if !ok {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return v
	}
	return filepath.Join(home, rest)
}

// npmConfigKeys are npmRunConfig's keys in a fixed order, for output.
var npmConfigKeys = []string{"before", "cache", "globalconfig", "include", "legacy-peer-deps", "min-release-age", "min-release-age-exclude",
	"offline", "omit", "optional", "prefer-offline", "prefer-online", "strict-peer-deps", "tag", "workspaces"}

// npmRecordOnly are recorded options the dry run is never told: workspaces
// decides where npm reads its configuration, and `npm install --workspaces`
// in a scratch directory with none fails with "No workspaces found!"
// (verified against npm 11.19.1).
var npmRecordOnly = flagSet("workspaces")

func (a *npmArgv) record(key, value string) {
	if !npmRunConfig[key] {
		return
	}
	if npmPathConfig[key] {
		value = filepath.Clean(expandHome(value))
	}
	if a.Config == nil {
		a.Config = map[string][]string{}
	}
	a.Config[key] = append(a.Config[key], value)
}

func (a npmArgv) last(key string) string {
	if v := a.Config[key]; len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

// global reports whether npm runs in global mode, where it reads no project
// .npmrc: `-g`/`--global` or `--location global`, the last value winning
// for each as in nopt.
func (a npmArgv) global() bool {
	return a.last("global") == "true" || a.last("location") == "global"
}

// prefix is the --prefix npm was given, cleaned and still relative to the
// command's directory, or "".
func (a npmArgv) prefix() string {
	return a.last("prefix")
}

// workspacesOff reports --workspaces=false (or --no-workspaces), which
// keeps npm's config discovery at the nearest package.json.
func (a npmArgv) workspacesOff() bool {
	return a.last("workspaces") == "false"
}

// cache is the --cache npm was given, or "".
func (a npmArgv) cache() string {
	return a.last("cache")
}

// npxPackages are the specs libnpmexec installs for the run, as typed: the
// --package values, else the command itself. They key the npx cache.
func (a npmArgv) npxPackages() []string {
	if len(a.Packages) > 0 {
		return slices.Clone(a.Packages)
	}
	if a.Call || len(a.Positionals) == 0 {
		return nil
	}
	return []string{a.Positionals[0]}
}

// resolveFlags renders the recorded resolution options back into flags for
// the dry run, in a fixed key order; npm re-reads them with its own
// last-wins and array rules, so every occurrence is kept.
func (a npmArgv) resolveFlags() []string {
	var out []string
	for _, key := range npmConfigKeys {
		if npmRecordOnly[key] {
			continue
		}
		for _, v := range a.Config[key] {
			switch {
			case npmConfig[key].isBool() && v == "true":
				out = append(out, "--"+key)
			case npmConfig[key].isBool() && v == "false":
				out = append(out, "--no-"+key)
			case key == "globalconfig", key == "cache":
				// A path, resolved against the command's directory as nopt
				// does; the dry run runs in another.
				out = append(out, "--"+key+"="+absPath(v))
			default:
				out = append(out, "--"+key+"="+v)
			}
		}
	}
	return out
}

// npmExecAt matches `npm exec` under any name npm takes for it (`x`, `exe`).
// It starts the run at 0, not after the verb, because npm reads options on
// either side of it.
func npmExecAt(args []string) (int, bool) {
	if idx := verbIndex("npm", args); idx >= 0 && npmDeref(args[idx]) == "exec" {
		return 0, true
	}
	return 0, false
}

// npmExecRun classifies `npm exec` / `npm x`. npm parses options anywhere
// before a "--", so the whole command line is read and the first positional,
// the verb, dropped.
func npmExecRun(args []string) installArgs {
	a := parseNpmArgv(args)
	if len(a.Positionals) > 0 {
		a.Positionals = a.Positionals[1:]
	}
	return a.target()
}

// npxRun classifies an npx command line: npx's own rewrite, then npm exec's.
func npxRun(args []string) installArgs {
	return parseNpmArgv(npxArgv(args)).target()
}

func (a npmArgv) target() installArgs {
	out := installArgs{Registry: a.Registry, Userconfig: a.Userconfig,
		NpmFlags: a.resolveFlags(), NpmGlobal: a.global(), NpmPrefix: a.prefix(), NpmWorkspacesOff: a.workspacesOff(),
		NpmCache: a.cache(), NpxPackages: a.npxPackages()}
	if len(a.Packages) > 0 {
		for _, p := range a.Packages {
			out.addTarget("npm", p)
		}
		return out
	}
	// --call runs its shell command from the project's own binaries; with no
	// --package, nothing is fetched for it.
	if a.Call || len(a.Positionals) == 0 {
		return out
	}
	out.addCommand(a.Positionals[0])
	return out
}

// addCommand adds the command of a run with no --package, which is also the
// package fetched. A bare name is recorded as LocalCommand, since npm and bun
// run a project's own binary of that name instead of fetching one. The token
// is kept as typed: `tool@latest` names the tag explicitly, which npm fetches
// (libnpmexec never takes a tag spec from the local tree) and which the dry
// run must see, or a `--tag` on the line would resolve a release the run
// does not use.
func (p *installArgs) addCommand(token string) {
	n := len(p.Specs)
	p.addTarget("npm", token)
	if len(p.Specs) > n && !strings.Contains(strings.TrimPrefix(token, "@"), "@") {
		p.LocalCommand = token
	}
}

// npx-cli.js's tables. Removed options are still recognised, so that their
// values are consumed (or dropped) exactly as npx does.
var (
	npxRemovedSwitches = flagSet("always-spawn", "ignore-existing", "shell-auto-fallback")
	npxRemovedOpts     = flagSet("npm", "node-arg", "n")
	npxExtraSwitches   = flagSet("no-install", "quiet", "q", "version", "v", "help", "h")
	npxOpts            = flagSet("package", "p", "cache", "userconfig", "call", "c", "shell",
		"npm", "node-arg", "n")
)

func npxRemoved(key string) bool { return npxRemovedSwitches[key] || npxRemovedOpts[key] }

func npxSwitch(key string) bool {
	if k, ok := npmConfig[key]; ok && k.isBool() {
		return true
	}
	return npxRemovedSwitches[key] || npxExtraSwitches[key]
}

// npxArgv is bin/npx-cli.js's rewrite of its argv into `npm exec` arguments: it
// expands shorthands, renames -p and --shell, drops removed options, and puts
// "--" in front of the first positional so that everything after it reaches
// the command. A port, quirks included — an option it does not know takes the
// next token as its value unless that token starts with "-", which is not what
// npm's parser then does with it, and parseNpmArgv is what settles the command.
func npxArgv(in []string) []string {
	args := slices.Clone(in)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			return slices.Insert(args, i, "--")
		}
		parts := strings.Split(strings.TrimLeft(arg, "-"), "=")
		key, v := parts[0], parts[1:]
		switch key {
		case "p":
			args[i] = strings.Join(append([]string{"--package"}, v...), "=")
		case "shell":
			args[i] = strings.Join(append([]string{"--script-shell"}, v...), "=")
		case "no-install":
			args[i] = "--yes=false"
		default:
			if exp, ok := npmShorthands[key]; ok && !npxRemoved(key) {
				a := slices.Clone(exp)
				if len(v) > 0 {
					a = append(a, strings.Join(v, "="))
				}
				args = slices.Replace(args, i, i+1, a...)
				i--
				continue
			}
		}
		if npxRemoved(key) {
			args = slices.Delete(args, i, i+1)
			i--
		}
		if len(v) == 0 && !npxSwitch(key) &&
			(npxOpts[key] || i+1 >= len(args) || !strings.HasPrefix(args[i+1], "-")) {
			if !npxRemoved(key) {
				i++
			} else if i+1 < len(args) {
				args = slices.Delete(args, i+1, i+2)
			}
		}
	}
	return args
}

// parseNpmArgv is nopt's parse (nopt-lib.js), reduced to what decides the
// command: which tokens are option values, and the --package and --call
// options. Not ported: a negated array option (`--no-ca x`) taking a value.
func parseNpmArgv(in []string) npmArgv {
	args := slices.Clone(in)
	var out npmArgv
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if isDashes(arg) {
			out.Positionals = append(out.Positionals, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' {
			out.Positionals = append(out.Positionals, arg)
			continue
		}
		hadEq := false
		if at := strings.IndexByte(arg, '='); at >= 0 {
			hadEq = true
			args = slices.Replace(args, i, i+1, arg[:at], arg[at+1:])
			arg = arg[:at]
		}
		if exp := npmResolveShort(arg); exp != nil {
			args = slices.Replace(args, i, i+1, exp...)
			if arg != exp[0] {
				i--
				continue
			}
		}
		key := strings.TrimLeft(arg, "-")
		// nopt toggles the negation per `no-` prefix (`--no-no-optional` is
		// optional on), and any prefix makes the option boolean.
		hadPrefix, negated := false, false
		for strings.HasPrefix(strings.ToLower(key), "no-") {
			hadPrefix, negated = true, !negated
			key = key[3:]
		}
		if full := npmAbbrev(key); full != "" {
			key = full
		}
		kind, known := npmConfig[key]
		la, hasLa := "", i+1 < len(args)
		if hasLa {
			la = args[i+1]
		}

		if hadPrefix || (known && kind.isBool()) || (!known && !hadEq) {
			value := "true"
			if negated {
				value = "false"
			}
			switch {
			case !hasLa:
			case la == "true" || la == "false":
				// nopt reads the word, then negates it for a --no- option:
				// `--no-optional=false` is optional on.
				value = la
				if negated {
					value = map[string]string{"true": "false", "false": "true"}[la]
				}
				i++
			case kind == npmBoolOrString && !isShortOption(la):
				i++
			case kind == npmBoolOrAlways && la == "always":
				i++
			}
			out.record(key, value)
			continue
		}

		switch {
		case !hasLa, isDashes(la):
			// No value: the option is just set.
		case kind == npmString && looksLikeOption(la):
			// A string option followed by another option is set empty.
		default:
			switch key {
			case "package":
				out.Packages = append(out.Packages, la)
			case "call":
				out.Call = true
			case "registry":
				out.Registry = la // the last wins, and is the one validated below
			case "userconfig":
				out.Userconfig = filepath.Clean(expandHome(la))
			default:
				out.record(key, la)
			}
			i++
			continue
		}
		if key == "call" {
			out.Call = true
		}
	}
	// nopt types registry as a url and drops the option when its value is
	// not one, so a run with `--registry nope` fetches from the default.
	if u, err := url.Parse(out.Registry); err != nil || u.Scheme == "" || u.Host == "" {
		out.Registry = ""
	} else {
		// nopt keeps the parsed URL's href, so a bare host gains its "/".
		if u.Path == "" {
			u.Path = "/"
		}
		out.Registry = u.String()
	}
	return out
}

// npmResolveShort is nopt's resolveShort: the expansion of a shorthand, of a
// run of single-letter shorthands (`-gy`), or of an abbreviated shorthand —
// unless the option is itself an npm option or an abbreviation of one.
func npmResolveShort(flag string) []string {
	arg := strings.TrimLeft(flag, "-")
	if arg == "" {
		return nil
	}
	if _, ok := npmConfig[arg]; ok {
		return nil
	}
	if exp, ok := npmShorthands[arg]; ok {
		return exp
	}
	var singles []string
	for _, c := range arg {
		exp, ok := npmShorthands[string(c)]
		if !ok {
			singles = nil
			break
		}
		singles = append(singles, exp...)
	}
	if singles != nil {
		return singles
	}
	if npmAbbrev(arg) != "" {
		return nil
	}
	if full := uniquePrefix(npmShorthandNames, arg); full != "" {
		return npmShorthands[full]
	}
	return nil
}

// npmAbbrev returns the option arg abbreviates, or "" when it is ambiguous or
// none.
func npmAbbrev(arg string) string {
	return uniquePrefix(npmConfigNames, arg)
}

var (
	npmConfigNames    = sortedKeys(npmConfig)
	npmShorthandNames = sortedKeys(npmShorthands)
)

// uniquePrefix is the `abbrev` package's lookup: a name maps to itself, and a
// prefix of exactly one name maps to that name.
func uniquePrefix(names []string, s string) string {
	if s == "" {
		return ""
	}
	match := ""
	for _, n := range names {
		if n == s {
			return n
		}
		if strings.HasPrefix(n, s) {
			if match != "" {
				return ""
			}
			match = n
		}
	}
	return match
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isDashes matches nopt's /^-{2,}$/, its end of options.
func isDashes(s string) bool {
	return len(s) >= 2 && strings.Trim(s, "-") == ""
}

// isShortOption matches /^-[^-]/.
func isShortOption(s string) bool {
	return len(s) >= 2 && s[0] == '-' && s[1] != '-'
}

// looksLikeOption matches /^-{1,2}[^-]+/.
func looksLikeOption(s string) bool {
	rest := strings.TrimPrefix(s, "-")
	if rest == s {
		return false
	}
	rest = strings.TrimPrefix(rest, "-")
	return rest != "" && rest[0] != '-'
}

// bunxAliases are the commands bunx fetches under another package's name when
// no --package is given.
var bunxAliases = map[string]string{
	"tsc":    "typescript",
	"claude": "@anthropic-ai/claude-code",
}

// bunxRun classifies bunx and `bun x` arguments, after bun's bunx parser: only
// --package / -p takes a value (the next token, verbatim, or after "="), any
// other option is a switch — "--" included — and the first positional is the
// command, with everything after it the program's own.
func bunxRun(args []string) installArgs {
	var out installArgs
	pkg, pkgSet := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			switch flag, value, hasInline := splitFlagValue(a); {
			case flag != "--package" && flag != "-p":
			case hasInline:
				pkg, pkgSet = value, true
			case i+1 < len(args):
				pkg, pkgSet = args[i+1], true
				i++
			}
			continue
		}
		if pkgSet {
			// The positional is only the binary; --package is what is
			// fetched, kept as typed (`tool@latest` included) for the
			// resolver, which must see the tag a configured one would
			// otherwise replace.
			out.addTarget("npm", pkg)
			return out
		}
		out.addCommand(a)
		if n := len(out.Specs); n > 0 {
			if alias, ok := bunxAliases[out.Specs[n-1].Name]; ok {
				// The token travels to the resolver as typed, so it is
				// renamed too: `tsc@latest` is `typescript@latest`, tag kept.
				s := out.Specs[n-1]
				toks := out.Tokens[s]
				delete(out.Tokens, s)
				out.Specs[n-1].Name = alias
				for _, tok := range toks {
					out.Tokens[out.Specs[n-1]] = append(out.Tokens[out.Specs[n-1]], alias+strings.TrimPrefix(tok, s.Name))
				}
			}
		}
		return out
	}
	// --package with no binary, or no command at all: bunx runs nothing.
	return out
}

// localBinFn is a test seam for projectHasBin.
var localBinFn = projectHasBin

// projectHasBin reports whether the npm project around the working directory
// has a binary called name: node_modules/.bin/<name> under the nearest
// ancestor holding a package.json or a node_modules, which is where npm's exec
// looks. npx, `npm exec` and bunx run that binary rather than fetching a
// package, so there is nothing to check. Looking only there, and not on PATH as
// bunx also does, can only cost a needless check.
func projectHasBin(name string) bool {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return false
	}
	bin := filepath.Join(npmLocalPrefix(), "node_modules", ".bin", name)
	for _, ext := range binExts() {
		if fi, err := os.Stat(bin + ext); err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

func binExts() []string {
	if runtime.GOOS == "windows" {
		return []string{"", ".cmd", ".exe"}
	}
	return []string{""}
}
