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
	out := installArgs{Registry: a.Registry}
	if len(a.Packages) > 0 {
		for _, p := range a.Packages {
			out.addTarget("npm", strings.TrimSuffix(p, "@latest"))
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
// run a project's own binary of that name instead of fetching one.
func (p *installArgs) addCommand(token string) {
	n := len(p.Specs)
	p.addTarget("npm", strings.TrimSuffix(token, "@latest"))
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
		negated := false
		for strings.HasPrefix(strings.ToLower(key), "no-") {
			negated = true
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

		if negated || (known && kind.isBool()) || (!known && !hadEq) {
			switch {
			case !hasLa:
			case la == "true" || la == "false":
				i++
			case kind == npmBoolOrString && !isShortOption(la):
				i++
			case kind == npmBoolOrAlways && la == "always":
				i++
			}
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
			// The positional is only the binary; --package is what is fetched.
			out.addTarget("npm", strings.TrimSuffix(pkg, "@latest"))
			return out
		}
		out.addCommand(a)
		if n := len(out.Specs); n > 0 {
			if alias, ok := bunxAliases[out.Specs[n-1].Name]; ok {
				out.Specs[n-1].Name = alias
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
	dir, err := os.Getwd()
	if err != nil {
		return false
	}
	for {
		_, pkgErr := os.Stat(filepath.Join(dir, "package.json"))
		nm, nmErr := os.Stat(filepath.Join(dir, "node_modules"))
		if pkgErr == nil || (nmErr == nil && nm.IsDir()) {
			bin := filepath.Join(dir, "node_modules", ".bin", name)
			for _, ext := range binExts() {
				if fi, err := os.Stat(bin + ext); err == nil && !fi.IsDir() {
					return true
				}
			}
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

func binExts() []string {
	if runtime.GOOS == "windows" {
		return []string{"", ".cmd", ".exe"}
	}
	return []string{""}
}
