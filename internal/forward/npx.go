package forward

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/check"
)

// npx is fetch-and-execute, not an install: `npx cowsay moo` downloads cowsay
// into npm's cache and runs it. Every invocation is therefore "an install" as
// far as installAt is concerned, but its arguments share nothing with an
// install's, so it has its own parser rather than a verbAt entry:
//
//   - Options come first. npx stops parsing its own options at the first
//     positional, and everything after that is the program's argv. Only that
//     first positional can be a package — `npx cowsay moo` must check cowsay,
//     never moo (which is itself a real npm package, and could block on it).
//   - `--package`/`-p` (repeatable) name the packages to fetch outright. When
//     any are given, the first positional is a *command* those packages
//     provide, not a package, and is not checked.
//   - `-c`/`--call` runs a shell string. With no `-p` it runs in the local
//     project's context and fetches nothing.
//
// npxValueFlags follows the same asymmetry as valueFlags, and it bites the same
// way: listing a boolean flag here swallows the package after it and runs it
// unchecked, so only flags known to take a value belong. `-s` is deliberately
// absent — legacy npx read it as --shell, npm 7+ reads it as --silent.
var npxValueFlags = flagSet("--call", "-c", "--workspace", "-w", "--registry",
	"--prefix", "-C", "--cache", "--userconfig", "--globalconfig", "--loglevel",
	"--shell", "--script-shell", "--node-arg", "-n", "--node-options")

// npxPackageFlags name the packages npx should fetch.
var npxPackageFlags = flagSet("--package", "-p")

// npxInstallAt matches every npx invocation; npxParse decides what, if
// anything, it fetches.
func npxInstallAt([]string) (int, bool) { return 0, true }

// localBinFn reports whether name is already installed in the project npx is
// run from. Overridable in tests.
var localBinFn = localBin

// npxParse classifies an npx command line into the packages it will fetch.
func npxParse(args []string) installArgs {
	var (
		packages []string
		command  string
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a == "--" {
			// Option parsing ends; the next token is the command.
			if i+1 < len(args) {
				command = args[i+1]
			}
			break
		}
		if !strings.HasPrefix(a, "-") {
			command = a
			break
		}
		flag, value, hasInline := splitFlagValue(a)
		switch {
		case npxPackageFlags[flag]:
			if !hasInline {
				if i+1 >= len(args) {
					continue
				}
				value = args[i+1]
				i++
			}
			packages = append(packages, value)
		case npxValueFlags[flag] && !hasInline:
			i++
		}
	}

	// With -p the positional is a bin those packages provide; without it the
	// positional is the package itself.
	asCommand := len(packages) == 0
	if asCommand && command != "" {
		packages = []string{command}
	}

	var out installArgs
	for _, tok := range packages {
		// `npm:` names a registry package under an alias; the package is what
		// follows it.
		tok = strings.TrimPrefix(tok, "npm:")
		if isNonPackageToken(tok) || strings.HasPrefix(tok, "github:") ||
			strings.HasPrefix(tok, "gitlab:") || strings.HasPrefix(tok, "bitbucket:") ||
			strings.HasPrefix(tok, "gist:") {
			out.NonPackages = append(out.NonPackages, tok)
			continue
		}
		s, err := check.ParseSpec("npm", tok)
		if err != nil {
			out.NonPackages = append(out.NonPackages, tok)
			continue
		}
		// A dist-tag or range (`cowsay@latest`, `cowsay@^1`) names no release,
		// so let the registry pick one rather than submitting a version that
		// does not exist.
		s.Version = concreteNpmVersion(s.Version)
		// An unpinned command already in the project's node_modules runs from
		// there: npx fetches nothing, so there is nothing to check here (the
		// install that put it there is what the other forwarders check).
		// `npx eslint` is overwhelmingly this case.
		if s.Version == "" && localBinFn(s.Name, asCommand) {
			continue
		}
		out.Specs = append(out.Specs, s)
	}
	return out
}

var semverish = regexp.MustCompile(`^\d+\.\d+\.\d+([-+][0-9A-Za-z.+-]*)?$`)

// concreteNpmVersion returns v when it names one release, else "".
func concreteNpmVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "="), "v")
	if semverish.MatchString(v) {
		return v
	}
	return ""
}

// localBin reports whether npx would use an unpinned name from the current
// project instead of fetching it. npm finds that project the way it finds any
// other: the nearest directory, walking up, with a node_modules or a
// package.json — and it stops there, so a stray ~/node_modules does not count.
//
// asCommand is the bare positional form (`npx eslint`), which npm first tries
// as a bin in node_modules/.bin; a scoped name or a -p package is looked up as
// an installed package instead.
func localBin(name string, asCommand bool) bool {
	dir, err := os.Getwd()
	if err != nil {
		return false
	}
	for {
		nm := filepath.Join(dir, "node_modules")
		if exists(nm) || exists(filepath.Join(dir, "package.json")) {
			if exists(filepath.Join(nm, filepath.FromSlash(name), "package.json")) {
				return true
			}
			if asCommand && !strings.HasPrefix(name, "@") {
				bin := filepath.Join(nm, ".bin", name)
				return exists(bin) || (runtime.GOOS == "windows" && exists(bin+".cmd"))
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

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
