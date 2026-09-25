package forward

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/warn"
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
// Which flags take a value is npm's call, not ours, and it changes between
// npm versions; see npx_flags.go.

// npxInstallAt matches every npx invocation; npxParse decides what, if
// anything, it fetches.
func npxInstallAt([]string) (int, bool) { return 0, true }

// localBinFn reports whether name is already installed in the project npx is
// run from. Overridable in tests.
var localBinFn = localBin

// npxParse classifies an npx command line into the packages it will fetch.
// A spec's Version is either an exact release or the specifier as written (a
// dist-tag or range), which resolveNpxSpecifiers turns into the release npm
// would pick.
func npxParse(args []string) installArgs {
	var (
		packages []string
		// candidates are the tokens that may be the package when no --package
		// is given: the first positional, plus the value of any flag whose
		// meaning depends on the npm version.
		candidates []string
		// redirected is set by --prefix, which moves the project npx looks in
		// for local bins away from the one localBin would search.
		redirected bool
		pick       npxPick
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" {
			continue
		}
		if a == "--" {
			// Option parsing ends; the next token is the command.
			if i+1 < len(args) {
				candidates = append(candidates, args[i+1])
			}
			break
		}
		if !strings.HasPrefix(a, "-") {
			candidates = append(candidates, a)
			break
		}
		key, value, hasInline := splitFlagValue(strings.TrimLeft(a, "-"))
		if long, ok := npxShorthands[key]; ok {
			if long == "" {
				continue // carries its own value, e.g. -s is --loglevel silent
			}
			key = long
		}
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch {
		case key == "package":
			if !hasInline {
				if i+1 >= len(args) {
					continue
				}
				value = next
				i++
			}
			packages = append(packages, value)
		case key == "tag" || key == "before":
			if !hasInline {
				if i+1 >= len(args) {
					continue
				}
				value = next
				i++
			}
			if key == "tag" {
				pick.tag, pick.tagSet = value, true
			} else {
				pick.before, pick.beforeSet = value, true
			}
		case key == "prefix":
			redirected = true
			if !hasInline && i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(key, "no-") || npxSwitches[key]:
			// nopt reads every --no-* as a boolean, and lets any boolean take
			// an explicit true/false.
			if !hasInline && (next == "true" || next == "false") {
				i++
			}
		case npxOptions[key]:
			if !hasInline && i+1 < len(args) {
				i++
			}
		default:
			// Unknown, or a value in some npm and a boolean in others. Under
			// one reading the next token is this flag's value, under the other
			// it is the package — so check it, and keep reading for the
			// package the first reading would run.
			if !hasInline && next != "" && !strings.HasPrefix(next, "-") {
				candidates = append(candidates, next)
				i++
			}
		}
	}

	// With -p the positional is a bin those packages provide; without it the
	// positional is the package itself.
	asCommand := len(packages) == 0
	if asCommand {
		packages = candidates
	}

	out := installArgs{npmPick: pick.withEnv()}
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
		if v, ok := exactNpmVersion(s.Version); ok {
			s.Version = v
		}
		// A name with no specifier that is already in the project's
		// node_modules runs from there: npx fetches nothing, so there is
		// nothing to check here (the install that put it there is what the
		// other forwarders check). `npx eslint` is overwhelmingly this case.
		// Not under --prefix, which points npx at a different project.
		if s.Version == "" && !redirected && localBinFn(s.Name, asCommand) {
			continue
		}
		out.Specs = append(out.Specs, s)
	}
	return out
}

// exactNpmVersion reports whether v names exactly one release, normalised the
// way npm normalises it (`v1.2.3` and `=1.2.3` are 1.2.3).
func exactNpmVersion(v string) (string, bool) {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "="), "v")
	if _, err := semver.StrictNewVersion(v); err != nil {
		return "", false
	}
	return v, true
}

// npxPick is the npm config, as npx was given it, that changes which release
// a specifier names. Flags win over npm_config_* environment variables, as in
// npm. A .npmrc can set these too and is not read here.
type npxPick struct {
	tag, before       string
	tagSet, beforeSet bool
}

func (p npxPick) withEnv() npxPick {
	if !p.tagSet {
		p.tag, p.tagSet = npmConfigEnv("tag")
	}
	if !p.beforeSet {
		p.before, p.beforeSet = npmConfigEnv("before")
	}
	return p
}

// npmConfigEnv reads npm_config_<key>, which npm matches case-insensitively.
func npmConfigEnv(key string) (string, bool) {
	prefix := "npm_config_" + key + "="
	for _, kv := range os.Environ() {
		if len(kv) >= len(prefix) && strings.EqualFold(kv[:len(prefix)], prefix) {
			return kv[len(prefix):], true
		}
	}
	return "", false
}

// npmDateLayouts are the spellings of a --before date this parser accepts: the
// ISO forms npm's own docs use, and the long forms JavaScript's Date prints.
var npmDateLayouts = []string{
	time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02T15:04:05", "2006-01-02T15:04",
	"2006-01-02 15:04:05", "2006-01-02", time.RFC1123, time.RFC1123Z,
	"Mon Jan 02 2006 15:04:05 GMT-0700", "Jan 2 2006", "January 2 2006", "Jan 2, 2006",
	"January 2, 2006",
}

// parseNpmDate reads a --before value. A date alone is midnight UTC and a date
// and time with no zone is local, which is how JavaScript's Date reads them.
func parseNpmDate(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	for _, layout := range npmDateLayouts {
		loc := time.Local
		if layout == "2006-01-02" || strings.Contains(layout, "Z07") || strings.Contains(layout, "MST") ||
			strings.Contains(layout, "-0700") {
			loc = time.UTC
		}
		if t, err := time.ParseInLocation(layout, v, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// resolveNpxSpecifiers turns every spec that is not an exact release — an
// unpinned name, a dist-tag or a range — into the release npm would run for it,
// honouring --tag and --before. Checking latest instead would pass a clean
// latest while npx runs whatever `@next`, an older major line, a deprecated
// latest or a cut-off date points at. A spec that cannot be resolved is treated
// like a registry outage: warned about and not checked, never reported clean.
func resolveNpxSpecifiers(ctx context.Context, resolve func(context.Context, string, string, registry.NpmPick) (string, error), p npxPick, specs []check.Spec) []check.Spec {
	pick := registry.NpmPick{DefaultTag: p.tag}
	// npm may read a date we cannot, and guessing would check a release other
	// than the one it runs, so an unreadable one skips every check it affects.
	beforeUnreadable := false
	if p.beforeSet && p.before != "" {
		t, ok := parseNpmDate(p.before)
		pick.Before, beforeUnreadable = t, !ok
	}
	out := make([]check.Spec, 0, len(specs))
	for _, s := range specs {
		if _, exact := exactNpmVersion(s.Version); !exact {
			if beforeUnreadable {
				warn.Add(ctx, warn.Entry{
					Class: "npx-before-unreadable",
					One:   "1 package's version depends on a --before date ossprey cannot read; skipping its check",
					Many:  "%d packages' versions depend on a --before date ossprey cannot read; skipping their checks",
					Item:  fmt.Sprintf("npm/%s (--before %q)", s.Name, p.before),
				})
				continue
			}
			v, err := resolve(ctx, s.Name, s.Version, pick)
			if err != nil {
				warn.Add(ctx, registry.UnresolvedEntry(s.Ecosystem, s.Name, err, "skipping its check"))
				continue
			}
			s.Version = v
		}
		out = append(out, s)
	}
	return out
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
