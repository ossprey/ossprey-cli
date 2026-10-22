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

// expandFn predicts what the named packages bring in; a test seam.
var expandFn = expandInstall

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
// check. With expand, the tree they bring in is resolved first and every
// package in it is checked at the release the manager picked — the named
// ones included, which is a better answer than the registry's "latest"
// guess. Without it (a tool run, whose fetched package runs rather than
// installs), or when the resolution fails, the names alone are resolved as
// before.
//
// A dependency the project's lockfile already pinned is not what this
// install brings in, so it is left to the project scan. Trusted sources
// apply to the whole tree, now that the resolver has said where each
// package comes from.
func resolveNamed(ctx context.Context, m *Manager, opts Options, start int, parsed installArgs,
	resolve func(context.Context, string, string, string) (string, error), expand bool) checkSet {
	var set checkSet
	var tree []catalog.Resolved
	if expand {
		var err error
		tree, err = expandFn(ctx, m, opts.Args, start, parsed)
		if err != nil {
			reportUnexpanded(ctx, parsed.Specs, err, opts.Passive)
		}
		set.expanded = err == nil
	}

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
// With collect (passive mode) the line is only collected: it would otherwise
// print from beside the running manager, which owns the terminal, and a
// passive run blocks nothing on the answer anyway.
func reportUnexpanded(ctx context.Context, specs []check.Spec, err error, collect bool) {
	headline, detail := catalog.ResolveFailure(err)
	line := fmt.Sprintf("could not resolve the dependencies of %s (%s); checking the named packages only",
		joinNames(specs), headline)
	if collect || (env.Verbose() && len(detail) > 0) {
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
func expandInstall(ctx context.Context, m *Manager, args []string, start int, parsed installArgs) ([]catalog.Resolved, error) {
	rest := args[start:]
	tokens := specTokens(m, parsed)
	switch m.Ecosystem {
	case "npm":
		return catalog.ResolveNpmInstall(ctx, npmProjectDir(m, args), tokens, npmResolveFlags(m, rest))
	case "pypi":
		if hasFlag(rest, "--no-deps") {
			return nil, nil
		}
		return catalog.ResolvePythonInstall(ctx, ".", tokens, uvResolveFlags(m, rest), pipResolveFlags(m, rest))
	}
	return nil, nil
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
	"--omit", "--include", "--registry", "--before", "--tag")

func npmResolveFlags(m *Manager, rest []string) []string {
	if m.Bin != "npm" {
		return nil
	}
	return pickFlags(rest, valueFlags[m.Bin], npmPassFlags, nil)
}

// Flags the pip and uv resolvers read the same way.
var pythonCommonFlags = flagSet("--pre", "--no-index", "-i", "--index-url", "--extra-index-url",
	"-f", "--find-links", "-c", "--constraint", "--python-version", "--keyring-provider")

// uvOnlyFlags are uv's own, passed when uv resolves a uv command.
var uvOnlyFlags = flagSet("--index", "--default-index", "--prerelease", "--resolution",
	"--exclude-newer", "-p", "--python", "--python-platform", "--allow-insecure-host",
	"--index-strategy", "--only-binary", "--no-binary", "--constraints")

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

// pipResolveFlags are passed to `pip install --dry-run`. uv's --index and
// --default-index are pip's --extra-index-url and --index-url.
func pipResolveFlags(m *Manager, rest []string) []string {
	switch m.Bin {
	case "pip", "pip3":
		return pickFlags(rest, valueFlags[m.Bin], union(pythonCommonFlags, pipOnlyFlags), nil)
	case "uv":
		return pickFlags(rest, valueFlags[m.Bin], union(pythonCommonFlags, flagSet("--index", "--default-index")),
			map[string]string{"--index": "--extra-index-url", "--default-index": "--index-url"})
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
