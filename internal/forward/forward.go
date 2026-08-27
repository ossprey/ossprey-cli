// Package forward implements the package-manager forwarder: it inspects an
// install command (npm/yarn/pip/poetry/uv), checks the named packages against
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
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/shim"
	"github.com/ossprey/ossprey-cli/internal/submit"
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

// Manager describes a supported package manager and how to recognise its
// install command.
type Manager struct {
	Bin       string // executable name, e.g. "npm"
	Ecosystem string // "npm" or "pypi"
	installAt func(args []string) (specStart int, ok bool)
}

// managers is the registry of supported forwarders. Install verbs include both
// the package-adding forms (`npm install <pkg>`, `yarn add <pkg>`) and the
// manifest-installing forms with no named packages (`npm install`, `npm ci`,
// `yarn install`, `poetry install`, `uv sync`); the latter trigger a project
// manifest scan instead of falling through unchecked (OSS-1284).
var managers = map[string]*Manager{
	"npm":    {Bin: "npm", Ecosystem: "npm", installAt: verbAt("npm", "install", "i", "add", "ci", "update", "up")},
	"pnpm":   {Bin: "pnpm", Ecosystem: "npm", installAt: verbAt("pnpm", "install", "i", "add", "update", "up")},
	"yarn":   {Bin: "yarn", Ecosystem: "npm", installAt: verbAt("yarn", "add", "install", "upgrade", "up")},
	"pip":    {Bin: "pip", Ecosystem: "pypi", installAt: verbAt("pip", "install")},
	"pip3":   {Bin: "pip3", Ecosystem: "pypi", installAt: verbAt("pip3", "install")},
	"poetry": {Bin: "poetry", Ecosystem: "pypi", installAt: verbAt("poetry", "add", "install", "update", "lock")},
	// uv: `uv add <pkg>`, `uv sync`, and `uv pip install <pkg>`.
	"uv": {Bin: "uv", Ecosystem: "pypi", installAt: uvInstallAt},
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
	SkipCI        bool
	CacheScanOnly bool
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

	finish := func(sbom *ossbom.SBOM, err error) error {
		if opts.CacheScanOnly {
			if err != nil {
				fmt.Fprintf(os.Stderr, "ossprey: warning: could not post scan (%v); forwarding\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "ossprey: scan posted to the Ossprey dashboard (ci-cache-scan-only); forwarding")
			}
			return execFn(ctx, m.Bin, opts.Args)
		}
		if err != nil {
			return err
		}
		return reportAndForward(ctx, m, opts, sbom)
	}

	resolve := opts.ResolveLatest
	if resolve == nil {
		resolve = registry.ResolveLatest
	}

	start, isInstall := m.installAt(opts.Args)
	if !isInstall {
		// Not an install (e.g. `npm run`, `pip list`) — nothing to check.
		return execFn(ctx, m.Bin, opts.Args)
	}

	if opts.SkipCI {
		fmt.Fprintf(os.Stderr, "ossprey: skip-ci set; forwarding `%s %s` without checking\n",
			m.Bin, strings.Join(opts.Args, " "))
		return execFn(ctx, m.Bin, opts.Args)
	}

	parsed := ParseSpecs(m, opts.Args[start:])

	switch {
	case len(parsed.Specs) > 0:
		// Explicit packages named — check exactly those.
		if other := slices.Concat(parsed.NonPackages, parsed.ReqFiles); len(other) > 0 {
			fmt.Fprintf(os.Stderr, "ossprey: not checking non-registry install targets: %s (run `ossprey scan` for full coverage)\n",
				strings.Join(other, ", "))
		}
		resolved := resolveSpecs(ctx, resolve, parsed.Specs)
		if len(resolved) == 0 {
			fmt.Fprintln(os.Stderr, "ossprey: nothing left to check after version resolution; forwarding")
			return execFn(ctx, m.Bin, opts.Args)
		}
		return finish(checkFn(ctx, check.Options{
			Specs:      resolved,
			APIURL:     opts.APIURL,
			APIKey:     opts.APIKey,
			SubmitOnly: opts.CacheScanOnly,
		}))

	case manifestInstall(parsed):
		// No packages named — the manager installs from the project manifest /
		// lockfile. Scan the project and check every declared dependency rather
		// than falling through unchecked.
		fmt.Fprintf(os.Stderr, "ossprey: no packages named; scanning project manifest before `%s %s`\n",
			m.Bin, strings.Join(opts.Args, " "))
		return finish(scanProjectFn(ctx, ".", opts.APIURL, opts.APIKey, opts.CacheScanOnly))

	default:
		// Only un-checkable explicit targets (local paths, archives, URLs, VCS
		// refs). Can't verify them against a registry — forward with a warning.
		fmt.Fprintf(os.Stderr, "ossprey: not checking non-registry install targets: %s; forwarding (run `ossprey scan` after install)\n",
			strings.Join(parsed.NonPackages, ", "))
		return execFn(ctx, m.Bin, opts.Args)
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
				fmt.Fprintf(os.Stderr, "ossprey: could not resolve latest version of %s/%s (%v); skipping its check\n",
					s.Ecosystem, s.Name, err)
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
	if reports, hasMalware := scan.MalwareReports(sbom); hasMalware {
		for _, msg := range reports {
			fmt.Fprintln(os.Stderr, "Error: "+msg)
		}
		fmt.Fprintf(os.Stderr, "ossprey: blocked `%s %s`\n", m.Bin, strings.Join(opts.Args, " "))
		return ErrBlocked
	}
	// Both messages sit after the malware check, never in front of it: gating the
	// block on a component count would forward an SBOM that carried a verdict but
	// no components.
	if n := len(sbom.Components); n == 0 {
		// Nothing catalogued means nothing verified, whether the project declares
		// nothing or every cataloger failed. "No malware found" would read as a
		// clean bill of health for an install that was never checked.
		fmt.Fprintf(os.Stderr, "ossprey: found no dependencies to check; forwarding `%s %s` unchecked\n",
			m.Bin, strings.Join(opts.Args, " "))
	} else {
		// The count is load-bearing: "no malware found" alone read the same
		// whether 40 packages were checked or none were.
		fmt.Fprintf(os.Stderr, "ossprey: no malware found in %s, forwarding to %s\n",
			countPackages(n), m.Bin)
	}
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

// scanProject catalogs dir, submits the resulting SBOM to the Ossprey API, and
// returns it with any vulnerabilities applied. It is the default scanProjectFn
// seam. When the directory has no catalogable dependencies it returns the empty
// SBOM without an API call so a bare install in a non-project dir forwards.
func scanProject(ctx context.Context, dir, apiURL, apiKey string, submitOnly bool) (*ossbom.SBOM, error) {
	sbom, err := scan.Run(ctx, scan.Options{Path: dir})
	if err != nil {
		return nil, err
	}
	if len(sbom.Components) == 0 {
		return sbom, nil // nothing declared to check
	}
	if submitOnly {
		if err := submit.Post(ctx, sbom, apiURL, apiKey); err != nil {
			return nil, err
		}
		return sbom, nil
	}
	if err := submit.Validate(ctx, sbom, apiURL, apiKey); err != nil {
		return nil, err
	}
	return sbom, nil
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
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
