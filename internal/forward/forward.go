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
	"strings"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
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
	"npm":    {Bin: "npm", Ecosystem: "npm", installAt: verbAt(0, "install", "i", "add", "ci")},
	"yarn":   {Bin: "yarn", Ecosystem: "npm", installAt: verbAt(0, "add", "install")},
	"pip":    {Bin: "pip", Ecosystem: "pypi", installAt: verbAt(0, "install")},
	"poetry": {Bin: "poetry", Ecosystem: "pypi", installAt: verbAt(0, "add", "install")},
	// uv: `uv add <pkg>`, `uv sync`, and `uv pip install <pkg>`.
	"uv": {Bin: "uv", Ecosystem: "pypi", installAt: uvInstallAt},
}

// Managers returns the names of every supported forwarder, for CLI wiring.
func Managers() []string {
	out := make([]string, 0, len(managers))
	for name := range managers {
		out = append(out, name)
	}
	return out
}

// Lookup returns the Manager for a binary name.
func Lookup(bin string) (*Manager, bool) {
	m, ok := managers[bin]
	return m, ok
}

// verbAt returns an installAt matcher: args[idx] must equal one of verbs, and
// the package specs begin at idx+1.
func verbAt(idx int, verbs ...string) func([]string) (int, bool) {
	return func(args []string) (int, bool) {
		if len(args) <= idx {
			return 0, false
		}
		if slices.Contains(verbs, args[idx]) {
			return idx + 1, true
		}
		return 0, false
	}
}

// uvInstallAt matches `uv add ...`, `uv sync`, and `uv pip install ...`.
func uvInstallAt(args []string) (int, bool) {
	if len(args) >= 1 && (args[0] == "add" || args[0] == "sync") {
		return 1, true
	}
	if len(args) >= 2 && args[0] == "pip" && args[1] == "install" {
		return 2, true
	}
	return 0, false
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

	resolve := opts.ResolveLatest
	if resolve == nil {
		resolve = registry.ResolveLatest
	}

	start, isInstall := m.installAt(opts.Args)
	if !isInstall {
		// Not an install (e.g. `npm run`, `pip list`) — nothing to check.
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
		sbom, err := checkFn(ctx, check.Options{Specs: resolved, APIURL: opts.APIURL, APIKey: opts.APIKey})
		if err != nil {
			return err
		}
		return reportAndForward(ctx, m, opts, sbom)

	case manifestInstall(parsed):
		// No packages named — the manager installs from the project manifest /
		// lockfile. Scan the project and check every declared dependency rather
		// than falling through unchecked.
		fmt.Fprintf(os.Stderr, "ossprey: no packages named; scanning project manifest before `%s %s`\n",
			m.Bin, strings.Join(opts.Args, " "))
		sbom, err := scanProjectFn(ctx, ".", opts.APIURL, opts.APIKey)
		if err != nil {
			return err
		}
		return reportAndForward(ctx, m, opts, sbom)

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
	fmt.Fprintln(os.Stderr, "ossprey: no malware found, forwarding to "+m.Bin)
	return execFn(ctx, m.Bin, opts.Args)
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
func scanProject(ctx context.Context, dir, apiURL, apiKey string) (*ossbom.SBOM, error) {
	sbom, err := scan.Run(ctx, scan.Options{Path: dir})
	if err != nil {
		return nil, err
	}
	if len(sbom.Components) == 0 {
		return sbom, nil // nothing declared to check
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
var valueFlags = map[string]map[string]bool{
	"npm": flagSet("--registry", "--prefix", "-C", "--cache", "--userconfig",
		"--globalconfig", "--tag", "--otp", "-w", "--workspace", "--omit", "--include"),
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
	path, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("%s not found on PATH: %w", bin, err)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
