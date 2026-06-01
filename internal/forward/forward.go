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
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
)

// Test seams: overridable in tests so Run's decision logic can be exercised
// without a real package manager on PATH or a live API.
var (
	execFn  = Exec
	checkFn = check.Run
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

// managers is the registry of supported forwarders.
var managers = map[string]*Manager{
	"npm":    {Bin: "npm", Ecosystem: "npm", installAt: verbAt(0, "install", "i", "add", "ci")},
	"yarn":   {Bin: "yarn", Ecosystem: "npm", installAt: verbAt(0, "add")},
	"pip":    {Bin: "pip", Ecosystem: "pypi", installAt: verbAt(0, "install")},
	"poetry": {Bin: "poetry", Ecosystem: "pypi", installAt: verbAt(0, "add")},
	// uv: both `uv add <pkg>` and `uv pip install <pkg>`.
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

// uvInstallAt matches `uv add ...` and `uv pip install ...`.
func uvInstallAt(args []string) (int, bool) {
	if len(args) >= 1 && args[0] == "add" {
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
//  2. Parse named package specs, resolving latest versions where unpinned.
//  3. Check them against the API; block (ErrBlocked) on malware.
//  4. Otherwise exec the real manager with the original args.
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

	specs := ParseSpecs(m, opts.Args[start:])
	if len(specs) == 0 {
		fmt.Fprintf(os.Stderr, "ossprey: no checkable packages found in `%s %s`; forwarding without a scan\n",
			m.Bin, strings.Join(opts.Args, " "))
		return execFn(ctx, m.Bin, opts.Args)
	}

	// Resolve latest versions for unpinned packages. Fail open: a registry
	// outage must not block the developer — warn and skip checking that one.
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

	if len(resolved) == 0 {
		fmt.Fprintln(os.Stderr, "ossprey: nothing left to check after version resolution; forwarding")
		return execFn(ctx, m.Bin, opts.Args)
	}

	sbom, err := checkFn(ctx, check.Options{
		Specs:  resolved,
		APIURL: opts.APIURL,
		APIKey: opts.APIKey,
	})
	if err != nil {
		return err
	}

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

// ParseSpecs extracts package specs from the install arguments (everything
// after the install verb). Flags (tokens starting with '-') are skipped.
func ParseSpecs(m *Manager, args []string) []check.Spec {
	var specs []check.Spec
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		s, err := check.ParseSpec(m.Ecosystem, a)
		if err != nil {
			continue
		}
		specs = append(specs, s)
	}
	return specs
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
