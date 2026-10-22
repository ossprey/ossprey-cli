package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// Resolved is one package a manager would install for a named install, as the
// manager's own kind of resolver reports it.
//
// This is the forwarder's view of an install before it happens: `npm install
// express` puts 65 packages on disk, and checking the one named left the other
// 64 — where a planted dependency actually lives — unchecked (OSS-2481).
type Resolved struct {
	Name    string
	Version string
	// Registry is where the package is fetched from, when the resolver said.
	Registry string
	// Locked marks a package the project's lockfile already carried before this
	// install, so the install is not what brings it in.
	Locked bool
	// npm's dependency kinds, as the lock records them whatever the omit
	// policy: an install with --omit=dev leaves a Dev package out,
	// --omit=optional an Optional one, --omit=peer a Peer one, and a
	// DevOptional one — reached both ways — only when both are omitted. A
	// release found at several paths carries a kind only if every copy does.
	Dev, Optional, DevOptional, Peer bool
}

// ErrNoResolver reports that no tool on the host can predict the install.
var ErrNoResolver = errors.New("no resolver on PATH")

// ErrNeedsUV reports a uv command only uv can predict, on a host with no
// working uv: one whose flags pip's dry run cannot honour, so it would pick
// releases by a different rule (see ResolvePythonInstallWithUV).
var ErrNeedsUV = errors.New("its uv flags need uv to resolve, and none works on PATH")

// ResolveNpmInstall predicts what `npm install <specs>` would put in the tree,
// by generating a lockfile in a throwaway copy of the project — never in the
// project itself — with `npm install --package-lock-only --ignore-scripts`,
// the same resolution the project scan trusts. Nothing is installed and no
// package's scripts run.
//
// projectDir is the project the install lands in, or "" for an install with
// no project context (global, redirected elsewhere, or a yarn/pnpm lockfile
// npm cannot read). With a project, its package.json, .npmrc and npm lockfile
// are copied in so npm keeps the versions the project already pins, and the
// packages that lockfile already named come back Locked. Local and workspace
// dependencies are dropped from the copy, since their paths do not exist
// there. Without one, configDir names the directory whose .npmrc npm reads as
// the command's project configuration (npm's local prefix), or "" when it
// reads none, as in global mode. flags are passed to npm after its own.
func ResolveNpmInstall(ctx context.Context, projectDir, configDir string, specs, flags []string) ([]Resolved, error) {
	npm, err := lookTool("npm")
	if err != nil {
		return nil, fmt.Errorf("%w (npm)", ErrNoResolver)
	}
	tmp, err := os.MkdirTemp("", "ossprey-npm-install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	locked := map[string]bool{}
	if projectDir != "" {
		if err := stageNpmProject(projectDir, tmp, locked); err != nil {
			return nil, err
		}
	} else if configDir != "" {
		// No project, but npm still reads a project-level .npmrc: a scoped
		// private registry applies to `npx @org/cli` too.
		if err := stageNpmrc(configDir, tmp); err != nil {
			return nil, err
		}
	}

	args := append([]string{"install",
		"--package-lock-only",
		"--ignore-scripts",
		"--no-audit",
		"--no-fund",
		"--no-update-notifier",
	}, flags...)
	args = append(args, specs...)

	budget := resolverTimeout()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := exec.CommandContext(ctx, npm, args...)
	cmd.Dir = tmp
	// The user's own cache, not a throwaway: the packuments npm fetches here
	// are the ones the real install is about to ask for.
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("npm timed out after %s (raise OSSPREY_RESOLVE_TIMEOUT)", budget)
		}
		if !errors.Is(runErr, exec.ErrWaitDelay) {
			return nil, newToolError("npm", "resolve", string(out))
		}
	}
	lock, err := os.ReadFile(filepath.Join(tmp, "package-lock.json"))
	if err != nil {
		return nil, fmt.Errorf("npm produced no package-lock.json: %w", err)
	}
	pkgs, err := parseNpmLock(lock, file.Location{})
	if err != nil {
		return nil, err
	}
	return resolvedFromPackages(pkgs, locked), nil
}

// stageNpmProject copies what npm needs to resolve as the project would into
// dst: package.json with its local dependencies removed, .npmrc for registry
// configuration, and the npm lockfile where there is one, recording every
// package that lockfile already names in locked.
func stageNpmProject(src, dst string, locked map[string]bool) error {
	data, err := os.ReadFile(filepath.Join(src, "package.json"))
	if err != nil {
		return err
	}
	cleaned, err := localFreePackageJSON(data)
	if err != nil {
		return fmt.Errorf("package.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dst, "package.json"), cleaned, 0o644); err != nil {
		return err
	}
	if err := stageNpmrc(src, dst); err != nil {
		return err
	}
	// A shrinkwrap outranks a package-lock, and is staged under the lock's
	// name so npm writes its result where it is read back from.
	for _, name := range []string{"npm-shrinkwrap.json", "package-lock.json"} {
		lock, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			continue
		}
		if pkgs, err := parseNpmLock(lock, file.Location{}); err == nil {
			for _, p := range pkgs {
				locked[p.Name+"@"+p.Version] = true
			}
		}
		return os.WriteFile(filepath.Join(dst, "package-lock.json"), lock, 0o644)
	}
	return nil
}

// stageNpmrc copies the .npmrc npm would read in src, where there is one, so
// the dry run resolves against the same registries as the real command.
func stageNpmrc(src, dst string) error {
	rc, err := os.ReadFile(filepath.Join(src, ".npmrc"))
	if err != nil {
		return nil
	}
	return os.WriteFile(filepath.Join(dst, ".npmrc"), rc, 0o600)
}

// localFreePackageJSON drops the dependencies npm could only resolve from the
// project's own disk — file:, link:, workspace: and path specs — and the
// workspaces field, which names directories the copy does not have. What is
// left resolves from registries alone.
func localFreePackageJSON(data []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	delete(doc, "workspaces")
	for _, field := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		deps, ok := doc[field].(map[string]any)
		if !ok {
			continue
		}
		for name, v := range deps {
			spec, _ := v.(string)
			if isLocalNpmSpec(spec) {
				delete(deps, name)
			}
		}
	}
	return json.Marshal(doc)
}

// isLocalNpmSpec reports whether a package.json dependency spec names
// something on the local disk rather than a registry or a remote.
func isLocalNpmSpec(spec string) bool {
	s := strings.TrimSpace(spec)
	if s == "." || s == ".." {
		return true
	}
	for _, p := range []string{"file:", "link:", "workspace:", "portal:", "./", "../", "/", "~/", `.\`, `..\`} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// resolvedFromPackages converts resolver output, marking the packages the
// project already locked and dropping anything not fetched from a registry
// (a git dependency, which no registry can be asked about).
func resolvedFromPackages(pkgs []pkg.Package, locked map[string]bool) []Resolved {
	out := make([]Resolved, 0, len(pkgs))
	for _, p := range pkgs {
		reg := registryOf(p)
		if strings.HasPrefix(reg, "git") {
			continue
		}
		rs, _ := p.Metadata.(registrySource)
		out = append(out, Resolved{
			Name:        p.Name,
			Version:     p.Version,
			Registry:    reg,
			Locked:      locked[p.Name+"@"+p.Version],
			Dev:         rs.Dev,
			Optional:    rs.Optional,
			DevOptional: rs.DevOptional,
			Peer:        rs.Peer,
		})
	}
	return out
}

// ResolvePythonInstall predicts what installing the named requirements brings
// in, with uv where the host has one (as the project scan prefers) and pip's
// dry run otherwise. Neither installs anything.
//
// Both are told never to build a source distribution: resolving a package
// that ships only an sdist means running its build backend, which is code
// from the very tree being checked. Such a package fails the resolution, and
// the caller falls back to checking the names alone, rather than running it.
//
// dir is where the resolver runs: where relative paths in the flags resolve
// and whose configuration (uv.toml, [tool.uv]) uv reads. "" runs it in a
// scratch directory with no project configuration at all, as uv's own tool
// commands do (`uvx` reads user and system configuration only); the caller
// then makes any path in the flags absolute. uvFlags go to `uv pip compile`,
// pipFlags to `pip install`, whichever is used.
func ResolvePythonInstall(ctx context.Context, dir string, specs, uvFlags, pipFlags []string) ([]Resolved, error) {
	if uv, ok := lookupUV(ctx); ok {
		return resolveWithUV(ctx, uv, dir, specs, uvFlags)
	}
	python, ok := findPython(ctx)
	if !ok {
		return nil, fmt.Errorf("%w (uv or python)", ErrNoResolver)
	}
	v, ok := pipReportVersion(ctx, python)
	if !ok {
		return nil, fmt.Errorf("%w (%s has no usable pip)", ErrNoResolver, python)
	}
	if v.olderThan(pipMinimum) {
		return nil, fmt.Errorf("pip %s is older than %s (needs --dry-run --report)", v, pipMinimum)
	}
	return resolveWithPip(ctx, python, dir, specs, pipFlags)
}

// ResolvePythonInstallWithUV is ResolvePythonInstall with no pip fallback,
// for a uv command whose flags pip cannot honour: `--index` and
// `--extra-index-url` make uv take a package from the first index that has
// it, where pip takes the best version across every index; `--overrides`,
// `--resolution`, `--exclude-newer` and the like change which release is
// picked and have no pip spelling. pip's dry run could then check a release
// uv does not install, with nothing saying so. Without a working uv it fails
// with ErrNeedsUV, and the caller checks the names.
func ResolvePythonInstallWithUV(ctx context.Context, dir string, specs, uvFlags []string) ([]Resolved, error) {
	uv, ok := lookupUV(ctx)
	if !ok {
		return nil, ErrNeedsUV
	}
	return resolveWithUV(ctx, uv, dir, specs, uvFlags)
}

// resolveWithUV compiles the requirements with `uv pip compile`, which
// resolves for this interpreter and platform — what `uv pip install` or `pip
// install` would put in the environment, not a universal lock.
func resolveWithUV(ctx context.Context, uv, dir string, specs, flags []string) ([]Resolved, error) {
	tmp, err := os.MkdirTemp("", "ossprey-uv-install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	req := filepath.Join(tmp, "requirements.txt")
	if err := os.WriteFile(req, []byte(strings.Join(specs, "\n")+"\n"), 0o600); err != nil {
		return nil, err
	}

	args := append([]string{"pip", "compile",
		"--no-header",
		"--no-annotate",
		"--no-progress",
		"--no-build",
	}, flags...)
	args = append(args, req)
	if dir == "" {
		dir = tmp
	}

	budget := resolverTimeout()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	cmd := exec.CommandContext(ctx, uv, args...)
	cmd.Dir = dir
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	stdout, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("uv timed out after %s (raise OSSPREY_RESOLVE_TIMEOUT)", budget)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, newToolError("uv", "resolve", string(ee.Stderr))
		}
		return nil, fmt.Errorf("uv: %w", err)
	}
	return resolvedFromPackages(parseUVOutput(stdout, file.Location{}), nil), nil
}

// resolveWithPip runs pip's dry run over the named requirements. Wheels only:
// see ResolvePythonInstall.
func resolveWithPip(ctx context.Context, python, dir string, specs, flags []string) ([]Resolved, error) {
	tmp, err := os.MkdirTemp("", "ossprey-pip-install-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	args := append([]string{"--only-binary=:all:"}, flags...)
	args = append(args, specs...)
	if dir == "" {
		dir = tmp
	}
	pkgs, err := runPipResolve(ctx, python, tmp, "", dir, args, file.Location{})
	if err != nil {
		return nil, err
	}
	return resolvedFromPackages(pkgs, nil), nil
}

// ResolveFailure splits a resolver's error into the one line worth printing
// and the tool's own output, which only a verbose run wants — the same split
// the catalogers make, so uv's or npm's `error:` lines never read as ossprey's.
func ResolveFailure(err error) (headline string, detail []string) {
	var te *toolError
	if errors.As(err, &te) {
		return te.tool + ": " + te.summary, te.detail
	}
	return err.Error(), nil
}
