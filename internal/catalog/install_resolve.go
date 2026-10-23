package catalog

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
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

// UVCacheDir is where uv keeps its cache for a tool run (`uv cache dir`),
// which honours UV_CACHE_DIR, a user-level uv.toml and the configuration
// flags given (--config-file, --no-config). It is asked from a scratch
// directory because a tool run reads no project configuration, while `uv
// cache dir` in a project whose uv.toml names a cache-dir would answer for
// the project (verified: uvx ignores that file, `uv cache dir` reports it).
// The answer may be relative, as uv printed it; the caller resolves it
// against the directory the run changes to.
func UVCacheDir(ctx context.Context, flags []string) (string, error) {
	uv, err := lookTool("uv")
	if err != nil {
		return "", fmt.Errorf("%w (uv)", ErrNoResolver)
	}
	scratch, err := os.MkdirTemp("", "ossprey-uv-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(scratch)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, uv, append([]string{"cache", "dir"}, flags...)...)
	cmd.Dir = scratch
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("uv cache dir: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// UVToolDir is where uv keeps installed tools (`uv tool dir`), which
// honours UV_TOOL_DIR, a user-level uv.toml and the configuration flags
// given; asked from a scratch directory for the reason UVCacheDir is.
func UVToolDir(ctx context.Context, flags []string) (string, error) {
	uv, err := lookTool("uv")
	if err != nil {
		return "", fmt.Errorf("%w (uv)", ErrNoResolver)
	}
	scratch, err := os.MkdirTemp("", "ossprey-uv-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(scratch)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, uv, append([]string{"tool", "dir"}, flags...)...)
	cmd.Dir = scratch
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("uv tool dir: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// UVInstalledTree is every package in the environment `uv tool install`
// keeps for name under toolDir (<toolDir>/<name>, a venv), or nil when the
// tool is not installed. `uvx <name>` runs that environment rather than
// resolving anything when the name is bare: no version, no `@latest`, no
// --with, no --isolated (verified against uv 0.11), so the releases that
// run are the ones installed back then.
func UVInstalledTree(toolDir, name string) ([]Resolved, error) {
	if toolDir == "" || name == "" {
		return nil, nil
	}
	for _, dir := range []string{canonicalPackageName(name), name} {
		env := filepath.Join(toolDir, dir)
		if _, err := os.Stat(filepath.Join(env, "pyvenv.cfg")); err != nil {
			continue
		}
		return venvPackages(env)
	}
	return nil, nil
}

// UVCachedTree is every package installed in a tool environment uv has
// cached under cacheDir that holds all of want (canonical PyPI name to the
// exact version asked for, "" for any), or nil when none does. `uvx` and
// `uv tool run` reuse such an environment (environments-v2/<key>/<key>, a
// venv) when it satisfies the request, with the dependencies it resolved
// back then, so a check of the run must cover both. Which environment uv
// would pick is its own hash of the request; every candidate holding the
// named packages is read, which can only check more. Provenance is not
// recorded by the venv, so nothing read here is trusted by registry.
func UVCachedTree(cacheDir string, want map[string]string) ([]Resolved, error) {
	if cacheDir == "" || len(want) == 0 {
		return nil, nil
	}
	keys, err := os.ReadDir(filepath.Join(cacheDir, "environments-v2"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Resolved
	seen := map[string]bool{}
	for _, key := range keys {
		dir := filepath.Join(cacheDir, "environments-v2", key.Name())
		envs := []string{dir}
		if subs, err := os.ReadDir(dir); err == nil {
			for _, sub := range subs {
				envs = append(envs, filepath.Join(dir, sub.Name()))
			}
		}
		for _, env := range envs {
			if _, err := os.Stat(filepath.Join(env, "pyvenv.cfg")); err != nil {
				continue
			}
			pkgs, err := venvPackages(env)
			if err != nil {
				return nil, err
			}
			if !holdsAll(pkgs, want) {
				continue
			}
			for _, r := range pkgs {
				if k := canonicalPackageName(r.Name) + "@" + r.Version; !seen[k] {
					seen[k] = true
					out = append(out, r)
				}
			}
		}
	}
	return out, nil
}

// venvPackages reads the installed distributions of a virtual environment
// from the METADATA of each dist-info in its site-packages (lib/pythonX.Y
// on POSIX, Lib on Windows).
func venvPackages(env string) ([]Resolved, error) {
	// The patterns are relative to the environment, so a bracket or star
	// in the cache path is a path character, not a wildcard.
	var files []string
	for _, pattern := range []string{
		"lib/python*/site-packages/*.dist-info/METADATA",
		"Lib/site-packages/*.dist-info/METADATA",
	} {
		matches, err := fs.Glob(os.DirFS(env), pattern)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			files = append(files, filepath.Join(env, filepath.FromSlash(m)))
		}
	}
	var out []Resolved
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		// Core metadata field names are case-insensitive.
		var name, version string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				break // end of headers
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			switch {
			case strings.EqualFold(key, "Name") && name == "":
				name = strings.TrimSpace(value)
			case strings.EqualFold(key, "Version") && version == "":
				version = strings.TrimSpace(value)
			}
		}
		if name == "" || version == "" {
			continue
		}
		if k := canonicalPackageName(name) + "@" + version; !seen[k] {
			seen[k] = true
			out = append(out, Resolved{Name: name, Version: version})
		}
	}
	return out, nil
}

// pep440Version is PEP 440's public version syntax, each segment in its
// own group: epoch, release, pre-release letter and number, post-release
// (its word and number, or the bare "-N" form), dev-release word and
// number, local.
var pep440Version = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?` +
	`(?:(?:[-_.]?(post|rev|r)[-_.]?(\d*))|(?:-(\d+)))?` +
	`(?:[-_.]?(dev)[-_.]?(\d*))?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

// pep440Key is a version in PEP 440's normalised form, so that spellings
// the specification calls equal compare equal as strings: "6.1.0" and
// "6.1", "1.0-alpha1" and "1.0a1", "1.0.post1" and "1.0-1". The local
// segment is returned apart, since "==" without one matches any. ok is
// false for a version the specification does not describe.
func pep440Key(v string) (key, local string, ok bool) {
	m := pep440Version.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return "", "", false
	}
	release := strings.Split(m[2], ".")
	for len(release) > 1 && strings.Trim(release[len(release)-1], "0") == "" {
		release = release[:len(release)-1]
	}
	for i, seg := range release {
		release[i] = number(seg)
	}
	var b strings.Builder
	if m[1] != "" && number(m[1]) != "0" {
		b.WriteString(number(m[1]) + "!")
	}
	b.WriteString(strings.Join(release, "."))
	if m[3] != "" {
		letter := map[string]string{"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}[m[3]]
		if letter == "" {
			letter = m[3]
		}
		b.WriteString(letter + number(m[4]))
	}
	switch {
	case m[5] != "":
		b.WriteString(".post" + number(m[6]))
	case m[7] != "":
		b.WriteString(".post" + number(m[7]))
	}
	if m[8] != "" {
		b.WriteString(".dev" + number(m[9]))
	}
	return b.String(), localKey(m[10]), true
}

// localKey is a local version segment normalised: separators as ".", and
// an all-digit part as its number ("build.01" is "build.1").
func localKey(local string) string {
	if local == "" {
		return ""
	}
	parts := strings.Split(strings.NewReplacer("-", ".", "_", ".").Replace(local), ".")
	for i, part := range parts {
		if strings.Trim(part, "0123456789") == "" {
			parts[i] = number(part)
		}
	}
	return strings.Join(parts, ".")
}

func number(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// pep440Equal reports whether a candidate version satisfies "==want" as PEP
// 440 reads it: equal in normalised form, with the candidate's local
// segment ignored unless want names one. A version the specification does
// not describe counts as equal, so an environment is read rather than
// skipped on a spelling this does not understand.
func pep440Equal(want, have string) bool {
	wk, wl, ok := pep440Key(want)
	if !ok {
		return true
	}
	hk, hl, ok := pep440Key(have)
	if !ok {
		return true
	}
	return wk == hk && (wl == "" || wl == hl)
}

// holdsAll reports whether pkgs has every package in want, at the exact
// version where one is given, as PEP 440 compares versions.
func holdsAll(pkgs []Resolved, want map[string]string) bool {
	for name, version := range want {
		found := false
		for _, r := range pkgs {
			if canonicalPackageName(r.Name) == name && (version == "" || pep440Equal(version, r.Version)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// NpxCacheKey is the directory under npm's `_npx` cache that libnpmexec
// installs the given packages into: the first 16 hex digits of the SHA-512
// of the specs as typed, sorted as npm sorts them, newline-joined
// (libnpmexec/lib/index.js).
func NpxCacheKey(packages []string) string {
	sorted := slices.Clone(packages)
	slices.SortFunc(sorted, npmCollate)
	sum := sha512.Sum512([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// npmCollateOrder is the order node's `localeCompare('en')` (ICU root
// collation) gives printable ASCII at the primary level: punctuation and
// symbols first, then digits, then letters with case ignored. Byte order
// differs (`-` before `_`, uppercase before lowercase), and a key computed
// in byte order looks up a different cache entry than npm writes for
// `--package a_b --package a-b`. `TestNpmCollateMatchesNode` holds this to
// the installed node.
const npmCollateOrder = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$0123456789abcdefghijklmnopqrstuvwxyz"

// npmCollate orders two specs as libnpmexec does: by primary weight first
// (letters case-folded), then, for strings equal at that level, lowercase
// before uppercase at the first case difference, then byte order so the
// sort is total. Anything outside printable ASCII sorts after it, by code
// point; package specs are ASCII.
func npmCollate(a, b string) int {
	if c := slices.Compare(collationKey(a, false), collationKey(b, false)); c != 0 {
		return c
	}
	if c := slices.Compare(collationKey(a, true), collationKey(b, true)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func collationKey(s string, tertiary bool) []int {
	key := make([]int, 0, len(s))
	for _, r := range s {
		if tertiary {
			if r >= 'A' && r <= 'Z' {
				key = append(key, 1)
			} else {
				key = append(key, 0)
			}
			continue
		}
		lr := r
		if r >= 'A' && r <= 'Z' {
			lr = r + 'a' - 'A'
		}
		if i := strings.IndexRune(npmCollateOrder, lr); i >= 0 {
			key = append(key, i)
		} else {
			key = append(key, len(npmCollateOrder)+int(r))
		}
	}
	return key
}

// NpxCachedTree is the dependency tree an earlier `npx`/`npm exec` of the
// same packages left in npm's cache (npmCache/_npx/<key>/package-lock.json),
// or nil when there is none. npm reuses that installation when the package
// it holds still satisfies the request, with the dependencies it resolved
// back then — which a fresh resolution today may not name — so a check of
// the run must cover both.
func NpxCachedTree(npmCache string, packages []string) ([]Resolved, error) {
	if npmCache == "" || len(packages) == 0 {
		return nil, nil
	}
	dir := filepath.Join(npmCache, "_npx", NpxCacheKey(packages))
	lock, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	// Only what the earlier run installed can run again: the lock also
	// records what its omit policy left out.
	pkgs, err := parseNpmLockAt(lock, file.Location{}, dir)
	if err != nil {
		return nil, err
	}
	return resolvedFromPackages(pkgs, nil), nil
}

// NpmConfigGet reads one key of npm's effective configuration for a command
// run in dir with flags — the command line, the environment and the project,
// user and global .npmrc files, as `npm config get <key>` reports it. flags
// are the command's own location and config-file selectors (-g, --prefix,
// --userconfig, --globalconfig), so the answer is the one the real command
// sees. The value is returned trimmed, empty when npm has none.
func NpmConfigGet(ctx context.Context, dir, key string, flags []string) (string, error) {
	npm, err := lookTool("npm")
	if err != nil {
		return "", fmt.Errorf("%w (npm)", ErrNoResolver)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, npm, append([]string{"config", "get", key}, flags...)...)
	cmd.Dir = dir
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("npm config get %s: %w", key, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// NpmConfigIncludes reports the dependency kinds (dev, optional, peer) npm's
// effective configuration includes for a command run in dir with flags —
// project, user and global .npmrc files and the environment, read by `npm
// config get include` the way the install reads them. An --include anywhere
// wins over an --omit on the command line, so a filter built from the
// command line alone must ask here before dropping a kind.
func NpmConfigIncludes(ctx context.Context, dir string, flags []string) ([]string, error) {
	out, err := NpmConfigGet(ctx, dir, "include", flags)
	if err != nil {
		return nil, err
	}
	// One line, comma-separated ("optional,dev"), empty when none.
	return strings.FieldsFunc(out, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}), nil
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
	if dir == "" {
		// A tool run: read uv's configuration as the run does.
		if flags, err = uvToolRunConfig(flags, tmp); err != nil {
			return nil, err
		}
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

// uvToolRunConfig gives a tool run's resolution the configuration the run
// reads. `uv pip compile` also applies the [pip] table of uv's
// configuration, which uvx and `uv tool run` ignore (verified against uv
// 0.11: with a top-level index-url and a [pip] index-url in one file, uvx
// fetches from the former and `uv pip compile` from the latter), so the
// file the run reads — --config-file, UV_CONFIG_FILE, else the user-level
// uv.toml — is copied into scratch without that table and named by
// --config-file. A run with --no-config reads none, and a file without a
// [pip] table is read as it is; a file uv cannot parse is left for uv to
// report, as the run would.
func uvToolRunConfig(flags []string, scratch string) ([]string, error) {
	path := ""
	for i := 0; i < len(flags); i++ {
		switch f := flags[i]; {
		case f == "--no-config":
			return flags, nil
		case f == "--config-file" && i+1 < len(flags):
			path = flags[i+1]
			i++
		case strings.HasPrefix(f, "--config-file="):
			path = strings.TrimPrefix(f, "--config-file=")
		}
	}
	if path == "" {
		path = os.Getenv("UV_CONFIG_FILE")
	}
	if path == "" {
		path = userUVConfig()
	}
	if path == "" {
		return flags, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return flags, nil
		}
		return nil, err
	}
	var cfg map[string]any
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return flags, nil
	}
	if _, ok := cfg["pip"]; !ok {
		return flags, nil
	}
	delete(cfg, "pip")
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return nil, err
	}
	stripped := filepath.Join(scratch, "uv.toml")
	if err := os.WriteFile(stripped, buf.Bytes(), 0o600); err != nil {
		return nil, err
	}
	var out []string
	for i := 0; i < len(flags); i++ {
		if f := flags[i]; f == "--config-file" {
			i++
		} else if !strings.HasPrefix(f, "--config-file=") {
			out = append(out, f)
		}
	}
	return append(out, "--config-file", stripped), nil
}

// userUVConfig is where uv looks for user-level configuration:
// $XDG_CONFIG_HOME/uv/uv.toml (~/.config/uv/uv.toml) on POSIX,
// %APPDATA%\uv\uv.toml on Windows.
func userUVConfig() string {
	if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			return filepath.Join(v, "uv", "uv.toml")
		}
		return ""
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "uv", "uv.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "uv", "uv.toml")
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
