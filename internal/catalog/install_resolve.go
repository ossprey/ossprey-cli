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
	// release found at several paths carries a kind only if every copy does;
	// Copies keeps each copy's own kinds, since an install leaves the
	// release out only when it leaves every copy out, which the AND alone
	// cannot say for copies of different kinds.
	Dev, Optional, DevOptional, Peer bool
	Copies                           []DependencyKinds
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
	} else {
		if configDir != "" {
			// No project, but npm still reads a project-level .npmrc: a
			// scoped private registry applies to `npx @org/cli` too.
			if err := stageNpmrc(configDir, tmp); err != nil {
				return nil, err
			}
		}
		// A manifest of its own, or npm takes the nearest ancestor with one
		// as the project — scratch sits under one when TMPDIR points inside
		// a project — and the dry run then rewrites that project's
		// package.json and lockfile (verified against npm 11.19.1).
		if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte("{\"name\":\"ossprey-scratch\",\"private\":true}\n"), 0o600); err != nil {
			return nil, err
		}
	}

	args := append([]string{"install",
		"--package-lock-only",
		"--ignore-scripts",
		"--no-audit",
		"--no-fund",
		"--no-update-notifier",
		// Nor may npm walk on past that manifest to an ancestor workspace
		// root whose globs happen to name scratch; a copied root still
		// locks its own members with this (verified).
		"--workspaces=false",
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
	// The configuration the tool run reads, named explicitly: a bare
	// scratch directory does not stop uv discovering a project's uv.toml
	// above it, which uvx ignores, and scratch sits under a project when
	// TMPDIR points inside one.
	if flags, err = uvToolRunConfig(flags, scratch); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, uv, append([]string{"cache", "dir"}, flags...)...)
	cmd.Dir = scratch
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("uv cache dir: %w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
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
	// The configuration the tool run reads, named explicitly: a bare
	// scratch directory does not stop uv discovering a project's uv.toml
	// above it, which uvx ignores, and scratch sits under a project when
	// TMPDIR points inside one.
	if flags, err = uvToolRunConfig(flags, scratch); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, uv, append([]string{"tool", "dir"}, flags...)...)
	cmd.Dir = scratch
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return "", fmt.Errorf("uv tool dir: %w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
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
			// A damaged environment hides only itself: the one uv reuses
			// may be the next.
			pkgs, err := venvPackages(env)
			if err != nil {
				continue
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
		// One unreadable dist-info does not hide the rest of the
		// environment, which may still be what runs.
		data, err := os.ReadFile(f)
		if err != nil {
			continue
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
	// `npm config get cache` refuses a relative path as protected (verified
	// against npm 11.19.1: one from .npmrc, the environment or --cache
	// errors, an absolute one answers), while `npm config list -l` prints
	// every key with the path resolved as the command resolves it.
	args := []string{"config", "get", key}
	if key == "cache" {
		args = []string{"config", "list", "-l"}
	}
	cmd := exec.CommandContext(ctx, npm, append(args, flags...)...)
	cmd.Dir = dir
	cmd.Env = toolEnv()
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("npm %s: %w", strings.Join(args, " "), err)
	}
	if key == "cache" {
		return npmConfigListValue(string(out), key)
	}
	return strings.TrimSpace(string(out)), nil
}

// npmConfigListValue reads one key out of `npm config list -l`, whose
// lines are `key = <json value>`; a line starting with `;` is a comment (a
// default an override replaced, or a section header).
func npmConfigListValue(listing, key string) (string, error) {
	for _, line := range strings.Split(listing, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, " = ")
		if !ok || k != key {
			continue
		}
		var value string
		if err := json.Unmarshal([]byte(v), &value); err != nil {
			return "", fmt.Errorf("npm config list: %s = %s: %w", key, v, err)
		}
		return value, nil
	}
	return "", nil
}

// NpmConfigOmits reports the dependency kinds (dev, optional, peer) npm's
// effective omit policy leaves out of a command run in dir with flags, as
// `npm config get omit` reports it: the command line's --omit and --include
// (passed in flags), the environment (npm_config_omit) and the project,
// user and global .npmrc files, with include winning over omit and the
// optional boolean (optional=false) counted as an omit — npm applies all of
// that itself (verified against npm 11.19.1: `.npmrc optional=false` answers
// `optional`, and `--include=optional` beside `.npmrc omit=optional` answers
// nothing). A filter built from the command line alone missed every omit
// configured outside it and blocked runs on packages they never install.
func NpmConfigOmits(ctx context.Context, dir string, flags []string) ([]string, error) {
	out, err := NpmConfigGet(ctx, dir, "omit", flags)
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
			Copies:      rs.Copies,
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
// configuration the run reads — the file named by --config-file or
// UV_CONFIG_FILE, else the user-level uv.toml over the system-level one,
// merged as uv merges them (field by field, the user's winning; arrays
// joined, the user's entries first) — is
// written into scratch without that table and named by --config-file. A
// run with --no-config reads none; a file uv cannot parse is left for uv
// to report, as the run would. A relative UV_CONFIG_FILE is read against
// the directory uv runs in, which for the resolver is scratch, so it is
// named by its absolute path whether or not it has the table. With no file
// named, the discovered configuration is always written and named, even
// when empty: a named file stops uv discovering a project's uv.toml or
// pyproject.toml above the directory it runs in (verified), and scratch
// may sit under a project when TMPDIR points inside one, where `uv pip
// compile` would read configuration uvx ignores.
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
	fromEnv := false
	if path == "" {
		path = os.Getenv("UV_CONFIG_FILE")
		fromEnv = path != "" && !filepath.IsAbs(path)
		if fromEnv {
			// uv reads a relative UV_CONFIG_FILE against the directory it
			// runs in, which for the resolver is scratch; name the file
			// where this process reads it.
			abs, err := filepath.Abs(path)
			if err != nil {
				return nil, err
			}
			path = abs
		}
	}
	sources := []string{path}
	discovered := path == ""
	if discovered {
		sources = uvConfigSources()
	}
	merged := map[string]any{}
	found := false
	for _, source := range sources {
		data, err := os.ReadFile(source)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		var cfg map[string]any
		if _, err := toml.Decode(string(data), &cfg); err != nil {
			return flags, nil
		}
		anchorUVConfigPaths(cfg, filepath.Dir(source))
		mergeTOML(merged, cfg)
		found = true
	}
	if _, ok := merged["pip"]; !discovered && (!found || !ok) {
		// A named file already stops project discovery; without the
		// table it is read as it is.
		if fromEnv {
			return append(slices.Clone(flags), "--config-file", path), nil
		}
		return flags, nil
	}
	delete(merged, "pip")
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(merged); err != nil {
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

// anchorUVConfigPaths makes absolute every relative local path among the
// index and find-links settings of one configuration file, against the
// directory of that file: uv resolves them there (verified: `find-links =
// ["./wheels"]` in a user-level uv.toml reads <config dir>/wheels from any
// directory and under --directory, and a named file's against its own), so
// the copy written to scratch would otherwise point the dry run at
// directories under scratch and resolve from the registry what the run
// takes from the local wheels. A URL is left as it is. cache-dir is not
// among them: uv resolves that one against the directory it runs in, and
// the tool run hands the resolver --cache-dir absolutely already.
func anchorUVConfigPaths(cfg map[string]any, dir string) {
	anchor := func(v any) any {
		s, ok := v.(string)
		if !ok || s == "" || strings.Contains(s, "://") || filepath.IsAbs(s) {
			return v
		}
		return filepath.Join(dir, s)
	}
	for _, k := range []string{"index-url", "default-index"} {
		if v, ok := cfg[k]; ok {
			cfg[k] = anchor(v)
		}
	}
	for _, k := range []string{"extra-index-url", "find-links"} {
		if list, ok := cfg[k].([]any); ok {
			for i := range list {
				list[i] = anchor(list[i])
			}
		}
	}
	switch idx := cfg["index"].(type) {
	case []map[string]any:
		for _, t := range idx {
			if v, ok := t["url"]; ok {
				t["url"] = anchor(v)
			}
		}
	case []any:
		for _, e := range idx {
			if t, ok := e.(map[string]any); ok {
				if v, ok := t["url"]; ok {
					t["url"] = anchor(v)
				}
			}
		}
	}
}

// mergeTOML lays over onto base as uv combines configuration: table by
// table, a value from over winning where both set one.
func mergeTOML(base, over map[string]any) {
	for k, v := range over {
		if ov, ok := v.(map[string]any); ok {
			if bv, ok := base[k].(map[string]any); ok {
				mergeTOML(bv, ov)
				continue
			}
		}
		if joined, ok := concatTOML(v, base[k]); ok {
			base[k] = joined
			continue
		}
		base[k] = v
	}
}

// concatTOML joins two arrays as uv joins them across its configuration
// files: the higher-precedence entries first (verified against uv 0.11 with
// --show-settings: the user's extra-index-url and [[index]] entries precede
// the system's). An array of tables decodes as []map[string]any, a plain
// one as []any; unlike kinds are not joined.
func concatTOML(over, base any) (any, bool) {
	switch o := over.(type) {
	case []any:
		if b, ok := base.([]any); ok {
			return slices.Concat(o, b), true
		}
	case []map[string]any:
		if b, ok := base.([]map[string]any); ok {
			return slices.Concat(o, b), true
		}
	}
	return nil, false
}

// uvResolutionKeys are the uv settings, in a configuration file or its
// environment, that change which releases resolve: the indexes and how they
// are searched, prerelease and resolution strategy, date cut-offs, build
// policy, the interpreter, and dependency overrides. pip's dry run honours
// none of them from uv's configuration.
var uvResolutionKeys = []string{"index", "index-url", "default-index", "extra-index-url", "find-links", "no-index",
	"index-strategy", "prerelease", "resolution", "exclude-newer", "exclude-newer-package", "torch-backend",
	"no-binary", "no-binary-package", "no-build", "no-build-package", "python", "python-preference",
	"override-dependencies", "constraint-dependencies", "build-constraint-dependencies", "dependency-metadata",
	"sources", "environments", "offline", "no-sources"}

// uvResolutionEnv are the UV_* variables uv reads for the same settings.
var uvResolutionEnv = []string{"UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS",
	"UV_NO_INDEX", "UV_INDEX_STRATEGY", "UV_PRERELEASE", "UV_RESOLUTION", "UV_EXCLUDE_NEWER", "UV_TORCH_BACKEND",
	"UV_NO_BINARY", "UV_NO_BINARY_PACKAGE", "UV_NO_BUILD", "UV_NO_BUILD_PACKAGE", "UV_PYTHON", "UV_PYTHON_PREFERENCE",
	"UV_OVERRIDE", "UV_CONSTRAINT", "UV_BUILD_CONSTRAINT", "UV_OFFLINE", "UV_NO_SOURCES"}

// UVConfigShapesResolution reports whether uv's configuration outside the
// command line would change what resolves: a UV_* variable for an index,
// strategy, cut-off, build policy, interpreter or override, or such a
// setting in the configuration uv reads — the file --config-file or
// UV_CONFIG_FILE names, else the project's uv.toml or pyproject.toml
// [tool.uv] at dir or above when dir is a project, and the user- and
// system-level uv.toml. A [pip] table counts too, since a pip-interface
// command reads it. --no-config stops the files, not the variables. The pip
// fallback reads none of this, so a uv command under such configuration
// must resolve with uv or not at all. A file that cannot be read or parsed
// counts as shaping, erring toward uv.
func UVConfigShapesResolution(flags []string, dir string) bool {
	for _, v := range uvResolutionEnv {
		if os.Getenv(v) != "" {
			return true
		}
	}
	path := ""
	for i := 0; i < len(flags); i++ {
		switch f := flags[i]; {
		case f == "--no-config":
			return false
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
	if path != "" {
		return tomlShapesResolution(path, "")
	}
	if dir != "" {
		// uv discovers the nearest uv.toml or pyproject.toml above dir,
		// uv.toml winning beside a pyproject.toml. The project's file is
		// merged over the user's and the system's, not read instead of
		// them, so one that shapes nothing still leaves theirs to check.
		for d := absDir(dir); ; d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, "uv.toml")); err == nil {
				if tomlShapesResolution(filepath.Join(d, "uv.toml"), "") {
					return true
				}
				break
			}
			if _, err := os.Stat(filepath.Join(d, "pyproject.toml")); err == nil {
				if tomlShapesResolution(filepath.Join(d, "pyproject.toml"), "tool.uv") {
					return true
				}
				break
			}
			if filepath.Dir(d) == d {
				break
			}
		}
	}
	for _, source := range uvConfigSources() {
		if _, err := os.Stat(source); err != nil {
			continue
		}
		if tomlShapesResolution(source, "") {
			return true
		}
	}
	return false
}

func absDir(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// tomlShapesResolution reports whether the table at dotted path table (the
// whole file for "") in the TOML file, or its [pip] sub-table, sets any of
// uvResolutionKeys. Unreadable or unparseable is true: what cannot be read
// cannot be reproduced for pip.
func tomlShapesResolution(path, table string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	var cfg map[string]any
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return true
	}
	if table != "" {
		for _, part := range strings.Split(table, ".") {
			sub, ok := cfg[part].(map[string]any)
			if !ok {
				return false
			}
			cfg = sub
		}
	}
	for _, k := range uvResolutionKeys {
		if _, ok := cfg[k]; ok {
			return true
		}
	}
	if pip, ok := cfg["pip"].(map[string]any); ok {
		for _, k := range uvResolutionKeys {
			if _, ok := pip[k]; ok {
				return true
			}
		}
	}
	return false
}

// uvConfigSources are the configuration files uv discovers for a tool run,
// lowest precedence first: the system-level uv.toml (/etc/uv/uv.toml, or
// the first under $XDG_CONFIG_DIRS; %PROGRAMDATA%\uv\uv.toml on Windows),
// then the user-level one ($XDG_CONFIG_HOME/uv/uv.toml, ~/.config/uv/uv.toml;
// %APPDATA%\uv\uv.toml on Windows). The XDG variables are read on every
// platform, which only matters where someone set them.
func uvConfigSources() []string {
	var system, user string
	if dirs := os.Getenv("XDG_CONFIG_DIRS"); dirs != "" {
		for _, d := range strings.Split(dirs, string(os.PathListSeparator)) {
			if d == "" {
				continue
			}
			system = filepath.Join(d, "uv", "uv.toml")
			if _, err := os.Stat(system); err == nil {
				break
			}
		}
	} else if runtime.GOOS == "windows" {
		if v := os.Getenv("PROGRAMDATA"); v != "" {
			system = filepath.Join(v, "uv", "uv.toml")
		}
	} else {
		system = filepath.Join("/etc", "uv", "uv.toml")
	}
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		user = filepath.Join(v, "uv", "uv.toml")
	} else if runtime.GOOS == "windows" {
		if v := os.Getenv("APPDATA"); v != "" {
			user = filepath.Join(v, "uv", "uv.toml")
		}
	} else if home, err := os.UserHomeDir(); err == nil {
		user = filepath.Join(home, ".config", "uv", "uv.toml")
	}
	var out []string
	for _, p := range []string{system, user} {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
	for _, spec := range specs {
		// A requirements file travels as one "-r <path>" spec, a line uv's
		// input reads as it is; pip takes it as two arguments.
		if path, ok := strings.CutPrefix(spec, "-r "); ok {
			args = append(args, "-r", path)
			continue
		}
		args = append(args, spec)
	}
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
