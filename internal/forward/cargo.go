package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/progress"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/submit"
)

// cargoWorkspaceFn finds the files a cargo command may rewrite; a test seam.
var cargoWorkspaceFn = readCargoWorkspace

// cargoCredentialFn resolves the credential a gating check submits with, as submit.Validate does; a test seam.
var cargoCredentialFn = func(ctx context.Context, apiURL, apiKey string) error {
	_, err := submit.NewClient(ctx, apiURL, apiKey)
	return err
}

// cargoVersionFn is the version line of the cargo a command runs; a test seam.
var cargoVersionFn = cargoVersion

// cargoMetadataFn is the workspace cargo metadata finds for a command run in dir; a test seam.
var cargoMetadataFn = cargoMetadata

// cargoRunFn runs cargo as a child in dir ("" for ours) with env added and its stderr to stderr; a test seam.
var cargoRunFn = runCargo

// commitFn renames a staged file over its target; a test seam.
var commitFn = func(s staged) error { return os.Rename(s.tmp, s.target) }

// cargoErrOut is where cargo's own stderr goes once its paths are spelled as the project's; a test seam.
var cargoErrOut io.Writer = os.Stderr

// cargoResolveShorts are the short options of add, update, fetch and generate-lockfile that take a value (TestCargoFlagTablesMatchCargo).
var cargoResolveShorts = flagSet("-F", "-m", "-p", "-Z")

// cargoResolveAt matches the cargo verbs that resolve and lock but build nothing, unless asked for --help.
func cargoResolveAt(args []string) (int, bool) {
	start, ok := verbAt("cargo", "add", "update", "generate-lockfile", "fetch")(args)
	if !ok || cargoPrintsOnly(args, start, cargoResolveShorts) {
		return 0, false
	}
	return start, true
}

// cargoPrintsOnly reports whether cargo would print help or its version and run nothing: -h or --help after the verb, or either or -V/--version before it (verified with cargo 1.99.1).
func cargoPrintsOnly(args []string, start int, verbShorts map[string]bool) bool {
	globals := globalValueFlags["cargo"]
	return cargoOptionsHave(cargoSplitShorts(args[:start-1], globals), globals, "-h", "--help", "-V", "--version") ||
		cargoOptionsHave(cargoSplitShorts(args[start:], verbShorts), verbShorts, "-h", "--help")
}

// cargoOptionsHave reports whether one of flags is among split args' options before `--`.
func cargoOptionsHave(split []string, takes map[string]bool, flags ...string) bool {
	return len(cargoOptionsIn(split, takes, flags...)) > 0
}

// cargoOptionsIn are the options among split args before `--` that are one of flags, in order, never a value an option took (`-C-h` names a directory).
func cargoOptionsIn(split []string, takes map[string]bool, flags ...string) []string {
	var out []string
	for i := 0; i < len(split); i++ {
		switch a := split[i]; {
		case a == "--":
			return out
		case slices.Contains(flags, a):
			out = append(out, a)
		case takes[a] && i+1 < len(split) && !cargoOptionalSkips(a, split[i+1]):
			i++
		}
	}
	return out
}

// cargoShorts splits a group of short options as clap reads it: switches up to one in takes, which takes the rest less one leading `=`, else the next token (owes).
func cargoShorts(a string, takes map[string]bool) (split []string, owes bool) {
	if len(a) < 3 || a[0] != '-' || a[1] == '-' {
		return []string{a}, len(a) == 2 && takes[a]
	}
	for i := 1; i < len(a); {
		_, n := utf8.DecodeRuneInString(a[i:])
		short := "-" + a[i:i+n]
		if short == "--" {
			// cargo refuses the group; splitting it would forge an end of options.
			return []string{a}, false
		}
		i += n
		split = append(split, short)
		if takes[short] {
			if i == len(a) {
				return split, true
			}
			v := strings.TrimPrefix(a[i:], "=")
			if cargoOptionalSkips(short, v) {
				// clap reads `-p-h` as -p's value, so it stays one token, `-p=-h`, that no reader takes for an option.
				split[len(split)-1] = short + "=" + v
				return split, false
			}
			return append(split, v), false
		}
	}
	return split, false
}

// cargoSplitShorts writes each group of short options before any `--` one option per token, as cargoShorts reads it: `-qFpcre2` is `-q -F pcre2`.
func cargoSplitShorts(args []string, takes map[string]bool) []string {
	var out []string
	for i, a := range args {
		if a == "--" {
			return append(out, args[i:]...)
		}
		split, _ := cargoShorts(a, takes)
		out = append(out, split...)
	}
	return out
}

// cargoInstallAt matches `cargo install`, but not `cargo install --list` or a line that only prints help or the version.
func cargoInstallAt(args []string) (int, bool) {
	start, ok := verbAt("cargo", "install")(args)
	if !ok || cargoHas(args[start:], "--list") || cargoPrintsOnly(args, start, valueFlags["cargo"]) {
		return 0, false
	}
	return start, true
}

// cargoHas reports whether one of flags is among args before `--`.
func cargoHas(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if slices.Contains(flags, a) {
			return true
		}
	}
	return false
}

// cargoOptionalValues are install's options whose value is optional (TestCargoFlagTablesMatchCargo).
var cargoOptionalValues = flagSet("--bin", "--example", "--target")

// cargoResolveOptional are the cargoResolveShorts whose value is optional: add's -p, and update's, which `cargo update --help` hides (TestCargoFlagTablesMatchCargo).
var cargoResolveOptional = flagSet("-p")

// cargoOptionalSkips reports whether clap leaves next alone for flag: an optional value is never an option token, so `--bin -F pcre2` gives pcre2 to -F.
func cargoOptionalSkips(flag, next string) bool {
	return (cargoOptionalValues[flag] || cargoResolveOptional[flag]) && len(next) > 1 && next[0] == '-'
}

// cargoSourceFlags install every crate named from somewhere other than crates.io.
var cargoSourceFlags = flagSet("--git", "--path", "--index", "--registry")

// parseCargoInstall classifies `cargo install`'s arguments: each positional is a crate, --version pins them all, and a source flag other than crates.io, or else a defaultRegistry, takes them off crates.io.
func parseCargoInstall(args []string, defaultRegistry string) installArgs {
	args = cargoSplitShorts(args, valueFlags["cargo"])
	var crates []string
	version, source, cratesIo := "", "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "":
			continue
		case a == "--":
			crates = append(crates, args[i+1:]...)
			i = len(args)
			continue
		case !strings.HasPrefix(a, "-"):
			crates = append(crates, a)
			continue
		}
		flag, value, inline := splitFlagValue(a)
		if !inline && valueFlags["cargo"][flag] && i+1 < len(args) && !cargoOptionalSkips(flag, args[i+1]) {
			value = args[i+1]
			i++
		}
		switch {
		case flag == "--version" || flag == "--vers":
			version = value
		case flag == "--registry" && value == "crates-io" || flag == "--index" && catalog.IsCratesIoIndex(value):
			source, cratesIo = "", true
		case cargoSourceFlags[flag]:
			source = flag + " " + value
		}
	}
	if source == "" && !cratesIo && defaultRegistry != "" {
		source = "registry.default " + defaultRegistry
	}
	var out installArgs
	for _, c := range crates {
		switch {
		case source != "":
			out.NonPackages = append(out.NonPackages, c)
		case version != "" && !strings.Contains(c, "@"):
			out.addCrate(c + "@" + version)
		default:
			out.addCrate(c)
		}
	}
	if source != "" {
		out.NonPackages = append(out.NonPackages, source)
	}
	return out
}

// addCrate adds one crate to install; a range, which check refuses, resolves to the latest release as a PyPI range does.
func (p *installArgs) addCrate(token string) {
	name, req, _ := strings.Cut(token, "@")
	if _, err := check.ParseSpec("cargo", token); err != nil && req != "" && registry.IsCargoName(name) {
		p.Specs = append(p.Specs, check.Spec{Ecosystem: "cargo", Name: name, Constraint: req})
		return
	}
	p.addTarget("cargo", token)
}

// checkCargoFirst resolves a cargo verb that only locks into a scratch Cargo.lock, checks that, and writes it to the project only when clean, so nothing unchecked reaches the project at any point.
func checkCargoFirst(ctx context.Context, m *Manager, opts Options) error {
	args := opts.Args
	command := m.Bin + " " + strings.Join(args, " ")
	flushWarnings(ctx)
	version, err := cargoVersionGate(ctx, command, args)
	if err != nil {
		return err
	}
	verb := verbIndex("cargo", args)
	rest := cargoSplitShorts(args[verb+1:], cargoResolveShorts)
	// Even a -b an option might have taken refuses, since misreading it costs only a refusal.
	if args[verb] == "update" && cargoHas(rest, "-b", "--breaking") {
		// It rewrites Cargo.toml as well as the lock, and only the lock is redirected (verified with cargo 1.99.1).
		return fmt.Errorf("did not run `%s`: --breaking edits Cargo.toml, which ossprey checks first only for `cargo add`; raise the requirement with `cargo add <crate>@<version>` instead", command)
	}
	if args[verb] == "fetch" {
		if bad := cargoFetchUnknown(rest); bad != "" {
			// The resolve step passes on only what update takes, so cargo fetch would reject the line after the lock landed.
			return fmt.Errorf("did not run `%s`: cargo fetch would reject `%s`", command, bad)
		}
	}
	dryRun := (args[verb] == "add" || args[verb] == "update") && cargoOptionsHave(rest, cargoResolveShorts, "-n", "--dry-run")
	if args[verb] == "add" && dryRun {
		// cargo add --dry-run writes nothing anywhere, lock or none (verified with cargo 1.97.0 and 1.99.1).
		return handoffFn(ctx, m.Bin, args)
	}
	ws, err := cargoWorkspaceFn(ctx, args)
	if err != nil {
		return fmt.Errorf("did not run `%s`: its Cargo.lock cannot be checked (%v)", command, err)
	}
	if !dryRun {
		// A missing credential stops here, before cargo runs, as it stops any gating install.
		if err := cargoCredentialFn(ctx, opts.APIURL, opts.APIKey); err != nil {
			return err
		}
	}
	paths := []string{ws.Lock}
	if args[verb] == "add" {
		paths = append(paths, ws.Manifests...)
	}
	before := make([]cargoFile, len(paths))
	for i, p := range paths {
		if before[i], err = readCargoState(p); err != nil {
			return fmt.Errorf("did not run `%s`: %v", command, err)
		}
	}

	var after []cargoFile
	var runErr error
	switch args[verb] {
	case "add":
		after, runErr, err = resolveCargoAdd(ctx, args, ws, before, version)
	case "fetch":
		after, runErr, err = resolveCargoLock(ctx, cargoFetchResolve(args), ws, before[0])
	default:
		after, runErr, err = resolveCargoLock(ctx, args, ws, before[0])
	}
	// Before anything else, since a resolve that failed after cargo ran may still have reached the project.
	if err := cargoTripwire(command, before); err != nil {
		return err
	}
	if err != nil {
		return fmt.Errorf("could not check `%s` (%v); the project was not changed", command, err)
	}
	if runErr != nil || dryRun {
		return runErr
	}
	lock := displayPath(ws.Lock)
	if !after[0].existed {
		return fmt.Errorf("`%s` left no Cargo.lock, so nothing was checked and the project was not changed", command)
	}

	stop := progress.Start(progressTo(), "ossprey: scan in progress")
	sbom, err := scanCargoLock(ctx, opts, ws, after[0].data, false)
	stop()
	flushWarnings(ctx)
	if err != nil {
		return fmt.Errorf("%s not checked (%v); the project was not changed", lock, err)
	}
	summary, hasMalware := scan.MalwareReports(sbom, severity.ParseFloor(sbom.FailingSeverityFloor))
	for _, msg := range summary.Informational {
		note("ossprey: %s\n", msg)
	}
	if hasMalware {
		printBlock(m, opts, summary)
		fmt.Fprintln(errOut, "ossprey: the project was not changed")
		return ErrBlocked
	}
	verdict, checked := CleanVerdict(sbom, len(summary.Informational), " in "+lock)
	if len(sbom.Components) > 0 && !checked {
		return fmt.Errorf("the platform checked none of the %s in %s (Rust is checked on Teams and Enterprise plans); the project was not changed", countPackages(len(sbom.Components)), lock)
	}
	if err := landCargo(before, after); err != nil {
		return err
	}
	if len(sbom.Components) == 0 {
		note("ossprey: found no dependencies to check in %s\n", lock)
	} else {
		fmt.Fprintf(errOut, "ossprey: %s\n", verdict)
	}
	if args[verb] == "fetch" {
		// The project now holds the checked lock, and --locked downloads exactly that or nothing (verified with cargo 1.97.0 and 1.99.1).
		return handoffFn(ctx, m.Bin, cargoFetchLocked(args))
	}
	return nil
}

// postCargoLock runs a cargo verb that only locks, then posts the Cargo.lock it leaves without waiting for a verdict.
func postCargoLock(ctx context.Context, m *Manager, opts Options) error {
	command := m.Bin + " " + strings.Join(opts.Args, " ")
	flushWarnings(ctx)
	runErr := execFn(ctx, m.Bin, opts.Args)
	ws, err := cargoWorkspaceFn(ctx, opts.Args)
	if cargoFailedOnItsWorkspace(command, runErr, err) {
		return runErr
	}
	var data []byte
	if err == nil {
		data, _, err = readCargoFile(ws.Lock)
		if errors.Is(err, fs.ErrNotExist) {
			// cargo add --dry-run with no lock writes nothing, so there is nothing to post.
			note("ossprey: `%s` left no Cargo.lock; nothing posted\n", command)
			return runErr
		}
	}
	// A failed command may still have locked (cargo fetch locks, then downloads), so its lock is posted, or a warning says why not.
	stop := progress.Submit(progressTo(), 0)
	var sbom *ossbom.SBOM
	if err == nil {
		sbom, err = scanCargoLock(ctx, opts, ws, data, true)
	}
	stop()
	flushWarnings(ctx)
	reportPassive(opts, sbom, err)
	return runErr
}

// cargoFailedOnItsWorkspace is a failed command whose workspace cargo metadata cannot read either: cargo's error says why, and only a moved or script lock may have been written.
func cargoFailedOnItsWorkspace(command string, runErr, wsErr error) bool {
	if runErr == nil || wsErr == nil || errors.Is(wsErr, errLockfileMoved) || errors.Is(wsErr, errScriptLock) {
		return false
	}
	note("ossprey: `%s` failed and its workspace could not be read (%v); nothing to check\n", command, wsErr)
	return true
}

// cargoVersionGate refuses a cargo that may ignore resolver.lockfile-path and write the project's lock itself, and returns the version line it read.
func cargoVersionGate(ctx context.Context, command string, args []string) (string, error) {
	line, err := cargoVersionFn(ctx, "", args)
	if err != nil {
		return "", fmt.Errorf("did not run `%s`: could not read cargo's version (%v)", command, err)
	}
	if !cargoRedirects(line) {
		return "", fmt.Errorf("did not run `%s`: ossprey needs cargo 1.97 or later to check it before it changes the project, and found `%s`; upgrade cargo (`rustup update`)", command, line)
	}
	return line, nil
}

// cargoVersion runs `cargo -V` in dir ("" for ours), after rustup's +toolchain alone, since -C makes a stable cargo fail and no other option changes the answer (verified).
func cargoVersion(ctx context.Context, dir string, args []string) (string, error) {
	probe := []string{"-V"}
	if len(args) > 0 && strings.HasPrefix(args[0], "+") {
		probe = []string{args[0], "-V"}
	}
	cmd, err := realCommand(ctx, "cargo", probe)
	if err != nil {
		return "", err
	}
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", errors.New(firstErrorLine(stderr.String(), err))
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line), nil
}

// cargoVersionLine is `cargo X.Y.Z[-pre] (hash date)` as every cargo -V prints it.
var cargoVersionLine = regexp.MustCompile(`^cargo (\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?(\s|$)`)

// cargoRedirects reports whether the cargo printing line is 1.97.0 or later in semver order, the first to honour resolver.lockfile-path: 1.97.0-nightly ignored it, so a pre-release ranks below its release (verified).
func cargoRedirects(line string) bool {
	m := cargoVersionLine.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	v := make([]int, 3)
	for i := range v {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return false
		}
		v[i] = n
	}
	switch c := slices.Compare(v, []int{1, 97, 0}); {
	case c > 0:
		return true
	case c == 0:
		return m[4] == ""
	}
	return false
}

// resolveCargoLock runs args with the lock redirected to a scratch copy of the project's, and returns what cargo locked there.
func resolveCargoLock(ctx context.Context, args []string, ws cargoWorkspace, before cargoFile) (after []cargoFile, runErr, err error) {
	scratch, err := os.MkdirTemp("", "ossprey-cargo-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(scratch)
	if real, err := filepath.EvalSymlinks(scratch); err == nil {
		scratch = real
	}
	at := filepath.Join(scratch, "Cargo.lock")
	// cargo resolves from nothing when the redirect names no lock, so the project's goes there first (verified).
	if before.existed {
		if err := os.WriteFile(at, before.data, 0o600); err != nil {
			return nil, nil, err
		}
	}
	stderr := newCargoStderr(cargoErrOut, at, ws.Lock)
	runErr = cargoRunFn(ctx, "", cargoRedirectEnv(at), cargoRedirectArgs(args, at), stderr)
	stderr.Flush()
	locked, err := readCargoState(at)
	if err != nil {
		return nil, runErr, err
	}
	locked.path = before.path
	return []cargoFile{locked}, runErr, nil
}

// resolveCargoAdd runs cargo add in a mirror of the workspace, with the cargo whose version line the gate read, and returns the lock and manifests it left there, in before's order.
func resolveCargoAdd(ctx context.Context, args []string, ws cargoWorkspace, before []cargoFile, version string) (after []cargoFile, runErr, err error) {
	cwd := cargoCwd(nil)
	mi, err := buildCargoMirror(ws, before, cwd, cargoCwd(args[:verbIndex("cargo", args)]))
	if err != nil {
		return nil, nil, err
	}
	defer mi.remove()
	run, err := mi.args(args)
	if err != nil {
		return nil, nil, err
	}
	dir := mirrorPath(mi.s, cwd)
	// rustup keys a directory override by the project's path, so the mirror may run another toolchain (verified with rustup).
	line, err := cargoVersionFn(ctx, dir, args)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read cargo's version in the mirror of the workspace (%v)", err)
	}
	if line != version {
		return nil, nil, fmt.Errorf("the mirror of the workspace runs `%s`, not the project's `%s` (a rustup override set for the project's directory does not apply there); name the toolchain with `cargo +<toolchain>` or RUSTUP_TOOLCHAIN", line, version)
	}
	// cargo add writes only a member's manifest, so the mirror's members must be the project's, all copies.
	project := strings.NewReplacer(mi.strip()...)
	got, err := cargoMetadataFn(ctx, dir, run, ws.ConfigDir)
	if err != nil {
		// cargo's own error names the manifest at fault, an absolute path or a [workspace] above the cache (verified with cargo 1.99.1).
		return nil, nil, fmt.Errorf("cargo metadata fails in ossprey's copy of the workspace with %s; either a Cargo.toml names the workspace or a member by an absolute path, which must be made relative to its Cargo.toml, or a Cargo.toml above %s has a [workspace]", project.Replace(strings.TrimPrefix(err.Error(), "cargo metadata: ")), filepath.Dir(mi.s))
	}
	if err := mi.sameWorkspace(got, ws); err != nil {
		return nil, nil, fmt.Errorf("cargo would see another workspace in ossprey's copy of it, since %s; %s", project.Replace(err.Error()), cargoAbsoluteHint)
	}
	at := mi.at(ws.Lock)
	stderr := newCargoStderr(cargoErrOut, mi.strip()...)
	runErr = cargoRunFn(ctx, dir, cargoRedirectEnv(at), cargoRedirectArgs(run, at), stderr)
	stderr.Flush()
	after = make([]cargoFile, len(before))
	for i, f := range before {
		if after[i], err = readCargoState(mi.at(f.path)); err != nil {
			return nil, runErr, err
		}
		after[i].path = f.path
	}
	if runErr != nil {
		return after, runErr, nil
	}
	// What the add brought in may lead cargo out of the mirror, so the project would lock what the mirror did not (verified with cargo 1.99.1).
	added, err := cargoMetadataFn(ctx, dir, run, ws.ConfigDir)
	if err != nil {
		return nil, nil, fmt.Errorf("after the add, cargo metadata fails in ossprey's copy of the workspace with %s", project.Replace(strings.TrimPrefix(err.Error(), "cargo metadata: ")))
	}
	if err := mi.added(got, added, ws, after); err != nil {
		return nil, nil, errors.New(project.Replace(err.Error()))
	}
	return after, nil, nil
}

// cargoAbsoluteHint says what leads cargo out of the mirror and how to stop it.
const cargoAbsoluteHint = "a Cargo.toml names the workspace or a member by an absolute path, in package.workspace, workspace.members, default-members or exclude, or a path dependency; make it relative to its Cargo.toml"

// runCargo runs the real cargo as a child, with ossprey's stdin and stdout.
func runCargo(ctx context.Context, dir string, env, args []string, stderr io.Writer) error {
	cmd, err := realCommand(ctx, "cargo", args)
	if err != nil {
		return err
	}
	cmd.Dir = dir
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, stderr
	return cmd.Run()
}

// cargoRedirectEnv points resolver.lockfile-path at lock, which beats every config file, and keeps cargo from writing target/.rustc_info.json into the project (verified).
func cargoRedirectEnv(lock string) []string {
	env := []string{"CARGO_RESOLVER_LOCKFILE_PATH=" + lock, "CARGO_CACHE_RUSTC_INFO=0"}
	if _, set := os.LookupEnv("CARGO_TERM_COLOR"); !set && cargoColours(term.IsTerminal(int(os.Stderr.Fd()))) {
		// cargo's stderr is a pipe now, so a terminal keeps its colours only if asked.
		env = append(env, "CARGO_TERM_COLOR=always")
	}
	return env
}

// cargoColours reports whether cargo's auto colour choice colours a stderr that is a terminal when tty: not under NO_COLOR or CLICOLOR=0, and with a TERM other than dumb, CLICOLOR or CI (verified with cargo 1.99.1).
func cargoColours(tty bool) bool {
	if !tty || os.Getenv("NO_COLOR") != "" || os.Getenv("CLICOLOR") == "0" {
		return false
	}
	t, termSet := os.LookupEnv("TERM")
	_, clicolor := os.LookupEnv("CLICOLOR")
	_, ci := os.LookupEnv("CI")
	return runtime.GOOS == "windows" || termSet && t != "dumb" || clicolor || ci
}

// cargoRedirectArgs appends a --config pointing resolver.lockfile-path at lock, before any `--`, since the last --config beats the environment and every other --config (verified with cargo 1.97.0 and 1.99.1).
func cargoRedirectArgs(args []string, lock string) []string {
	i := slices.Index(args, "--")
	if i < 0 {
		i = len(args)
	}
	return slices.Concat(args[:i], []string{"--config", "resolver.lockfile-path=" + tomlString(lock)}, args[i:])
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// cargoFetchSwitches and cargoFetchValues are every option `cargo fetch` takes, without and with a value (TestCargoFlagTablesMatchCargo).
var (
	cargoFetchSwitches = flagSet("-v", "--verbose", "-q", "--quiet", "-h", "--help", "--locked", "--offline", "--frozen")
	cargoFetchValues   = flagSet("--color", "--config", "-Z", "--target", "-m", "--manifest-path")
)

// cargoFetchUnknown is the first of split's tokens after fetch that cargo fetch does not take, or "".
func cargoFetchUnknown(split []string) string {
	for i := 0; i < len(split); i++ {
		a := split[i]
		name, _, inline := strings.Cut(a, "=")
		switch {
		case a == "--":
			if i+1 < len(split) {
				return split[i+1]
			}
		case cargoFetchSwitches[a], inline && strings.HasPrefix(a, "--") && cargoFetchValues[name]:
		case cargoFetchValues[a]:
			// clap takes no option as a value, and only --target may go without one.
			switch {
			case i+1 < len(split) && !(len(split[i+1]) > 1 && split[i+1][0] == '-'):
				i++
			case !cargoOptionalValues[a]:
				return a
			}
		default:
			return a
		}
	}
	return ""
}

// cargoFetchResolve is the `cargo update --workspace` that locks exactly what `cargo fetch` would and downloads no crate (verified with cargo 1.97.0 and 1.99.1; git dependencies are still checked out), passing every fetch option but --target, which update does not take.
func cargoFetchResolve(args []string) []string {
	verb := verbIndex("cargo", args)
	out := append(slices.Clone(args[:verb]), "update", "--workspace")
	rest := cargoSplitShorts(args[verb+1:], cargoResolveShorts)
	for i := 0; i < len(rest) && rest[i] != "--"; i++ {
		a := rest[i]
		name, _, inline := strings.Cut(a, "=")
		switch {
		case cargoFetchSwitches[a]:
			out = append(out, a)
		case inline && strings.HasPrefix(a, "--") && cargoFetchValues[name]:
			if name != "--target" {
				out = append(out, a)
			}
		case cargoFetchValues[a] && i+1 < len(rest) && !cargoOptionalSkips(a, rest[i+1]):
			if a != "--target" {
				out = append(out, a, rest[i+1])
			}
			i++
		}
	}
	return out
}

// cargoFetchLocked is the user's fetch with --locked added unless --locked or --frozen is already there.
func cargoFetchLocked(args []string) []string {
	verb := verbIndex("cargo", args)
	globals := globalValueFlags["cargo"]
	if cargoOptionsHave(cargoSplitShorts(args[:verb], globals), globals, "--locked", "--frozen") ||
		cargoOptionsHave(cargoSplitShorts(args[verb+1:], cargoResolveShorts), cargoResolveShorts, "--locked", "--frozen") {
		return args
	}
	i := slices.Index(args, "--")
	if i < 0 {
		i = len(args)
	}
	return slices.Concat(args[:i], []string{"--locked"}, args[i:])
}

// cargoStderr writes cargo's stderr on a line at a time, each scratch path spelled as the project path it stands for, and never fails a write, since cargo exits without locking when its stderr closes (verified).
type cargoStderr struct {
	w   io.Writer
	r   *strings.Replacer
	buf []byte
}

// newCargoStderr writes to w, replacing each old with its new.
func newCargoStderr(w io.Writer, oldnew ...string) *cargoStderr {
	return &cargoStderr{w: w, r: strings.NewReplacer(oldnew...)}
}

func (c *cargoStderr) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexAny(c.buf, "\r\n")
		if i < 0 {
			return len(p), nil
		}
		_, _ = io.WriteString(c.w, c.r.Replace(string(c.buf[:i+1])))
		c.buf = c.buf[i+1:]
	}
}

// Flush writes a last line with no newline.
func (c *cargoStderr) Flush() {
	if len(c.buf) > 0 {
		_, _ = io.WriteString(c.w, c.r.Replace(string(c.buf)))
		c.buf = nil
	}
}

// cargoFile is a project file's bytes and mode, or that it did not exist.
type cargoFile struct {
	path    string
	existed bool
	data    []byte
	mode    fs.FileMode
}

// same reports whether f and g hold the same bytes, or both did not exist.
func (f cargoFile) same(g cargoFile) bool {
	return f.existed == g.existed && bytes.Equal(f.data, g.data)
}

// readCargoState reads p, failing when it is not a regular file, is over the bound, or is a link to nothing.
func readCargoState(p string) (cargoFile, error) {
	data, fi, err := readCargoFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		if _, lerr := os.Lstat(p); lerr == nil {
			return cargoFile{}, fmt.Errorf("%s is a link to nothing", displayPath(p))
		}
		return cargoFile{path: p}, nil
	}
	if err != nil {
		return cargoFile{}, err
	}
	return cargoFile{path: p, existed: true, data: data, mode: fi.Mode().Perm()}, nil
}

// cargoTripwire puts back each project file that changed while cargo ran, keeping what it found beside it, and fails.
func cargoTripwire(command string, before []cargoFile) error {
	var changed, kept []string
	for _, f := range before {
		now, err := readCargoState(f.path)
		if err == nil && now.same(f) {
			continue
		}
		changed = append(changed, displayPath(f.path))
		if err == nil && now.existed {
			// Another program may have written it, so its bytes are kept rather than lost.
			if k, err := keepFound(f.path, now.data); err == nil {
				kept = append(kept, displayPath(k))
			} else {
				fmt.Fprintf(errOut, "ossprey: warning: could not keep what was found in %s (%v)\n", displayPath(f.path), err)
			}
		}
		if f.existed {
			err = landFile(f.path, f.data)
		} else {
			err = os.Remove(f.path)
		}
		if err != nil {
			fmt.Fprintf(errOut, "ossprey: warning: could not put back %s (%v)\n", displayPath(f.path), err)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	msg := fmt.Sprintf("%s changed while `%s` ran, by a cargo ignoring the scratch copy ossprey gave it or by another program, so it was put back unchecked", strings.Join(changed, ", "), command)
	if len(kept) > 0 {
		msg += "; what was found is kept in " + strings.Join(kept, ", ")
	}
	return errors.New(msg)
}

// keepFound writes data to a new file beside p and returns its name.
func keepFound(p string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".ossprey-found-*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return f.Name(), err
}

// staged is data written and synced to tmp beside target, the real file path names, to be renamed over it.
type staged struct{ path, target, tmp string }

// landCargo stages each file cargo changed beside its target, checks every project file still holds what cargo started from, then renames them back to back, the lock first so a manifest never names a crate the lock lacks, and puts back what it renamed if a later rename fails.
func landCargo(before, after []cargoFile) error {
	var changed []int
	for i, f := range after {
		if f.same(before[i]) {
			continue
		}
		if !f.existed {
			return fmt.Errorf("cargo removed %s, so nothing was written", displayPath(f.path))
		}
		changed = append(changed, i)
	}
	var files []staged
	done := 0
	defer func() {
		for _, s := range files[done:] {
			os.Remove(s.tmp)
		}
	}()
	for _, i := range changed {
		s, err := stageFile(after[i].path, after[i].data)
		if err != nil {
			return fmt.Errorf("could not write %s (%v); the project was not changed", displayPath(after[i].path), err)
		}
		files = append(files, s)
	}
	for _, f := range before {
		if now, err := readCargoState(f.path); err != nil || !now.same(f) {
			return fmt.Errorf("%s changed while ossprey checked it, so nothing was written; run the command again", displayPath(f.path))
		}
	}
	for ; done < len(files); done++ {
		if err := commitFn(files[done]); err != nil {
			return putBack(before, changed[:done], fmt.Sprintf("could not write %s (%v)", displayPath(files[done].path), err))
		}
	}
	return nil
}

// putBack restores the project files at landed to their bytes in before, after a later file failed to land, and says what was restored or could not be.
func putBack(before []cargoFile, landed []int, failed string) error {
	if len(landed) == 0 {
		return errors.New(failed + "; the project was not changed")
	}
	var back, lost []string
	for _, i := range slices.Backward(landed) {
		f := before[i]
		var err error
		if f.existed {
			err = landFile(f.path, f.data)
		} else {
			err = os.Remove(f.path)
		}
		if err != nil {
			lost = append(lost, fmt.Sprintf("%s (%v)", displayPath(f.path), err))
		} else {
			back = append(back, displayPath(f.path))
		}
	}
	if len(lost) == 0 {
		return fmt.Errorf("%s, so ossprey put back %s and the project is as it was", failed, strings.Join(back, ", "))
	}
	return fmt.Errorf("%s and could not put back %s, so Cargo.lock may not match the manifests; run `ossprey cargo fetch` before you build", failed, strings.Join(lost, ", "))
}

// stageFile writes data to a new file beside p's real target, given the target's mode or a new lock's, and syncs it, as cargo writes Cargo.toml bar the sync (verified with cargo 1.99.1).
func stageFile(p string, data []byte) (staged, error) {
	target, err := filepath.EvalSymlinks(p)
	if errors.Is(err, fs.ErrNotExist) {
		target, err = p, nil
	}
	if err != nil {
		return staged{}, err
	}
	fi, statErr := os.Stat(target)
	// A new lock gets cargo's mode for one, 0666 less the umask.
	perm := fs.FileMode(0o666)
	if statErr == nil {
		perm = 0o600
	}
	dir, base := filepath.Split(target)
	var tmp *os.File
	var name string
	for range 100 {
		name = filepath.Join(dir, "."+base+".ossprey-"+strconv.FormatUint(uint64(rand.Uint32()), 10))
		if tmp, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm); !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return staged{}, err
	}
	_, err = tmp.Write(data)
	if err == nil && statErr == nil {
		err = tmp.Chmod(fi.Mode().Perm())
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return staged{}, err
	}
	return staged{path: p, target: target, tmp: name}, nil
}

// landFile replaces p with data as cargo writes Cargo.toml, a new file beside the real target given the target's mode and renamed over it (verified with cargo 1.99.1), and syncs it first, which cargo does not.
func landFile(p string, data []byte) error {
	s, err := stageFile(p, data)
	if err != nil {
		return err
	}
	if err := commitFn(s); err != nil {
		os.Remove(s.tmp)
		return err
	}
	return nil
}

// scanCargoLock scans a copy of a workspace's Cargo.lock bytes alone, so nothing else in the tree is checked with it.
func scanCargoLock(ctx context.Context, opts Options, ws cargoWorkspace, data []byte, submitOnly bool) (*ossbom.SBOM, error) {
	tmp, err := os.MkdirTemp("", "ossprey-cargo-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	// Named after the workspace, since the dashboard shows the scanned directory's name.
	name := filepath.Base(filepath.Dir(ws.Lock))
	if name == "." || name == string(filepath.Separator) {
		name = "workspace"
	}
	dir := filepath.Join(tmp, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), data, 0o600); err != nil {
		return nil, err
	}
	return scanProjectFn(ctx, scanRequest{
		Dir: dir, APIURL: opts.APIURL, APIKey: opts.APIKey, MonitorID: opts.MonitorID,
		SubmitOnly: submitOnly, Installed: true, Trust: opts.Trust, CargoConfigDir: ws.ConfigDir,
	})
}

// cargoWorkspace is what a cargo command may rewrite, spelled as cargo spells it, and where cargo reads its configuration.
type cargoWorkspace struct {
	Lock string
	// Manifests are the root's Cargo.toml, then each member's.
	Manifests []string
	// Deps are the directories of the members' path dependencies.
	Deps      []string
	ConfigDir string
}

// errLockfileMoved is a resolver.lockfile-path, which puts the lock where this check does not look.
var errLockfileMoved = errors.New("a resolver.lockfile-path may move it")

// errScriptLock is a cargo script (-Zscript), whose lock cargo keeps under its build directory, where this check does not look.
var errScriptLock = errors.New("a cargo script keeps it in the build directory")

// readCargoWorkspace asks `cargo metadata --no-deps`, which reads manifests only, for the workspace root and its members, once no configuration may move the lock.
func readCargoWorkspace(ctx context.Context, args []string) (cargoWorkspace, error) {
	verb := verbIndex("cargo", args)
	if verb < 0 {
		return cargoWorkspace{}, errors.New("no cargo command")
	}
	configDir := cargoConfigDir(args[:verb])
	// Decided first, so cargo metadata never reads a config ossprey would refuse, a FIFO included.
	if lockfileMoved(args, configDir) {
		return cargoWorkspace{}, errLockfileMoved
	}
	return cargoMetadata(ctx, "", args, configDir)
}

// cargoMetadata asks `cargo metadata --no-deps` in dir ("" for ours) for the root and members a cargo command would use, with relative --config paths read from configDir.
func cargoMetadata(ctx context.Context, dir string, args []string, configDir string) (cargoWorkspace, error) {
	verb := verbIndex("cargo", args)
	// The options before the verb, rustup's +toolchain included, pick the same workspace and configuration.
	cmdArgs := append(withoutConfigFiles(args[:verb], configDir), "metadata", "--no-deps", "--format-version", "1")
	cmdArgs = append(cmdArgs, withoutConfigFiles(cargoWorkspaceFlags(args[verb+1:]), configDir)...)
	// The cargo the command runs, as Exec finds it, so both read the same manifests.
	cmd, err := realCommand(ctx, "cargo", cmdArgs)
	if err != nil {
		return cargoWorkspace{}, err
	}
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return cargoWorkspace{}, fmt.Errorf("cargo metadata: %s", firstErrorLine(stderr.String(), err))
	}
	var meta struct {
		WorkspaceRoot string `json:"workspace_root"`
		Packages      []struct {
			ManifestPath string `json:"manifest_path"`
			Dependencies []struct {
				Path string `json:"path"`
			} `json:"dependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(out, &meta); err != nil || meta.WorkspaceRoot == "" {
		return cargoWorkspace{}, errors.New("cargo metadata named no workspace root")
	}
	// Kept as cargo spells them, since cargo reaches a member or root through a linked directory without resolving it (verified with cargo 1.99.1).
	root := filepath.Clean(meta.WorkspaceRoot)
	ws := cargoWorkspace{
		Lock:      filepath.Join(root, "Cargo.lock"),
		Manifests: []string{filepath.Join(root, "Cargo.toml")},
		ConfigDir: configDir,
	}
	for _, p := range meta.Packages {
		if p.ManifestPath == "" {
			continue
		}
		if filepath.Base(p.ManifestPath) != "Cargo.toml" {
			// Only a script's manifest has another name, and cargo does not lock it at workspace_root (verified with cargo 1.99.1).
			return cargoWorkspace{}, errScriptLock
		}
		if m := filepath.Clean(p.ManifestPath); !slices.Contains(ws.Manifests, m) {
			ws.Manifests = append(ws.Manifests, m)
		}
		for _, d := range p.Dependencies {
			if d.Path != "" {
				ws.Deps = append(ws.Deps, filepath.Clean(d.Path))
			}
		}
	}
	return ws, nil
}

// canonicalDir is dir with every link resolved, or as cleaned when it cannot be.
func canonicalDir(dir string) string {
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return real
	}
	return filepath.Clean(dir)
}

// withoutConfigFiles drops each --config naming a file, which cargo metadata needs not to find the workspace and could drain (a pipe, or on macOS a /dev/fd/N sharing cargo's offset); a directory stays, as cargo fails on it alike.
func withoutConfigFiles(opts []string, dir string) []string {
	file := func(c string) bool {
		fi, err := os.Stat(cargoConfigPath(c, dir))
		return err == nil && !fi.IsDir()
	}
	out := make([]string, 0, len(opts))
	for i := 0; i < len(opts); i++ {
		a := opts[i]
		v, attached := strings.CutPrefix(a, "--config=")
		switch {
		case a == "--":
			return append(out, opts[i:]...)
		case a == "--config" && i+1 < len(opts):
			if !file(opts[i+1]) {
				out = append(out, a, opts[i+1])
			}
			i++
		case !attached || !file(v):
			out = append(out, a)
		}
	}
	return out
}

// firstErrorLine is cargo's own error line, with the lines up to a blank one when it ends in a colon, else its first line, else err.
func firstErrorLine(stderr string, err error) string {
	first := ""
	lines := strings.Split(stderr, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "error") {
			if !strings.HasSuffix(line, ":") {
				return line
			}
			// cargo names what it means on the lines after, such as the workspace a member believes it is in.
			for _, next := range lines[i+1:] {
				if next = strings.TrimSpace(next); next == "" {
					break
				}
				line += " " + next
			}
			return line
		}
		if first == "" {
			first = line
		}
	}
	if first != "" {
		return first
	}
	return err.Error()
}

// cargoWorkspaceFlags are the options after the verb that move the workspace or its configuration, spelled for `cargo metadata`.
func cargoWorkspaceFlags(rest []string) []string {
	rest = cargoSplitShorts(rest, cargoResolveShorts)
	var out []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		var name, value string
		switch {
		case a == "--":
			return out
		case a == "--manifest-path" || a == "-m" || a == "--config" || a == "-Z":
			if i+1 >= len(rest) {
				continue
			}
			name, value = a, rest[i+1]
			i++
		case strings.HasPrefix(a, "--manifest-path=") || strings.HasPrefix(a, "--config="):
			name, value, _ = strings.Cut(a, "=")
		default:
			continue
		}
		if name == "-m" {
			name = "--manifest-path"
		}
		out = append(out, name, value)
	}
	return out
}

// cargoChdir is -C's directory joined to the working directory as chdir(2) is given it, else the working directory.
func cargoChdir(globals []string) string {
	dir, _ := os.Getwd()
	globals = cargoSplitShorts(globals, globalValueFlags["cargo"])
	for i := 0; i < len(globals); i++ {
		a := globals[i]
		var v string
		switch {
		case a == "-C" && i+1 < len(globals):
			v = globals[i+1]
			i++
		case globalValueFlags["cargo"][a]:
			i++
			continue
		default:
			continue
		}
		if !filepath.IsAbs(v) {
			// Not cleaned yet: the kernel follows a link before the `..` after it, so `lnk/..` is the link target's parent (verified).
			v = dir + string(filepath.Separator) + v
		}
		dir = v
	}
	if runtime.GOOS == "windows" {
		// Windows takes `..` off the path as written, before it opens anything.
		return filepath.Clean(dir)
	}
	return dir
}

// cargoConfigDir is where cargo starts reading configuration: -C's directory, else the working directory, resolved as chdir(2) resolves it.
func cargoConfigDir(globals []string) string {
	// EvalSymlinks takes each `..` off the resolved prefix, as the kernel does.
	return canonicalDir(cargoChdir(globals))
}

// cargoCwd is the working directory cargo spells after -C: getcwd's physical path, or on Windows the path as set, short names and all.
func cargoCwd(globals []string) string {
	if runtime.GOOS == "windows" {
		return cargoChdir(globals)
	}
	return cargoConfigDir(globals)
}

// lockfileMoved reports whether a resolver.lockfile-path cargo may read could move the lock: from the environment, a --config on the line, or a config file or one it includes.
func lockfileMoved(args []string, configDir string) bool {
	if os.Getenv("CARGO_RESOLVER_LOCKFILE_PATH") != "" {
		return true
	}
	// Only the decoded key counts, escapes included, though a config that cannot be read, is not a regular file, or that the bounded parser refuses may set it too.
	moves := func(data []byte, err error) bool {
		if err != nil {
			return true
		}
		doc, ok := cargoConfigDoc(data)
		resolver, _ := doc["resolver"].(map[string]any)
		return !ok || resolver["lockfile-path"] != nil || doc["include"] != nil
	}
	for _, c := range cargoConfigArgs(args) {
		if moves(cargoConfigArg(c, configDir)) {
			return true
		}
	}
	files := cargoConfigFiles(configDir)
	if home := catalog.CargoHome(configDir); home != "" {
		files = append(files, cargoConfigFile(home))
	}
	for _, f := range files {
		if data, there, err := readConfig(f); there && moves(data, err) {
			return true
		}
	}
	return false
}

// cargoDefaultRegistry is the registry other than crates.io that `cargo install` takes a crate from when the line names none, or "".
func cargoDefaultRegistry(args []string) string {
	// The value set nearest the line wins; an include, or a regular file that cannot be read or that the bounded parser refuses, may set it too.
	pick := func(data []byte, err error) (string, bool) {
		if errors.Is(err, catalog.ErrNotRegular) {
			// cargo install reads its config again from CARGO_HOME, when a pipe read once is empty, so one that is not a regular file sets nothing.
			return "", false
		}
		doc, ok := cargoConfigDoc(data)
		if err != nil || !ok {
			return "a config it cannot read", true
		}
		if reg, _ := doc["registry"].(map[string]any); reg != nil {
			if v, ok := reg["default"].(string); ok {
				return v, true
			}
		}
		if doc["include"] != nil {
			return "an included config", true
		}
		return "", false
	}
	found := func(v string) string {
		if v == "crates-io" {
			return ""
		}
		return v
	}
	dir := cargoConfigDir(args[:max(verbIndex("cargo", args), 0)])
	for _, c := range slices.Backward(cargoConfigArgs(args)) {
		if v, ok := pick(cargoConfigArg(c, dir)); ok {
			return found(v)
		}
	}
	if v := os.Getenv("CARGO_REGISTRY_DEFAULT"); v != "" {
		return found(v)
	}
	home := catalog.CargoHome(dir)
	if home == "" {
		return ""
	}
	// cargo install reads no project config, only those from CARGO_HOME up.
	for _, f := range append(cargoConfigFiles(home), cargoConfigFile(home)) {
		if data, there, err := readConfig(f); there {
			if v, ok := pick(data, err); ok {
				return found(v)
			}
		}
	}
	return ""
}

// cargoConfigArgs are the --config values on the line, in order, before any `--`.
func cargoConfigArgs(args []string) []string {
	var out []string
	for i := 0; i < len(args) && args[i] != "--"; i++ {
		if args[i] == "--config" && i+1 < len(args) {
			out = append(out, args[i+1])
			i++
		} else if v, ok := strings.CutPrefix(args[i], "--config="); ok {
			out = append(out, v)
		}
	}
	return out
}

// cargoConfigArg is what cargo reads for a --config value: the file it names, from dir where cargo runs, when that exists, else the value as TOML.
func cargoConfigArg(c, dir string) ([]byte, error) {
	if c != "" {
		if data, there, err := readConfig(cargoConfigPath(c, dir)); there {
			return data, err
		}
	}
	return []byte(c), nil
}

// cargoConfigPath is the file a --config value names, read from dir where cargo runs.
func cargoConfigPath(c, dir string) string {
	if c != "" && dir != "" && filepath.VolumeName(c) == "" && !os.IsPathSeparator(c[0]) {
		// cargo joins the value to its working directory uncleaned, so the kernel applies `..` after any link.
		return dir + string(filepath.Separator) + c
	}
	return c
}

// cargoConfigFiles are the configs cargo reads from dir up, one per level.
func cargoConfigFiles(dir string) []string {
	var out []string
	for d := dir; ; d = filepath.Dir(d) {
		out = append(out, cargoConfigFile(filepath.Join(d, ".cargo")))
		if filepath.Dir(d) == d {
			return out
		}
	}
}

// cargoConfigFile is the one config cargo reads in dir: the legacy config when it opens, else config.toml.
func cargoConfigFile(dir string) string {
	legacy := filepath.Join(dir, "config")
	// cargo opens anything there, but a FIFO may never open, so only a regular file is opened here.
	if fi, err := os.Stat(legacy); err == nil && !fi.Mode().IsRegular() {
		return legacy
	}
	if f, err := os.Open(legacy); err == nil {
		f.Close()
		return legacy
	}
	return filepath.Join(dir, "config.toml")
}

// cargoConfigDoc parses a cargo config, or a --config KEY=VALUE, with the catalog's bounded parser; false is one it refuses or cannot decode.
func cargoConfigDoc(data []byte) (map[string]any, bool) {
	doc, err := catalog.ParseCargoConfig(data)
	return doc, err == nil
}

// readConfig reads the config at p when cargo would find one there, failing on one that is not a regular file, since a FIFO may never end.
func readConfig(p string) (data []byte, there bool, err error) {
	if !exists(p) {
		return nil, false, nil
	}
	data, _, err = catalog.ReadRegular(p, catalog.CargoManifestLimit)
	return data, true, err
}

// readCargoFile reads a manifest or lock whole, or fails when it is not a regular file or is over catalog.CargoProofLimit.
func readCargoFile(p string) ([]byte, fs.FileInfo, error) {
	data, fi, err := catalog.ReadRegular(p, catalog.CargoProofLimit)
	if err == nil && len(data) > catalog.CargoProofLimit {
		err = &fs.PathError{Op: "read", Path: p, Err: fmt.Errorf("over the %d byte limit", catalog.CargoProofLimit)}
	}
	return data, fi, err
}

// exists reports whether p names anything.
func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// displayPath is p relative to the working directory, preferring whichever spelling of it, physical or as typed, holds p.
func displayPath(p string) string {
	wd, err := os.Getwd()
	if err != nil {
		return p
	}
	real, err := filepath.EvalSymlinks(wd)
	if err != nil {
		real = wd
	}
	best := p
	for _, base := range []string{real, wd} {
		rel, err := filepath.Rel(base, p)
		switch {
		case err != nil:
		case rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)):
			return rel
		case best == p:
			best = rel
		}
	}
	return best
}
