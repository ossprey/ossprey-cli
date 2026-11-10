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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

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

// cargoRunFirstShorts are the short options of add, update, fetch and generate-lockfile that take a value (TestCargoFlagTablesMatchCargo).
var cargoRunFirstShorts = flagSet("-F", "-m", "-p", "-Z")

// cargoRunFirstAt matches the cargo verbs that resolve and lock but build nothing, unless asked for --help.
func cargoRunFirstAt(args []string) (int, bool) {
	start, ok := verbAt("cargo", "add", "update", "generate-lockfile", "fetch")(args)
	if !ok || cargoPrintsOnly(args, start, cargoRunFirstShorts) {
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

// cargoOptionsHave reports whether one of flags is among split args' options before `--`, never a value an option took (`-C-h` names a directory).
func cargoOptionsHave(split []string, takes map[string]bool, flags ...string) bool {
	for i := 0; i < len(split); i++ {
		switch a := split[i]; {
		case a == "--":
			return false
		case slices.Contains(flags, a):
			return true
		case takes[a] && i+1 < len(split) && !cargoOptionalSkips(a, split[i+1]):
			i++
		}
	}
	return false
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
			return append(split, strings.TrimPrefix(a[i:], "=")), false
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

// cargoOptionalSkips reports whether clap leaves next alone for flag: an optional value is never an option token, so `--bin -F pcre2` gives pcre2 to -F.
func cargoOptionalSkips(flag, next string) bool {
	return cargoOptionalValues[flag] && len(next) > 1 && next[0] == '-'
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

// checkCargoAfter runs a cargo verb that only resolves and locks, then checks the Cargo.lock it leaves; a block puts back every file it changed.
func checkCargoAfter(ctx context.Context, m *Manager, opts Options) error {
	command := m.Bin + " " + strings.Join(opts.Args, " ")
	if opts.Passive {
		flushWarnings(ctx)
		before := cargoLockBefore(ctx, opts.Args)
		runErr := execFn(ctx, m.Bin, opts.Args)
		written := changedFiles(before)
		ws, err := cargoWorkspaceFn(ctx, opts.Args)
		if cargoFailedOnItsWorkspace(command, runErr, err) {
			return runErr
		}
		if err == nil && ws.LockMayMove && !lockChanged(written, ws.Lock) {
			// Only a lock cargo changed is known to be there, which shows only when cargoLockBefore saved it.
			err = errLockfileMoved
		}
		if err == nil && !exists(ws.Lock) {
			// cargo add --dry-run with no lock writes nothing, so there is nothing to post.
			note("ossprey: `%s` left no Cargo.lock; nothing posted\n", command)
			return runErr
		}
		// A failed command may still have locked (cargo fetch locks, then downloads), so its lock is posted, or a warning says why not.
		stop := progress.Submit(progressTo(), 0)
		var sbom *ossbom.SBOM
		if err == nil {
			sbom, err = scanCargoLock(ctx, opts, ws, true)
		}
		stop()
		flushWarnings(ctx)
		reportPassive(opts, sbom, err)
		return runErr
	}

	ws, err := cargoWorkspaceFn(ctx, opts.Args)
	var saved []savedFile
	var unread []string
	if err == nil {
		// A missing credential stops here, before cargo changes anything, as it stops any gating install.
		if credErr := cargoCredentialFn(ctx, opts.APIURL, opts.APIKey); credErr != nil {
			flushWarnings(ctx)
			return credErr
		}
		saved, unread = snapshot(ws.files())
	}
	flushWarnings(ctx)
	runErr := execFn(ctx, m.Bin, opts.Args)
	// Read as cargo exits, so a block undoes cargo's changes and never an edit made while the check runs.
	changes := changedFiles(saved)
	if cargoFailedOnItsWorkspace(command, runErr, err) {
		return runErr
	}
	if err == nil && ws.LockMayMove && !lockChanged(changes, ws.Lock) {
		// Only cargo read the config that could move the lock, and it left the project lock alone, so it may have written one elsewhere.
		err = errLockfileMoved
	}
	// A moved or script lock has no snapshot, so a failed command still gets the warning below.
	if runErr != nil && err == nil {
		// cargo writes before it can fail: fetch locks before it downloads, add edits Cargo.toml before it resolves; a lock unread before may have changed.
		if !lockChanged(changes, ws.Lock) && !slices.Contains(unread, ws.Lock) {
			var changed []string
			for _, c := range changes {
				changed = append(changed, displayPath(c.before.path))
			}
			if len(changed) > 0 {
				fmt.Fprintf(errOut, "ossprey: warning: `%s` failed after changing %s, which was not checked\n", command, strings.Join(changed, ", "))
			}
			// A manifest unread before cargo ran may have changed too.
			if len(unread) > 0 {
				fmt.Fprintf(errOut, "ossprey: warning: `%s` failed after possibly changing %s, which was not checked\n", command, strings.Join(displayPaths(unread), ", "))
			}
			return runErr
		}
	}
	if err == nil && len(changes) == 0 && !exists(ws.Lock) {
		// cargo add --dry-run with no lock writes nothing, so there is nothing to check.
		note("ossprey: `%s` left no Cargo.lock; nothing to check\n", command)
		return runErr
	}
	var sbom *ossbom.SBOM
	if err == nil {
		stop := progress.Start(progressTo(), "ossprey: scan in progress")
		sbom, err = scanCargoLock(ctx, opts, ws, false)
		stop()
	}
	flushWarnings(ctx)
	if err != nil {
		kept := "cargo's changes are kept"
		if runErr != nil && len(changes) == 0 && slices.Contains(unread, ws.Lock) {
			// A failed command may have changed nothing, and a lock unread before cannot say.
			kept = "any changes cargo made are kept"
		}
		fmt.Fprintf(errOut, "ossprey: warning: Cargo.lock not checked after `%s` (%v); %s\n", command, err, kept)
		return runErr
	}

	summary, hasMalware := scan.MalwareReports(sbom, severity.ParseFloor(sbom.FailingSeverityFloor))
	for _, msg := range summary.Informational {
		note("ossprey: %s\n", msg)
	}
	lock := displayPath(ws.Lock)
	if hasMalware {
		printBlock(m, opts, summary)
		reportRestore(command, changes, unread)
		return ErrBlocked
	}
	verdict, checked := CleanVerdict(sbom, len(summary.Informational), " in "+lock)
	switch {
	case len(sbom.Components) == 0:
		note("ossprey: found no dependencies to check in %s\n", lock)
	case !checked:
		note("ossprey: the platform checked none of the %s in %s\n", countPackages(len(sbom.Components)), lock)
	default:
		fmt.Fprintf(errOut, "ossprey: %s\n", verdict)
	}
	return runErr
}

// lockChanged reports whether cargo changed the lock, which shows it wrote the lock there.
func lockChanged(changes []fileChange, lock string) bool {
	return slices.ContainsFunc(changes, func(c fileChange) bool { return c.before.path == lock })
}

// cargoLockBefore saves the lock before a passive cargo runs when only a --config naming no regular file may move it, which cargo metadata is never handed, so reading the workspace first drains nothing.
func cargoLockBefore(ctx context.Context, args []string) []savedFile {
	verb := verbIndex("cargo", args)
	if verb < 0 || len(cargoConfigArgs(args)) == 0 || lockfileMoved(args, cargoConfigDir(args[:verb])) != lockUnreadArg {
		return nil
	}
	ws, err := cargoWorkspaceFn(ctx, args)
	if err != nil || !ws.LockMayMove {
		return nil
	}
	saved, _ := snapshot([]string{ws.Lock})
	return saved
}

// cargoFailedOnItsWorkspace is a failed command whose workspace cargo metadata cannot read either: cargo's error says why, and only a moved or script lock may have been written.
func cargoFailedOnItsWorkspace(command string, runErr, wsErr error) bool {
	if runErr == nil || wsErr == nil || errors.Is(wsErr, errLockfileMoved) || errors.Is(wsErr, errScriptLock) {
		return false
	}
	note("ossprey: `%s` failed and its workspace could not be read (%v); nothing to check\n", command, wsErr)
	return true
}

// scanCargoLock scans a copy of the workspace's Cargo.lock alone, so nothing else in the tree is checked with it.
func scanCargoLock(ctx context.Context, opts Options, ws cargoWorkspace, submitOnly bool) (*ossbom.SBOM, error) {
	data, _, err := readCargoFile(ws.Lock)
	if err != nil {
		return nil, err
	}
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

// cargoWorkspace is what a cargo command may rewrite, and where cargo reads its configuration.
type cargoWorkspace struct {
	Lock      string
	Manifests []string
	ConfigDir string
	// LockMayMove is a config only cargo can read, so the lock counts only where cargo changed it.
	LockMayMove bool
}

func (w cargoWorkspace) files() []string {
	return append(slices.Clone(w.Manifests), w.Lock)
}

// errLockfileMoved is a resolver.lockfile-path, which puts the lock where this check does not look.
var errLockfileMoved = errors.New("a resolver.lockfile-path may move it")

// lockPlace is what the configs cargo reads say of where it writes the lock, in rising order of doubt.
type lockPlace int

const (
	lockStays lockPlace = iota
	// lockUnreadArg is a --config naming no regular file, which only cargo reads, since reading it would drain it.
	lockUnreadArg
	// lockUnreadLevel is a config cargo finds that is not a regular file, which cargo metadata reads too.
	lockUnreadLevel
	lockMoves
)

// errScriptLock is a cargo script (-Zscript), whose lock cargo keeps under its build directory, where this check does not look.
var errScriptLock = errors.New("a cargo script keeps it in the build directory")

// readCargoWorkspace asks `cargo metadata --no-deps`, which reads manifests only, for the workspace root and its members.
func readCargoWorkspace(ctx context.Context, args []string) (cargoWorkspace, error) {
	verb := verbIndex("cargo", args)
	if verb < 0 {
		return cargoWorkspace{}, errors.New("no cargo command")
	}
	configDir := cargoConfigDir(args[:verb])
	// The options before the verb, rustup's +toolchain included, pick the same workspace and configuration.
	cmdArgs := append(withoutConfigFiles(args[:verb], configDir), "metadata", "--no-deps", "--format-version", "1")
	cmdArgs = append(cmdArgs, withoutConfigFiles(cargoWorkspaceFlags(args[verb+1:]), configDir)...)
	// The cargo the command runs, as Exec finds it, so both read the same manifests.
	cmd, err := realCommand(ctx, "cargo", cmdArgs)
	if err != nil {
		return cargoWorkspace{}, err
	}
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
		} `json:"packages"`
	}
	if err := json.Unmarshal(out, &meta); err != nil || meta.WorkspaceRoot == "" {
		return cargoWorkspace{}, errors.New("cargo metadata named no workspace root")
	}
	ws := cargoWorkspace{
		Lock:      filepath.Join(meta.WorkspaceRoot, "Cargo.lock"),
		Manifests: []string{filepath.Join(meta.WorkspaceRoot, "Cargo.toml")},
		ConfigDir: configDir,
	}
	for _, p := range meta.Packages {
		if p.ManifestPath != "" && filepath.Base(p.ManifestPath) != "Cargo.toml" {
			// Only a script's manifest has another name, and cargo does not lock it at workspace_root (verified with cargo 1.99.1).
			return cargoWorkspace{}, errScriptLock
		}
		if p.ManifestPath != "" && !slices.Contains(ws.Manifests, p.ManifestPath) {
			ws.Manifests = append(ws.Manifests, p.ManifestPath)
		}
	}
	switch lockfileMoved(args, ws.ConfigDir) {
	case lockMoves:
		return cargoWorkspace{}, errLockfileMoved
	case lockUnreadArg, lockUnreadLevel:
		ws.LockMayMove = true
	}
	return ws, nil
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

// firstErrorLine is cargo's own error line, else its first line, else err.
func firstErrorLine(stderr string, err error) string {
	first := ""
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "error") {
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
	rest = cargoSplitShorts(rest, cargoRunFirstShorts)
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

// cargoConfigDir is where cargo starts reading configuration: -C's directory, else the working directory, resolved as chdir(2) resolves it.
func cargoConfigDir(globals []string) string {
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
		dir = filepath.Clean(dir)
	}
	// EvalSymlinks takes each `..` off the resolved prefix, as the kernel does.
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return real
	}
	return filepath.Clean(dir)
}

// lockfileMoved reports whether a resolver.lockfile-path cargo may read moves the lock, or only cargo can tell: from the environment, a --config on the line, or a config file or one it includes.
func lockfileMoved(args []string, configDir string) lockPlace {
	if os.Getenv("CARGO_RESOLVER_LOCKFILE_PATH") != "" {
		return lockMoves
	}
	// Only the decoded key counts, escapes included, though a config that cannot be read, or that the bounded parser refuses, may set it too; one that is not a regular file is left to cargo.
	place := func(data []byte, err error, unread lockPlace) lockPlace {
		if errors.Is(err, catalog.ErrNotRegular) {
			return unread
		}
		if err != nil {
			return lockMoves
		}
		doc, ok := cargoConfigDoc(data)
		resolver, _ := doc["resolver"].(map[string]any)
		if !ok || resolver["lockfile-path"] != nil || doc["include"] != nil {
			return lockMoves
		}
		return lockStays
	}
	got := lockStays
	for _, c := range cargoConfigArgs(args) {
		data, err := cargoConfigArg(c, configDir)
		got = max(got, place(data, err, lockUnreadArg))
	}
	files := cargoConfigFiles(configDir)
	if home := catalog.CargoHome(configDir); home != "" {
		files = append(files, cargoConfigFile(home))
	}
	for _, f := range files {
		if data, there, err := readConfig(f); there {
			got = max(got, place(data, err, lockUnreadLevel))
		}
	}
	return got
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

// savedFile is a manifest or lock as it stood, or that it did not exist; unread is one there that could not be read.
type savedFile struct {
	path    string
	existed bool
	data    []byte
	mode    fs.FileMode
	unread  bool
	// info is the file read, which tells it apart from another the path reaches later.
	info fs.FileInfo
}

// stateOf saves p as it stands now; one that is not a regular file or is over the bound is unread.
func stateOf(p string) savedFile {
	data, fi, err := readCargoFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return savedFile{path: p}
	}
	if err != nil {
		return savedFile{path: p, existed: true, unread: true}
	}
	return savedFile{path: p, existed: true, data: data, mode: fi.Mode().Perm(), info: fi}
}

// is reports whether f and g hold the same state; an unread one matches nothing.
func (f savedFile) is(g savedFile) bool {
	return !f.unread && !g.unread && f.existed == g.existed && bytes.Equal(f.data, g.data)
}

// snapshot saves each file, or that it did not exist; one it cannot read is left out, and so never touched, and returned to be named on a block.
func snapshot(paths []string) (saved []savedFile, unread []string) {
	for _, p := range paths {
		if f := stateOf(p); !f.unread {
			saved = append(saved, f)
		} else {
			unread = append(unread, p)
		}
	}
	return saved, unread
}

// fileChange is a saved file the command changed, created or removed, and what the command left there.
type fileChange struct{ before, after savedFile }

// changedFiles are the saved files the command changed, created or removed, each with what it left.
func changedFiles(saved []savedFile) []fileChange {
	var out []fileChange
	for _, f := range saved {
		if now := stateOf(f.path); !f.is(now) {
			out = append(out, fileChange{f, now})
		}
	}
	return out
}

// reportRestore undoes each change in the file cargo left, while it is still as cargo left it, leaves alone one changed again or already back since, and says so.
func reportRestore(command string, changes []fileChange, unread []string) {
	var done, kept, back []string
	for _, c := range changes {
		f, now := c.before, stateOf(c.before.path)
		verb := "restore"
		var err error
		switch {
		case f.is(now):
			back = append(back, displayPath(f.path))
			continue
		case !c.after.is(now) || c.after.mode != now.mode || now.existed && (!os.SameFile(now.info, c.after.info) || !sameOwner(now.info, c.after.info)):
			// A permission change since cargo exited is the user's too, and a file the path reaches only since was never cargo's.
			err = errNotLeft
		case !f.existed:
			verb, err = "remove", removeLeft(f.path, c.after.info)
		default:
			err = rewriteLeft(f, c.after)
		}
		switch {
		case errors.Is(err, errNotLeft):
			kept = append(kept, displayPath(f.path))
		case err != nil:
			fmt.Fprintf(errOut, "ossprey: warning: could not %s %s (%v)\n", verb, displayPath(f.path), err)
		default:
			done = append(done, verb+"d "+displayPath(f.path))
		}
	}
	if len(done) > 0 {
		fmt.Fprintf(errOut, "ossprey: undid `%s`: %s\n", command, strings.Join(done, ", "))
	}
	if len(back) > 0 {
		fmt.Fprintf(errOut, "ossprey: `%s` changed %s, already back as before\n", command, strings.Join(back, ", "))
	}
	if len(kept) > 0 {
		fmt.Fprintf(errOut, "ossprey: warning: did not undo `%s` in %s, changed again after cargo exited\n", command, strings.Join(kept, ", "))
	}
	if len(unread) > 0 {
		fmt.Fprintf(errOut, "ossprey: warning: did not undo `%s` in %s, which could not be read before cargo ran\n", command, strings.Join(displayPaths(unread), ", "))
	}
	if len(changes) == 0 && len(unread) == 0 {
		fmt.Fprintf(errOut, "ossprey: `%s` changed no Cargo.toml or Cargo.lock; nothing to restore\n", command)
	}
}

// errNotLeft is a path that no longer reaches the file cargo left there.
var errNotLeft = errors.New("not the file cargo left")

// removeLeft removes the file cargo created at p, at the end of any link it wrote through, and only while it is the file left.
func removeLeft(p string, left fs.FileInfo) error {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(real); err != nil || !os.SameFile(fi, left) {
		return errNotLeft
	}
	return os.Remove(real)
}

// writeRestore writes a restore's bytes, to a staged copy or in place; a test seam.
var writeRestore = func(w io.Writer, data []byte) error {
	_, err := w.Write(data)
	return err
}

// errInPlace is a restore a staged copy would make differently from a write in place, so it is written in place.
var errInPlace = errors.New("restore in place")

// rewriteLeft puts f's bytes and mode back in the file left at its path, through a link as cargo wrote: a staged copy replaces it when that keeps what a write in place keeps, else it is written in place.
func rewriteLeft(f, left savedFile) error {
	if !left.existed {
		return recreateLeft(f)
	}
	target, err := filepath.EvalSymlinks(f.path)
	if err != nil {
		return err
	}
	if err := replaceLeft(f, left, target); !errors.Is(err, errInPlace) {
		return err
	}
	return rewriteInPlace(f, left)
}

// replaceLeft renames a synced copy of f over target while the path still reaches it as cargo left it; errInPlace when the copy cannot be made beside it or would not keep its one name, owner, group and ACL.
func replaceLeft(f, left savedFile, target string) error {
	dir, err := os.OpenRoot(filepath.Dir(target))
	if err != nil {
		return errInPlace
	}
	defer dir.Close()
	base := filepath.Base(target)
	if fi, err := dir.Lstat(base); err != nil || !os.SameFile(fi, left.info) {
		return errNotLeft
	} else if !oneLink(fi) || hasACL(target) {
		return errInPlace
	}
	tmp, name, err := stageFile(dir, base)
	if err != nil {
		// Only a directory that will not take the copy falls back; a full volume leaves cargo's file whole.
		if errors.Is(err, fs.ErrPermission) {
			return errInPlace
		}
		return err
	}
	// Removed through the directory held open, so no copy is left in a directory moved since.
	defer func() {
		if name != "" {
			dir.Remove(name)
		}
	}()
	if !ownAs(tmp, left.info) || !sameACL(tmp, target) {
		tmp.Close()
		return errInPlace
	}
	if err := writeStaged(tmp, f); err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(f.path); err != nil || real != target {
		return errNotLeft
	}
	fi, err := os.Lstat(target)
	if err != nil || !os.SameFile(fi, left.info) || !leftIn(dir, base, left) {
		return errNotLeft
	}
	if !oneLink(fi) {
		return errInPlace
	}
	if err := renameStaged(dir, name, base); err != nil {
		// A mount point (EBUSY), another device or a file not ours to replace still takes cargo's own in-place write.
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) || errors.Is(err, fs.ErrPermission) {
			return errInPlace
		}
		return err
	}
	name = ""
	return nil
}

// stageFile, renameStaged and linkStaged stage a copy and rename it over the target or link it in; test seams.
var (
	stageFile    = stageIn
	renameStaged = func(dir *os.Root, from, to string) error { return dir.Rename(from, to) }
	linkStaged   = func(dir *os.Root, from, to string) error { return dir.Link(from, to) }
)

// rewriteInPlace writes f's bytes into the file left at its path, as cargo writes a lock, once the handle shows it still as cargo left it.
func rewriteInPlace(f, left savedFile) error {
	fh, err := os.OpenFile(f.path, os.O_RDWR|catalog.ONonblock, 0)
	if err != nil {
		return err
	}
	if !holdsLeft(fh, left) {
		fh.Close()
		return errNotLeft
	}
	err = fh.Truncate(0)
	if err == nil {
		_, err = fh.Seek(0, io.SeekStart)
	}
	if err == nil {
		err = writeRestore(fh, f.data)
	}
	if err == nil {
		_ = fh.Chmod(f.mode)
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	return err
}

// recreateLeft writes back a file cargo removed, at the end of any link it was reached through, by linking in a staged copy, or by creating it in place when no copy can be staged or linked; either way one that has appeared there since is left alone.
func recreateLeft(f savedFile) error {
	at, base, err := linkEnd(f.path)
	if err != nil {
		return err
	}
	if dir, err := os.OpenRoot(at); err == nil {
		defer dir.Close()
		if tmp, name, err := stageFile(dir, base); err == nil {
			defer dir.Remove(name)
			if err := writeStaged(tmp, f); err != nil {
				return err
			}
			switch err := linkStaged(dir, name, base); {
			case err == nil:
				return nil
			case errors.Is(err, fs.ErrExist):
				return errNotLeft
			}
			// A filesystem without hard links refuses the link, so the file is created below, which never replaces one either.
		}
	}
	fh, err := os.OpenFile(filepath.Join(at, base), os.O_WRONLY|os.O_CREATE|os.O_EXCL|catalog.ONonblock, f.mode)
	if errors.Is(err, fs.ErrExist) {
		return errNotLeft
	}
	if err != nil {
		return err
	}
	err = writeRestore(fh, f.data)
	if err == nil {
		_ = fh.Chmod(f.mode)
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	return err
}

// linkEnd is the real directory and name p leads to through the links at its end, each link's text read against its own directory as the kernel reads it.
func linkEnd(p string) (string, string, error) {
	for range 40 {
		dir, base := filepath.Split(p)
		dir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", "", err
		}
		p = filepath.Join(dir, base)
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
			return dir, base, nil
		}
		to, err := os.Readlink(p)
		if err != nil {
			return "", "", err
		}
		p = linkTarget(dir, to)
	}
	return "", "", &fs.PathError{Op: "readlink", Path: p, Err: syscall.ELOOP}
}

// linkTarget is the path a link in dir whose text is to leads to, as the kernel reads it.
func linkTarget(dir, to string) string {
	switch {
	case filepath.IsAbs(to):
		return to
	case filepath.VolumeName(to) != "":
		// A drive-relative text (C:x) starts from that drive's working directory.
		if abs, err := filepath.Abs(to); err == nil {
			return abs
		}
		return to
	case to != "" && os.IsPathSeparator(to[0]):
		// A text rooted without a drive (\x) starts at the root of the link's own drive.
		return filepath.VolumeName(dir) + to
	}
	// Left uncleaned, so a `..` after a link in the text goes where the kernel takes it.
	return dir + string(filepath.Separator) + to
}

// stageIn creates a new file in dir to stage a copy of base in, and returns its name there.
func stageIn(dir *os.Root, base string) (*os.File, string, error) {
	var err error
	for range 100 {
		name := "." + base + ".ossprey-" + strconv.FormatUint(uint64(rand.Uint32()), 10)
		var fh *os.File
		if fh, err = dir.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); !errors.Is(err, fs.ErrExist) {
			return fh, name, err
		}
	}
	return nil, "", err
}

// writeStaged writes f's bytes and mode to a staged copy, synced and closed.
func writeStaged(tmp *os.File, f savedFile) error {
	err := writeRestore(tmp, f.data)
	if err == nil {
		err = tmp.Chmod(f.mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	return err
}

// leftIn reports whether base in dir is still the file cargo left, with its mode and contents.
func leftIn(dir *os.Root, base string, left savedFile) bool {
	fh, err := dir.OpenFile(base, os.O_RDONLY|catalog.ONonblock, 0)
	if err != nil {
		return false
	}
	defer fh.Close()
	return holdsLeft(fh, left)
}

// holdsLeft reports whether fh is the file cargo left, with the owner, mode and contents it had as cargo exited.
func holdsLeft(fh *os.File, left savedFile) bool {
	fi, err := fh.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(fi, left.info) || fi.Mode().Perm() != left.mode || !sameOwner(fi, left.info) {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(fh, catalog.CargoProofLimit+1))
	return err == nil && bytes.Equal(data, left.data)
}

// displayPaths is each of paths as displayPath gives it.
func displayPaths(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = displayPath(p)
	}
	return out
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
