package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/progress"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/shim"
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
	if !ok || cargoHas(cargoSplitShorts(args[start:], cargoRunFirstShorts), "-h", "--help") {
		return 0, false
	}
	return start, true
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

// cargoInstallAt matches `cargo install`, but not `cargo install --list`.
func cargoInstallAt(args []string) (int, bool) {
	start, ok := verbAt("cargo", "install")(args)
	if !ok || cargoHas(args[start:], "--list") {
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
		// clap fills an optional value only from a token that is not an option, so `--bin -F pcre2` gives pcre2 to -F.
		if !inline && valueFlags["cargo"][flag] && i+1 < len(args) && !(cargoOptionalValues[flag] && len(args[i+1]) > 1 && args[i+1][0] == '-') {
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
		runErr := execFn(ctx, m.Bin, opts.Args)
		ws, err := cargoWorkspaceFn(ctx, opts.Args)
		if err == nil && !exists(ws.Lock) {
			// cargo add --dry-run with no lock writes nothing, so there is nothing to post.
			note("ossprey: `%s` left no Cargo.lock; nothing posted\n", command)
			return runErr
		}
		// A failed command may still have locked (cargo fetch locks, then downloads), so its lock is posted if there is one.
		if runErr != nil && err != nil {
			return runErr
		}
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
	if err == nil {
		// A missing credential stops here, before cargo changes anything, as it stops any gating install.
		if credErr := cargoCredentialFn(ctx, opts.APIURL, opts.APIKey); credErr != nil {
			flushWarnings(ctx)
			return credErr
		}
		saved = snapshot(ws.files())
	}
	flushWarnings(ctx)
	runErr := execFn(ctx, m.Bin, opts.Args)
	// Read as cargo exits, so a block undoes cargo's changes and never an edit made while the check runs.
	changes := changedFiles(saved)
	if runErr != nil {
		if err != nil {
			return runErr
		}
		// cargo writes before it can fail: fetch locks before it downloads, add edits Cargo.toml before it resolves.
		if !slices.ContainsFunc(changes, func(c fileChange) bool { return c.before.path == ws.Lock }) {
			var changed []string
			for _, c := range changes {
				changed = append(changed, displayPath(c.before.path))
			}
			if len(changed) > 0 {
				fmt.Fprintf(errOut, "ossprey: warning: `%s` failed after changing %s, which was not checked\n", command, strings.Join(changed, ", "))
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
		fmt.Fprintf(errOut, "ossprey: warning: Cargo.lock not checked after `%s` (%v); cargo's changes are kept\n", command, err)
		return runErr
	}

	summary, hasMalware := scan.MalwareReports(sbom, severity.ParseFloor(sbom.FailingSeverityFloor))
	for _, msg := range summary.Informational {
		note("ossprey: %s\n", msg)
	}
	lock := displayPath(ws.Lock)
	if hasMalware {
		printBlock(m, opts, summary)
		reportRestore(command, changes)
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

// scanCargoLock scans a copy of the workspace's Cargo.lock alone, so nothing else in the tree is checked with it.
func scanCargoLock(ctx context.Context, opts Options, ws cargoWorkspace, submitOnly bool) (*ossbom.SBOM, error) {
	data, err := os.ReadFile(ws.Lock)
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
}

func (w cargoWorkspace) files() []string {
	return append(slices.Clone(w.Manifests), w.Lock)
}

// errLockfileMoved is a resolver.lockfile-path, which puts the lock where this check does not look.
var errLockfileMoved = errors.New("a resolver.lockfile-path may move it")

// readCargoWorkspace asks `cargo metadata --no-deps`, which reads manifests only, for the workspace root and its members.
func readCargoWorkspace(ctx context.Context, args []string) (cargoWorkspace, error) {
	verb := verbIndex("cargo", args)
	if verb < 0 {
		return cargoWorkspace{}, errors.New("no cargo command")
	}
	// The options before the verb, rustup's +toolchain included, pick the same workspace and configuration.
	cmdArgs := append(slices.Clone(args[:verb]), "metadata", "--no-deps", "--format-version", "1")
	cmdArgs = append(cmdArgs, cargoWorkspaceFlags(args[verb+1:])...)
	path, err := shim.LookPathReal("cargo")
	if err != nil {
		return cargoWorkspace{}, err
	}
	cmd := exec.CommandContext(ctx, path, cmdArgs...)
	cmd.Env = envWithoutMonitorID()
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
		ConfigDir: cargoConfigDir(args[:verb]),
	}
	for _, p := range meta.Packages {
		if p.ManifestPath != "" && !slices.Contains(ws.Manifests, p.ManifestPath) {
			ws.Manifests = append(ws.Manifests, p.ManifestPath)
		}
	}
	if lockfileMoved(args, ws.ConfigDir) {
		return cargoWorkspace{}, errLockfileMoved
	}
	return ws, nil
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

// cargoConfigDir is where cargo starts reading configuration: -C's directory, else the working directory, symlinks resolved as the kernel does.
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
			v = filepath.Join(dir, v)
		}
		dir = v
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real
	}
	return dir
}

// lockfileMoved reports a resolver.lockfile-path cargo may read: from the environment, the command line, or a config file or one it includes.
func lockfileMoved(args []string, configDir string) bool {
	if os.Getenv("CARGO_RESOLVER_LOCKFILE_PATH") != "" {
		return true
	}
	for _, a := range args {
		if strings.Contains(a, "lockfile-path") {
			return true
		}
	}
	// A quoted key may spell it with escapes, and a config the bounded parser refuses may set it too.
	moves := func(data []byte) bool {
		doc, ok := cargoConfigDoc(data)
		resolver, _ := doc["resolver"].(map[string]any)
		return !ok || bytes.Contains(data, []byte("lockfile-path")) || resolver["lockfile-path"] != nil || doc["include"] != nil
	}
	for _, c := range cargoConfigArgs(args) {
		if data, ok := cargoConfigArg(c); ok && moves(data) {
			return true
		}
	}
	files := cargoConfigFiles(configDir)
	if home := cargoHome(); home != "" {
		files = append(files, cargoConfigFile(home))
	}
	for _, f := range files {
		if data, ok := readRegular(f); ok && moves(data) {
			return true
		}
	}
	return false
}

// cargoDefaultRegistry is the registry other than crates.io that `cargo install` takes a crate from when the line names none, or "".
func cargoDefaultRegistry(args []string) string {
	// The value set nearest the line wins; an include, or a config the bounded parser refuses, may set it too.
	pick := func(data []byte) (string, bool) {
		doc, ok := cargoConfigDoc(data)
		if !ok {
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
	for _, c := range slices.Backward(cargoConfigArgs(args)) {
		if data, ok := cargoConfigArg(c); ok {
			if v, ok := pick(data); ok {
				return found(v)
			}
		}
	}
	if v := os.Getenv("CARGO_REGISTRY_DEFAULT"); v != "" {
		return found(v)
	}
	home := cargoHome()
	if home == "" {
		return ""
	}
	// cargo install reads no project config, only those from CARGO_HOME up.
	for _, f := range append(cargoConfigFiles(home), cargoConfigFile(home)) {
		if data, ok := readRegular(f); ok {
			if v, ok := pick(data); ok {
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

// cargoConfigArg is what cargo reads for a --config value: the file it names when that exists, else the value as TOML.
func cargoConfigArg(c string) ([]byte, bool) {
	if c != "" && exists(c) {
		return readRegular(c)
	}
	return []byte(c), true
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

// cargoHome is CARGO_HOME, else ~/.cargo, else "".
func cargoHome() string {
	if home := os.Getenv("CARGO_HOME"); home != "" {
		return home
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".cargo")
	}
	return ""
}

// readRegular reads p only when it is a regular file, since a FIFO may never end, and stops one byte past the bounded parser's limit.
func readRegular(p string) ([]byte, bool) {
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, catalog.CargoManifestLimit+1))
	return data, err == nil
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
}

// stateOf saves p as it stands now.
func stateOf(p string) savedFile {
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return savedFile{path: p}
	}
	if err != nil || !fi.Mode().IsRegular() {
		return savedFile{path: p, existed: true, unread: true}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return savedFile{path: p, existed: true, unread: true}
	}
	return savedFile{path: p, existed: true, data: data, mode: fi.Mode().Perm()}
}

// is reports whether f and g hold the same state; an unread one matches nothing.
func (f savedFile) is(g savedFile) bool {
	return !f.unread && !g.unread && f.existed == g.existed && bytes.Equal(f.data, g.data)
}

// snapshot saves each file, or that it did not exist; one it cannot read is left out, and so never touched.
func snapshot(paths []string) []savedFile {
	var out []savedFile
	for _, p := range paths {
		if f := stateOf(p); !f.unread {
			out = append(out, f)
		}
	}
	return out
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

// reportRestore undoes each change still as the command left it, leaves alone one changed again since, and says so.
func reportRestore(command string, changes []fileChange) {
	var done, kept []string
	for _, c := range changes {
		f, now := c.before, stateOf(c.before.path)
		switch {
		case f.is(now):
			continue
		case !c.after.is(now):
			kept = append(kept, displayPath(f.path))
		case !f.existed:
			if err := os.Remove(f.path); err != nil {
				fmt.Fprintf(errOut, "ossprey: warning: could not remove %s (%v)\n", displayPath(f.path), err)
				continue
			}
			done = append(done, "removed "+displayPath(f.path))
		default:
			if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
				fmt.Fprintf(errOut, "ossprey: warning: could not restore %s (%v)\n", displayPath(f.path), err)
				continue
			}
			_ = os.Chmod(f.path, f.mode)
			done = append(done, "restored "+displayPath(f.path))
		}
	}
	if len(done) > 0 {
		fmt.Fprintf(errOut, "ossprey: undid `%s`: %s\n", command, strings.Join(done, ", "))
	}
	if len(kept) > 0 {
		fmt.Fprintf(errOut, "ossprey: warning: did not undo `%s` in %s, changed again after cargo exited\n", command, strings.Join(kept, ", "))
	}
	if len(done) == 0 && len(kept) == 0 {
		fmt.Fprintf(errOut, "ossprey: `%s` changed no Cargo.toml or Cargo.lock; nothing to restore\n", command)
	}
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
		case !strings.HasPrefix(rel, ".."):
			return rel
		case best == p:
			best = rel
		}
	}
	return best
}
