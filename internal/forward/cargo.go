package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/check"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/progress"
	"github.com/ossprey/ossprey-cli/internal/registry"
	"github.com/ossprey/ossprey-cli/internal/scan"
	"github.com/ossprey/ossprey-cli/internal/severity"
	"github.com/ossprey/ossprey-cli/internal/shim"
)

// cargoWorkspaceFn finds the files a cargo command may rewrite; a test seam.
var cargoWorkspaceFn = readCargoWorkspace

// cargoRunFirstAt matches the cargo verbs that resolve and lock but build nothing, unless asked for --help.
func cargoRunFirstAt(args []string) (int, bool) {
	start, ok := verbAt("cargo", "add", "update", "generate-lockfile", "fetch")(args)
	if !ok || cargoHas(args[start:], "-h", "--help") {
		return 0, false
	}
	return start, true
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

// cargoSourceFlags install every crate named from somewhere other than crates.io.
var cargoSourceFlags = flagSet("--git", "--path", "--index", "--registry")

// parseCargoInstall classifies `cargo install`'s arguments: each positional is a crate, --version pins them all, and a source flag takes them off crates.io.
func parseCargoInstall(args []string) installArgs {
	var crates []string
	version, source := "", ""
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
		if !inline && valueFlags["cargo"][flag] && i+1 < len(args) {
			value = args[i+1]
			i++
		}
		switch {
		case flag == "--version" || flag == "--vers":
			version = value
		case cargoSourceFlags[flag]:
			source = flag + " " + value
		}
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
		if err := execFn(ctx, m.Bin, opts.Args); err != nil {
			return err
		}
		stop := progress.Submit(progressTo(), 0)
		ws, err := cargoWorkspaceFn(ctx, opts.Args)
		var sbom *ossbom.SBOM
		if err == nil {
			sbom, err = scanCargoLock(ctx, opts, ws, true)
		}
		stop()
		flushWarnings(ctx)
		reportPassive(opts, sbom, err)
		return nil
	}

	ws, err := cargoWorkspaceFn(ctx, opts.Args)
	var saved []savedFile
	if err == nil {
		saved = snapshot(ws.files())
	}
	flushWarnings(ctx)
	if runErr := execFn(ctx, m.Bin, opts.Args); runErr != nil {
		return runErr // cargo's own exit code, unscanned
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
		return nil
	}

	summary, hasMalware := scan.MalwareReports(sbom, severity.ParseFloor(sbom.FailingSeverityFloor))
	for _, msg := range summary.Informational {
		note("ossprey: %s\n", msg)
	}
	lock := displayPath(ws.Lock)
	if hasMalware {
		printBlock(m, opts, summary)
		reportRestore(command, saved)
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
	return nil
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
var errLockfileMoved = errors.New("resolver.lockfile-path moves it")

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
		case strings.HasPrefix(a, "-m") || strings.HasPrefix(a, "-Z"):
			name, value = a[:2], strings.TrimPrefix(a[2:], "=")
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
	for i := 0; i < len(globals); i++ {
		a := globals[i]
		var v string
		switch {
		case a == "-C" && i+1 < len(globals):
			v = globals[i+1]
			i++
		case strings.HasPrefix(a, "-C") && len(a) > 2:
			v = strings.TrimPrefix(a[2:], "=")
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

// lockfileMoved reports a resolver.lockfile-path cargo may read: from the environment, the command line, or a config file.
func lockfileMoved(args []string, configDir string) bool {
	if os.Getenv("CARGO_RESOLVER_LOCKFILE_PATH") != "" {
		return true
	}
	var files []string
	for i, a := range args {
		if strings.Contains(a, "lockfile-path") {
			return true
		}
		if a == "--config" && i+1 < len(args) {
			files = append(files, args[i+1])
		} else if v, ok := strings.CutPrefix(a, "--config="); ok {
			files = append(files, v)
		}
	}
	for d := configDir; ; d = filepath.Dir(d) {
		files = append(files, filepath.Join(d, ".cargo", "config.toml"), filepath.Join(d, ".cargo", "config"))
		if filepath.Dir(d) == d {
			break
		}
	}
	home := os.Getenv("CARGO_HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".cargo")
		}
	}
	if home != "" {
		files = append(files, filepath.Join(home, "config.toml"), filepath.Join(home, "config"))
	}
	for _, f := range files {
		// Only a regular file is read: a FIFO may never end.
		if fi, err := os.Stat(f); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if data, err := os.ReadFile(f); err == nil && bytes.Contains(data, []byte("lockfile-path")) {
			return true
		}
	}
	return false
}

// savedFile is a manifest or lock as it was before cargo ran.
type savedFile struct {
	path    string
	existed bool
	data    []byte
	mode    fs.FileMode
}

// snapshot saves each file, or that it did not exist; one it cannot read is left out, and so never touched.
func snapshot(paths []string) []savedFile {
	var out []savedFile
	for _, p := range paths {
		fi, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			out = append(out, savedFile{path: p})
			continue
		}
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		out = append(out, savedFile{path: p, existed: true, data: data, mode: fi.Mode().Perm()})
	}
	return out
}

// reportRestore puts back every saved file the command changed, removes those it created, and says so.
func reportRestore(command string, saved []savedFile) {
	var done []string
	for _, f := range saved {
		now, err := os.ReadFile(f.path)
		switch {
		case !f.existed && errors.Is(err, fs.ErrNotExist):
			continue
		case !f.existed:
			if err := os.Remove(f.path); err != nil {
				fmt.Fprintf(errOut, "ossprey: warning: could not remove %s (%v)\n", displayPath(f.path), err)
				continue
			}
			done = append(done, "removed "+displayPath(f.path))
		case err == nil && bytes.Equal(now, f.data):
			continue
		default:
			if err := os.WriteFile(f.path, f.data, f.mode); err != nil {
				fmt.Fprintf(errOut, "ossprey: warning: could not restore %s (%v)\n", displayPath(f.path), err)
				continue
			}
			_ = os.Chmod(f.path, f.mode)
			done = append(done, "restored "+displayPath(f.path))
		}
	}
	if len(done) == 0 {
		fmt.Fprintf(errOut, "ossprey: `%s` changed no Cargo.toml or Cargo.lock; nothing to restore\n", command)
		return
	}
	fmt.Fprintf(errOut, "ossprey: undid `%s`: %s\n", command, strings.Join(done, ", "))
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
