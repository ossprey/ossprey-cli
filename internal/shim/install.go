package shim

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Options configures Install and Uninstall. The zero value is the sane default
// for every field: user's shim directory, the running binary, every supported
// manager that is actually installed, shell profiles updated.
type Options struct {
	// Dir is the shim directory. Empty means Dir().
	Dir string
	// Binary is the ossprey executable the shims call. Empty means the running
	// executable.
	Binary string
	// Managers limits the shims to these commands. Empty means every supported
	// manager found on PATH (or all of them when All is set).
	Managers []string
	// All installs shims for supported managers that are not installed yet, so a
	// later `brew install pnpm` is covered without re-running install.
	All bool
	// SkipProfiles leaves shell startup files untouched. For containers and
	// CI, where PATH is set in the image or the workflow rather than a profile.
	SkipProfiles bool
	// Home overrides the home directory searched for shell profiles (test seam).
	Home string
}

// ManagerResult is the per-manager outcome of an install or uninstall.
type ManagerResult struct {
	Name string
	Path string // shim script path
	Real string // the genuine manager this shim shadows, if found
	Note string // why it was skipped, when it was
}

// Result reports what an install or uninstall did, in enough detail for the CLI
// to print something a developer can act on.
type Result struct {
	Dir      string
	Binary   string
	Done     []ManagerResult // shims written (install) or removed (uninstall)
	Skipped  []ManagerResult // managers deliberately not touched
	Profiles []string        // startup files that changed
	// OnPath reports whether Dir is on the PATH of the *current* process, i.e.
	// whether the change is already live in this shell.
	OnPath bool
	// PathHint, when non-empty, is the command a user must run themselves
	// because we could not make the PATH change for them.
	PathHint string
}

// Plan reports what Install would do, without writing anything. It backs
// `ossprey shim install --dry-run`: this command edits shell profiles and
// shadows the commands a developer's whole day runs on, so "show me first" has
// to be available.
func Plan(o Options) (*Result, error) {
	dir, bin, err := resolve(o)
	if err != nil {
		return nil, err
	}
	managers, explicit, err := managersFor(o)
	if err != nil {
		return nil, err
	}

	res := &Result{Dir: dir, Binary: bin, OnPath: onPath(dir)}
	for _, name := range managers {
		real, lookErr := LookPathReal(name)
		if lookErr != nil && !o.All && !explicit {
			res.Skipped = append(res.Skipped, ManagerResult{Name: name, Note: "not installed"})
			continue
		}
		res.Done = append(res.Done, ManagerResult{Name: name, Path: filepath.Join(dir, scriptName(name)), Real: real})
	}
	if o.SkipProfiles || runtime.GOOS == "windows" {
		return res, nil
	}
	home, err := homeDir(o)
	if err != nil {
		return res, nil
	}
	for _, p := range Profiles(home) {
		if !hasBlockFor(p.Path, dir) { // report what would change, not what we would touch
			res.Profiles = append(res.Profiles, p.Path)
		}
	}
	return res, nil
}

// Install writes the shim scripts and prepends the shim directory to PATH.
//
// It is idempotent: running it twice changes nothing the second time, and it is
// the supported way to re-point existing shims after ossprey moves.
func Install(o Options) (*Result, error) {
	res, err := Plan(o)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(res.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("create shim directory %s: %w", res.Dir, err)
	}
	for _, m := range res.Done {
		if err := writeShim(m.Path, m.Name, res.Dir, res.Binary); err != nil {
			return nil, err
		}
	}

	res.Profiles = nil
	if !o.SkipProfiles {
		profiles, hint, err := updatePath(o, res.Dir)
		if err != nil {
			return nil, err
		}
		res.Profiles, res.PathHint = profiles, hint
	}
	res.OnPath = onPath(res.Dir)
	return res, nil
}

// Uninstall removes the shims and the PATH block. It only deletes files
// carrying Marker, so anything else a user has put in the directory survives —
// deleting a directory's worth of unknown files is not ours to do.
func Uninstall(o Options) (*Result, error) {
	dir := o.Dir
	if dir == "" {
		d, err := Dir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	res := &Result{Dir: dir}

	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read shim directory %s: %w", dir, err)
	}
	var only []string
	if len(o.Managers) > 0 {
		if only, err = ValidateManagers(o.Managers); err != nil {
			return nil, err
		}
	}
	kept := 0
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() || !IsShim(path) {
			kept++
			continue
		}
		name := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if len(only) > 0 && !slices.Contains(only, name) {
			kept++
			continue
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove %s: %w", path, err)
		}
		res.Done = append(res.Done, ManagerResult{Name: name, Path: path})
	}
	if kept == 0 {
		_ = os.Remove(dir) // best effort; a non-empty dir simply stays
	}

	// A partial uninstall (`--managers npm`) must leave PATH alone: the
	// remaining shims still need the directory in front.
	if len(only) == 0 && !o.SkipProfiles {
		profiles, err := removePath(o)
		if err != nil {
			return nil, err
		}
		res.Profiles = profiles
		if runtime.GOOS == "windows" {
			if changed, err := windowsRemoveUserPath(dir); err == nil && changed {
				res.Profiles = append(res.Profiles, "Windows user PATH")
			}
		}
	}
	res.OnPath = onPath(dir)
	return res, nil
}

// writeShim writes one shim, refusing to clobber a file that is not ours.
func writeShim(path, manager, dir, bin string) error {
	if _, err := os.Stat(path); err == nil && !IsShim(path) {
		return fmt.Errorf("%s already exists and was not created by ossprey; move it aside or choose another shim directory with %s", path, DirEnv)
	}
	// Write-then-rename: a shim must never be observed half-written, because
	// the thing observing it is the shell trying to run `npm`.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(Script(manager, dir, bin)), 0o755); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

func resolve(o Options) (dir, bin string, err error) {
	dir = o.Dir
	if dir == "" {
		if dir, err = Dir(); err != nil {
			return "", "", err
		}
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return "", "", fmt.Errorf("resolve shim directory: %w", err)
	}

	bin = o.Binary
	if bin == "" {
		if bin, err = os.Executable(); err != nil {
			return "", "", fmt.Errorf("locate the ossprey binary: %w", err)
		}
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return "", "", fmt.Errorf("resolve ossprey binary path: %w", err)
	}
	if filepath.Dir(bin) == dir {
		return "", "", fmt.Errorf("the ossprey binary is inside the shim directory (%s); shims must call an ossprey outside it", dir)
	}
	return dir, bin, nil
}

// managersFor returns the managers to shim and whether the user named them
// explicitly (in which case "not installed" is not a reason to skip: they asked).
func managersFor(o Options) (names []string, explicit bool, err error) {
	if len(o.Managers) == 0 {
		return DefaultManagers(), false, nil
	}
	names, err = ValidateManagers(o.Managers)
	return names, true, err
}

func updatePath(o Options, dir string) (changed []string, hint string, err error) {
	if runtime.GOOS == "windows" {
		ok, err := windowsAddUserPath(dir)
		if err != nil || !ok {
			return nil, fmt.Sprintf(`[Environment]::SetEnvironmentVariable('Path', '%s;' + [Environment]::GetEnvironmentVariable('Path','User'), 'User')`, dir), nil
		}
		return []string{"Windows user PATH"}, "", nil
	}

	home, err := homeDir(o)
	if err != nil {
		return nil, "", err
	}
	for _, p := range Profiles(home) {
		wrote, err := WriteBlock(p, dir)
		if err != nil {
			return nil, "", err
		}
		if wrote {
			changed = append(changed, p.Path)
		}
	}
	return changed, "", nil
}

func removePath(o Options) ([]string, error) {
	home, err := homeDir(o)
	if err != nil {
		return nil, err
	}
	var changed []string
	for _, p := range Profiles(home) {
		removed, err := RemoveBlock(p)
		if err != nil {
			return nil, err
		}
		if removed {
			changed = append(changed, p.Path)
		}
	}
	return changed, nil
}

func homeDir(o Options) (string, error) {
	if o.Home != "" {
		return o.Home, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return home, nil
}

// onPath reports whether dir is on the current process's PATH.
func onPath(dir string) bool {
	for _, e := range filepath.SplitList(os.Getenv("PATH")) {
		if sameDir(e, dir) {
			return true
		}
	}
	return false
}

func sameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// windowsAddUserPath prepends dir to the persistent user PATH. It goes through
// PowerShell rather than `setx`, which silently truncates a PATH longer than
// 1024 characters — a real risk on a developer machine and an unpleasant way to
// find out we shipped this.
func windowsAddUserPath(dir string) (bool, error) {
	script := fmt.Sprintf(`$d='%s'
$p=[Environment]::GetEnvironmentVariable('Path','User')
if (($p -split ';') -contains $d) { exit 2 }
if ($p) { $p = "$d;$p" } else { $p = $d }
[Environment]::SetEnvironmentVariable('Path',$p,'User')`, dir)
	return runPowerShell(script)
}

// windowsRemoveUserPath drops dir from the persistent user PATH.
func windowsRemoveUserPath(dir string) (bool, error) {
	script := fmt.Sprintf(`$d='%s'
$p=[Environment]::GetEnvironmentVariable('Path','User')
if (-not (($p -split ';') -contains $d)) { exit 2 }
$p = (($p -split ';') | Where-Object { $_ -ne $d }) -join ';'
[Environment]::SetEnvironmentVariable('Path',$p,'User')`, dir)
	return runPowerShell(script)
}

// runPowerShell reports (changed, err). Exit code 2 means "nothing to do".
func runPowerShell(script string) (bool, error) {
	ps, err := exec.LookPath("powershell")
	if err != nil {
		return false, err
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 2 {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
