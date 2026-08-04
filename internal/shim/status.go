package shim

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Status is a snapshot of the shim installation, built to answer the question a
// developer actually asks: "is `npm` going through ossprey right now, and if
// not, why not?"
type Status struct {
	Dir       string
	DirExists bool
	// OnPath reports whether Dir is on the PATH of the process asking. False
	// with shims installed usually means "you have not opened a new shell yet".
	OnPath bool
	// Binary is the ossprey executable the installed shims call, and BinaryOK
	// whether it still exists.
	Binary   string
	BinaryOK bool
	// Bypass reports that BypassEnv is set, which disables every shim.
	Bypass   bool
	Managers []ManagerStatus
	Profiles []ProfileStatus
}

// ManagerStatus is the per-command view: what we installed, what the shell
// actually resolves today, and whether those agree.
type ManagerStatus struct {
	Name     string
	Shim     string // shim path, "" if not installed
	Resolves string // what this command resolves to on the current PATH
	Real     string // the genuine manager, ignoring shims
	// Active means the command currently goes through ossprey.
	Active bool
}

// ProfileStatus is one shell startup file and whether it carries the PATH block.
type ProfileStatus struct {
	Path    string
	Managed bool
}

// Load inspects the filesystem and the current PATH. It never writes.
func Load(o Options) (*Status, error) {
	dir := o.Dir
	if dir == "" {
		d, err := Dir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	st := &Status{Dir: dir, OnPath: onPath(dir), Bypass: os.Getenv(BypassEnv) != ""}
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		st.DirExists = true
	}

	for _, name := range DefaultManagers() {
		m := ManagerStatus{Name: name}
		shimPath := filepath.Join(dir, scriptName(name))
		if IsShim(shimPath) {
			m.Shim = shimPath
			if st.Binary == "" {
				st.Binary = ShimBinary(shimPath)
			}
		}
		if p, err := exec.LookPath(name); err == nil {
			m.Resolves = p
		}
		if p, err := LookPathReal(name); err == nil {
			m.Real = p
		}
		// Active is decided by what the command actually resolves to, not by what
		// we installed: a second shim directory, a wrapper, or a PATH entry that
		// wins over ours all show up here as "installed but not active".
		m.Active = m.Resolves != "" && IsShim(m.Resolves)
		st.Managers = append(st.Managers, m)
	}

	if st.Binary != "" {
		if err := executable(st.Binary); err == nil {
			st.BinaryOK = true
		}
	}

	home, err := homeDir(o)
	if err != nil {
		return st, nil // profiles are a nice-to-have; the rest of the status stands
	}
	for _, p := range Profiles(home) {
		st.Profiles = append(st.Profiles, ProfileStatus{Path: p.Path, Managed: HasBlock(p.Path)})
	}
	return st, nil
}

// Installed reports whether any shim is present.
func (s *Status) Installed() bool {
	for _, m := range s.Managers {
		if m.Shim != "" {
			return true
		}
	}
	return false
}
