package shim

import (
	"os"
	"os/exec"
	"path/filepath"
)

type Status struct {
	Dir       string
	DirExists bool
	OnPath    bool
	Binary    string
	BinaryOK  bool
	Bypass    bool
	Managers  []ManagerStatus
	Profiles  []ProfileStatus
}

type ManagerStatus struct {
	Name     string
	Shim     string
	Resolves string
	Real     string
	Active   bool
}

type ProfileStatus struct {
	Path    string
	Managed bool
}

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
		return st, nil
	}
	for _, p := range Profiles(home) {
		st.Profiles = append(st.Profiles, ProfileStatus{Path: p.Path, Managed: HasBlock(p.Path)})
	}
	return st, nil
}

func (s *Status) Installed() bool {
	for _, m := range s.Managers {
		if m.Shim != "" {
			return true
		}
	}
	return false
}
