// Package hook installs the plain-git-hook flavour of the pre-commit malware
// check: a marker-carrying POSIX sh script at .git/hooks/pre-commit (or
// wherever core.hooksPath points) that execs `ossprey precommit`.
//
// It follows the same conventions as internal/shim:
//
//   - Fail open: the script warns and exits 0 when the ossprey binary is
//     missing — a hook that can break `git commit` gets ripped out.
//   - Only our files: install refuses to overwrite a hook that does not carry
//     our marker, and uninstall removes only marker-carrying hooks.
//
// Unlike the shims this is per-repository state, so everything takes the
// repository directory rather than a global config dir.
package hook

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Marker identifies a hook script written by ossprey. Same convention as
// shim.Marker: any file whose head carries it is ours to overwrite or delete,
// any file without it is somebody else's and is never touched.
const Marker = "OSSPREY-PRECOMMIT-HOOK-V1"

// hookName is the git hook this package manages.
const hookName = "pre-commit"

// Script is the hook body. POSIX sh — git for Windows runs hooks under its
// bundled sh, so one script covers every platform. It fails open when the
// ossprey binary is missing, mirroring the PATH shims.
const Script = `#!/bin/sh
# ` + Marker + `
# Installed by 'ossprey precommit install'; remove with 'ossprey precommit uninstall'.
# Checks staged dependency changes against Ossprey's known-malware list.
if command -v ossprey >/dev/null 2>&1; then
    exec ossprey precommit "$@"
fi
echo "ossprey: binary not found on PATH; skipping pre-commit malware check" >&2
exit 0
`

// State describes what currently occupies the repo's pre-commit hook slot.
type State int

const (
	// NotInstalled: no pre-commit hook file exists.
	NotInstalled State = iota
	// Installed: the hook file exists and carries our marker.
	Installed
	// Foreign: a hook file exists but was not written by ossprey.
	Foreign
)

// Status reports where the hook lives and what is there.
type Status struct {
	// HooksDir is the resolved hooks directory (respects core.hooksPath).
	HooksDir string
	// Path is HooksDir/pre-commit.
	Path  string
	State State
}

// Load resolves the hook location for the repo at repoDir and inspects it.
func Load(repoDir string) (Status, error) {
	dir, err := hooksDir(repoDir)
	if err != nil {
		return Status{}, err
	}
	st := Status{HooksDir: dir, Path: filepath.Join(dir, hookName)}
	head, err := readHead(st.Path)
	switch {
	case err != nil:
		st.State = NotInstalled
	case bytes.Contains(head, []byte(Marker)):
		st.State = Installed
	default:
		st.State = Foreign
	}
	return st, nil
}

// Install writes the hook script for the repo at repoDir. Re-running over an
// ossprey-installed hook refreshes it; a foreign hook is never overwritten —
// the caller is told to chain manually or use the pre-commit framework.
func Install(repoDir string) (Status, error) {
	st, err := Load(repoDir)
	if err != nil {
		return Status{}, err
	}
	if st.State == Foreign {
		return st, fmt.Errorf(
			"a pre-commit hook already exists at %s and was not written by ossprey; refusing to overwrite it.\n"+
				"Either add `ossprey precommit` to that hook yourself, or manage both with the pre-commit framework\n"+
				"(https://pre-commit.com) using this repo's published hook id `ossprey`", st.Path)
	}
	// core.hooksPath may point at a directory that does not exist yet.
	if err := os.MkdirAll(st.HooksDir, 0o755); err != nil {
		return st, fmt.Errorf("create hooks directory %s: %w", st.HooksDir, err)
	}
	if err := os.WriteFile(st.Path, []byte(Script), 0o755); err != nil {
		return st, fmt.Errorf("write %s: %w", st.Path, err)
	}
	// WriteFile only applies the mode on create; refresh must keep it exec.
	if err := os.Chmod(st.Path, 0o755); err != nil {
		return st, fmt.Errorf("chmod %s: %w", st.Path, err)
	}
	st.State = Installed
	return st, nil
}

// Uninstall removes the hook if — and only if — it carries our marker.
// A missing hook is not an error (uninstall is idempotent); a foreign hook is.
func Uninstall(repoDir string) (Status, error) {
	st, err := Load(repoDir)
	if err != nil {
		return Status{}, err
	}
	switch st.State {
	case NotInstalled:
		return st, nil
	case Foreign:
		return st, fmt.Errorf("the pre-commit hook at %s was not written by ossprey; leaving it alone", st.Path)
	}
	if err := os.Remove(st.Path); err != nil {
		return st, fmt.Errorf("remove %s: %w", st.Path, err)
	}
	st.State = NotInstalled
	return st, nil
}

// hooksDir resolves the repo's hooks directory via git itself, so
// core.hooksPath (local, global, or system) is honoured exactly as git would.
func hooksDir(repoDir string) (string, error) {
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", "--git-path", "hooks")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("not a git repository (or git missing): %s", strings.TrimSpace(stderr.String()))
	}
	dir := strings.TrimSpace(stdout.String())
	if dir == "" {
		return "", fmt.Errorf("git reported an empty hooks path for %s", repoDir)
	}
	// --git-path output is relative to the directory git ran in (repoDir)
	// unless core.hooksPath is absolute.
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(repoDir, dir)
	}
	// Absolute paths in messages ("Installed pre-commit hook: …") beat a bare
	// ".git/hooks/pre-commit" when repoDir is ".".
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Clean(dir), nil
}

// readHead returns up to the first 2 KiB of the file — enough to find the
// marker without reading an arbitrarily large foreign hook.
func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 2048))
}
