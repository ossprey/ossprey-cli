// Package shim installs PATH shims that transparently route package-manager
// invocations through ossprey. With shims installed, a developer keeps typing
// `npm install left-pad` and the install is checked for malware first — no
// `ossprey` prefix to remember, no shell alias to maintain.
//
// A shell alias would not do: aliases only exist in interactive shells, so they
// miss Makefiles, CI steps, and the subprocesses coding agents spawn. A real
// executable earlier on PATH is found by execvp, so it covers all of those.
//
// A shim is a tiny script named after the manager (`npm`, `pip`, …) living in a
// directory that is prepended to PATH. It execs `ossprey <manager> "$@"`, which
// checks the install and then execs the *real* manager.
//
// Three properties make that safe:
//
//   - The shim removes its own directory from PATH before exec'ing, so the real
//     manager is what gets found downstream. That is the recursion guard.
//   - Every shim carries the Marker string. LookPathReal skips any PATH
//     candidate carrying it, so even a PATH the shim failed to strip (a symlink
//     alias, a re-prepending wrapper) cannot make ossprey exec back into itself.
//   - Shims fail open. If the ossprey binary is missing, or BypassEnv is set,
//     the shim runs the real manager unchecked rather than breaking the build.
//
// The decision of *which* subcommands get checked deliberately lives in
// internal/forward, not in the shim script: `npm run build` and `poetry run
// pytest` reach ossprey and are exec'd straight through. One allowlist, in one
// language, shared by `ossprey npm` and the shim.
//
// This package is a leaf: it deliberately does not import internal/forward
// (which imports it). An external test asserts the two manager lists agree.
package shim

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

const (
	// Marker identifies a script as an ossprey-generated shim. It is the
	// recursion guard (LookPathReal refuses to return a file containing it) and
	// the deletion guard (Uninstall only removes files containing it, so a
	// user's own script that happens to share the directory survives).
	Marker = "OSSPREY-SHIM-V1"

	// BypassEnv, when set to any non-empty value, makes every shim skip the
	// malware check and exec the real manager directly. The escape hatch for
	// "ossprey is in my way right now".
	BypassEnv = "OSSPREY_SHIM_BYPASS"

	// DirEnv overrides the shim directory (also the test seam).
	DirEnv = "OSSPREY_SHIM_DIR"

	// binPrefix tags the line in each generated shim recording which ossprey
	// binary it calls. `ossprey shim status` reads it back.
	binPrefix = "ossprey-bin: "

	// blockStart/blockEnd delimit the managed region ossprey writes into shell
	// profiles. Everything between them is owned by this package and is
	// rewritten wholesale on install and removed on uninstall.
	blockStart = "# >>> ossprey shims >>>"
	blockEnd   = "# <<< ossprey shims <<<"
)

// defaultManagers are the commands shimmed when none are named. Every entry
// must be a registered forwarder subcommand; TestDefaultManagersAreForwarders
// enforces it. Aliases (pip3) are included because a developer who types `pip3`
// expects the same protection as one who types `pip`.
var defaultManagers = []string{"npm", "pnpm", "yarn", "pip", "pip3", "poetry", "uv"}

// DefaultManagers returns the commands shimmed when none are named.
func DefaultManagers() []string {
	return slices.Clone(defaultManagers)
}

// ValidateManagers normalises a user-supplied manager list. Unknown names are
// an error listing the valid ones — a typo should never silently install
// nothing, or worse, install a shim for a command ossprey cannot forward.
func ValidateManagers(names []string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if !slices.Contains(defaultManagers, name) {
			return nil, fmt.Errorf("unknown package manager %q (supported: %s)", name, strings.Join(defaultManagers, ", "))
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no package managers named (supported: %s)", strings.Join(defaultManagers, ", "))
	}
	return out, nil
}

// Dir returns the shim directory:
//
//	$OSSPREY_SHIM_DIR                      when set (test seam / power users)
//	$OSSPREY_CONFIG_DIR/shims              when set, to stay next to credentials
//	%LOCALAPPDATA%\ossprey\shims           on Windows
//	~/.ossprey/shims                       elsewhere
//
// A dotted home directory is used rather than os.UserConfigDir because on macOS
// that resolves to "~/Library/Application Support/…", and a PATH entry
// containing spaces is a needless hazard in every shell profile we touch.
func Dir() (string, error) {
	if d := os.Getenv(DirEnv); d != "" {
		return d, nil
	}
	if d := os.Getenv("OSSPREY_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "shims"), nil
	}
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "ossprey", "shims"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".ossprey", "shims"), nil
}

// IsShim reports whether path is an ossprey-generated shim. It reads only the
// first 2 KiB: the marker is in the header of every generated script, and a
// false negative on some unrelated multi-megabyte binary is not worth the read.
//
// This is the guard that keeps `ossprey npm` from exec'ing the `npm` shim that
// invoked it, so it must stay cheap and must never report true for a real
// package manager.
func IsShim(path string) bool {
	head, err := readHead(path)
	if err != nil {
		return false
	}
	return bytes.Contains(head, []byte(Marker))
}

// ShimBinary returns the ossprey binary a generated shim calls, or "" if path
// is not a shim. It lets `ossprey shim status` say "these shims point at a
// binary that no longer exists" instead of leaving a developer to guess.
func ShimBinary(path string) string {
	head, err := readHead(path)
	if err != nil || !bytes.Contains(head, []byte(Marker)) {
		return ""
	}
	for _, line := range strings.Split(string(head), "\n") {
		if i := strings.Index(line, binPrefix); i >= 0 {
			return strings.TrimSpace(line[i+len(binPrefix):])
		}
	}
	return ""
}

func readHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 2048))
}

// scriptName is the on-disk filename for a manager. Windows resolves commands
// through PATHEXT, so the shim must be a ".cmd" to shadow the real `npm.cmd`.
func scriptName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".cmd"
	}
	return name
}
