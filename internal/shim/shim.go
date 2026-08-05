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
	Marker = "OSSPREY-SHIM-V1"

	BypassEnv = "OSSPREY_SHIM_BYPASS"

	DirEnv = "OSSPREY_SHIM_DIR"

	binPrefix = "ossprey-bin: "

	blockStart = "# >>> ossprey shims >>>"
	blockEnd   = "# <<< ossprey shims <<<"
)

var defaultManagers = []string{"npm", "pnpm", "yarn", "pip", "pip3", "poetry", "uv"}

func DefaultManagers() []string {
	return slices.Clone(defaultManagers)
}

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

func IsShim(path string) bool {
	head, err := readHead(path)
	if err != nil {
		return false
	}
	return bytes.Contains(head, []byte(Marker))
}

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

func scriptName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".cmd"
	}
	return name
}
