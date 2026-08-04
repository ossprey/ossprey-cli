package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LookPathReal resolves bin the way exec.LookPath would, except that it skips
// ossprey shims. It is what stands between `npm` (the shim) → `ossprey npm` →
// `npm` (the shim again) and an infinite fork bomb.
//
// The shim scripts already strip their own directory from PATH before exec'ing
// ossprey, so in the normal case this changes nothing. It matters when that
// stripping does not bite: the directory reached through a symlink or a
// differently-spelled path, a wrapper that re-prepends PATH, a shim copied
// somewhere else by hand. Cheap insurance against the one bug in this feature
// that would render a developer's machine unusable.
func LookPathReal(bin string) (string, error) {
	if strings.ContainsRune(bin, filepath.Separator) || (runtime.GOOS == "windows" && strings.ContainsRune(bin, '/')) {
		if err := executable(bin); err != nil {
			return "", err
		}
		return bin, nil
	}

	var skipped []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			dir = "." // POSIX: an empty PATH entry means the working directory.
		}
		for _, cand := range candidates(filepath.Join(dir, bin)) {
			if executable(cand) != nil {
				continue
			}
			if IsShim(cand) {
				skipped = append(skipped, cand)
				continue
			}
			return cand, nil
		}
	}

	if len(skipped) > 0 {
		return "", fmt.Errorf("%s resolves only to ossprey shims (%s) — the real %s is not on PATH; "+
			"run `ossprey shim status` or `ossprey shim uninstall`", bin, strings.Join(skipped, ", "), bin)
	}
	return "", fmt.Errorf("%s not found on PATH", bin)
}

// candidates expands a path to the names the OS would actually try. On Windows
// a bare `npm` is really `npm.cmd`/`npm.exe`, chosen via PATHEXT.
func candidates(path string) []string {
	if runtime.GOOS != "windows" {
		return []string{path}
	}
	// An extension already spelled out is used as-is.
	if ext := filepath.Ext(path); ext != "" {
		for _, e := range pathExts() {
			if strings.EqualFold(ext, e) {
				return []string{path}
			}
		}
	}
	exts := pathExts()
	out := make([]string, 0, len(exts))
	for _, e := range exts {
		out = append(out, path+e)
	}
	return out
}

func pathExts() []string {
	raw := os.Getenv("PATHEXT")
	if raw == "" {
		raw = ".COM;.EXE;.BAT;.CMD"
	}
	var out []string
	for _, e := range strings.Split(raw, ";") {
		if e = strings.TrimSpace(e); e != "" {
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			out = append(out, strings.ToLower(e))
		}
	}
	return out
}

// executable reports whether path is a runnable file.
func executable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if runtime.GOOS == "windows" {
		return nil // Windows decides by extension, handled in candidates.
	}
	if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}
