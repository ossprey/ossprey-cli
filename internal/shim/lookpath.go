package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

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
			dir = "."
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

func candidates(path string) []string {
	if runtime.GOOS != "windows" {
		return []string{path}
	}
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

func executable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}
