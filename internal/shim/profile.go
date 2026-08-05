package shim

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Profile struct {
	Path string
	Fish bool
}

func Profiles(home string) []Profile {
	type candidate struct {
		rel    string
		shell  string
		fish   bool
		always bool
	}
	candidates := []candidate{
		{rel: ".profile", always: true},
		{rel: ".bashrc", shell: "bash"},
		{rel: ".bash_profile"},
		{rel: ".zshrc", shell: "zsh"},
		{rel: ".zprofile"},
		{rel: filepath.Join(".config", "fish", "config.fish"), shell: "fish", fish: true},
	}

	var out []Profile
	for _, c := range candidates {
		path := filepath.Join(home, c.rel)
		_, err := os.Stat(path)
		exists := err == nil
		if !exists && !c.always && !shellInstalled(c.shell) {
			continue
		}
		out = append(out, Profile{Path: path, Fish: c.fish})
	}
	return out
}

func shellInstalled(name string) bool {
	if name == "" {
		return false
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func HasBlock(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), blockStart)
}

func hasBlockFor(path, dir string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, blockStart) && strings.Contains(s, dir)
}

func WriteBlock(p Profile, dir string) (bool, error) {
	old, err := os.ReadFile(p.Path)
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", p.Path, err)
	}

	body := stripBlock(string(old))
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	updated := body + block(p, dir)
	if updated == string(old) {
		return false, nil
	}

	if err := os.MkdirAll(filepath.Dir(p.Path), 0o755); err != nil {
		return false, fmt.Errorf("create %s: %w", filepath.Dir(p.Path), err)
	}
	if err := writeFilePreservingMode(p.Path, []byte(updated), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func RemoveBlock(p Profile) (bool, error) {
	old, err := os.ReadFile(p.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", p.Path, err)
	}
	updated := stripBlock(string(old))
	if updated == string(old) {
		return false, nil
	}
	if err := writeFilePreservingMode(p.Path, []byte(updated), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func block(p Profile, dir string) string {
	var b strings.Builder
	b.WriteString(blockStart + "\n")
	b.WriteString("# Puts the ossprey shim directory ahead of npm/pip/... on PATH, so package\n")
	b.WriteString("# installs are checked for malware first. Managed by `ossprey shim install`:\n")
	b.WriteString("# edits inside this block are overwritten. Remove with `ossprey shim uninstall`.\n")
	if p.Fish {
		q := fishQuote(dir)
		fmt.Fprintf(&b, "if not contains %s $PATH\n", q)
		fmt.Fprintf(&b, "    set -gx PATH %s $PATH\n", q)
		b.WriteString("end\n")
	} else {
		fmt.Fprintf(&b, "ossprey_shims=%s\n", shellQuote(dir))
		b.WriteString("case \":$PATH:\" in\n")
		b.WriteString("  *\":$ossprey_shims:\"*) ;;\n")
		b.WriteString("  *) PATH=\"$ossprey_shims:$PATH\" ;;\n")
		b.WriteString("esac\n")
		b.WriteString("export PATH\n")
		b.WriteString("unset ossprey_shims\n")
	}
	b.WriteString(blockEnd + "\n")
	return b.String()
}

func stripBlock(content string) string {
	for {
		start := strings.Index(content, blockStart)
		if start < 0 {
			return content
		}
		head := strings.TrimRight(content[:start], "\n")
		if head != "" {
			head += "\n"
		}

		rest := content[start:]
		end := strings.Index(rest, blockEnd)
		if end < 0 {
			content = head
			continue
		}
		tail := rest[end+len(blockEnd):]
		content = head + strings.TrimPrefix(tail, "\n")
	}
}

func writeFilePreservingMode(path string, data []byte, def os.FileMode) error {
	mode := def
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func fishQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}
