package shim

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Profile is a shell startup file ossprey manages a PATH block in.
type Profile struct {
	Path string
	Fish bool // fish syntax rather than POSIX
}

// Profiles returns the startup files to write the PATH block into, for a given
// home directory.
//
// Several files, not one, because no single file covers the ways a package
// manager gets invoked: ~/.profile is read by login shells and by most
// dev-container / desktop-session setups, ~/.bashrc by interactive bash,
// ~/.zshrc by interactive zsh (which never reads ~/.profile). A file is
// included when it already exists, or when its shell is installed and the file
// is one we are willing to create.
func Profiles(home string) []Profile {
	type candidate struct {
		rel     string
		shell   string // create the file if this shell is installed ("" = never create)
		fish    bool
		always  bool
		mkdirAt string
	}
	candidates := []candidate{
		{rel: ".profile", always: true},
		{rel: ".bashrc", shell: "bash"},
		{rel: ".bash_profile"},
		{rel: ".zshrc", shell: "zsh"},
		{rel: ".zprofile"},
		{rel: filepath.Join(".config", "fish", "config.fish"), shell: "fish", fish: true, mkdirAt: filepath.Join(".config", "fish")},
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

// HasBlock reports whether path already carries the managed ossprey block.
func HasBlock(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), blockStart)
}

// hasBlockFor reports whether path already carries a managed block pointing at
// dir — i.e. whether WriteBlock would be a no-op.
func hasBlockFor(path, dir string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, blockStart) && strings.Contains(s, dir)
}

// WriteBlock makes p contain exactly one managed block pointing at dir,
// creating the file if needed. It reports whether the file changed, so install
// can stay quiet about profiles that were already correct.
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

// RemoveBlock deletes the managed block from p, leaving everything else — and
// the file itself — alone. Reports whether the file changed.
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

// block renders the managed region. The PATH edit is idempotent in the shell
// too: sourcing a profile twice (tmux, `exec zsh`, nested shells) must not stack
// duplicate entries.
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

// stripBlock removes every managed block from content, including a block whose
// end marker is missing (a half-deleted edit should not make us give up).
func stripBlock(content string) string {
	for {
		start := strings.Index(content, blockStart)
		if start < 0 {
			return content
		}
		// Trim the newline before the block so repeated install/uninstall cycles
		// do not accumulate blank lines.
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

// writeFilePreservingMode writes data to path, keeping the existing file mode
// when there is one — a profile a user has chmod'ed 600 stays 600.
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

// fishQuote renders s as a single-quoted fish word. fish escapes with a
// backslash inside single quotes, unlike POSIX shells.
func fishQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}
