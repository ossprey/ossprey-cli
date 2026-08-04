package shim

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteBlockPreservesUserContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".zshrc")
	original := "export EDITOR=vim\nalias g=git\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	p := Profile{Path: path}
	if changed, err := WriteBlock(p, "/opt/shims"); err != nil || !changed {
		t.Fatalf("WriteBlock = %v, %v; want changed", changed, err)
	}

	body := read(t, path)
	if !strings.HasPrefix(body, original) {
		t.Fatalf("user content was disturbed:\n%s", body)
	}
	if !strings.Contains(body, "/opt/shims") {
		t.Fatalf("PATH entry missing:\n%s", body)
	}
	// Windows has no POSIX permission bits — Go models only the read-only flag,
	// so a 0600 file reads back as 0666 there. The guarantee is a POSIX one.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("file mode changed to %v (%v); a 600 profile must stay 600", fi.Mode().Perm(), err)
		}
	}

	if changed, err := WriteBlock(p, "/opt/shims"); err != nil || changed {
		t.Fatalf("second WriteBlock = %v, %v; want unchanged", changed, err)
	}

	if changed, err := RemoveBlock(p); err != nil || !changed {
		t.Fatalf("RemoveBlock = %v, %v; want changed", changed, err)
	}
	if got := read(t, path); got != original {
		t.Fatalf("uninstall did not restore the file:\nwant %q\ngot  %q", original, got)
	}
}

// A user who edits the block by hand can leave it without its end marker. We
// must still be able to take it out rather than stacking a second copy.
func TestWriteBlockRepairsTruncatedBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".bashrc")
	if err := os.WriteFile(path, []byte("keep me\n"+blockStart+"\nPATH=/old:$PATH\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteBlock(Profile{Path: path}, "/new/shims"); err != nil {
		t.Fatal(err)
	}
	body := read(t, path)
	if n := strings.Count(body, blockStart); n != 1 {
		t.Fatalf("%d managed blocks, want 1:\n%s", n, body)
	}
	if strings.Contains(body, "/old") || !strings.Contains(body, "/new/shims") {
		t.Fatalf("stale PATH entry survived:\n%s", body)
	}
	if !strings.HasPrefix(body, "keep me\n") {
		t.Fatalf("content before the block was lost:\n%s", body)
	}
}

func TestWriteBlockCreatesFishConfig(t *testing.T) {
	home := t.TempDir()
	p := Profile{Path: filepath.Join(home, ".config", "fish", "config.fish"), Fish: true}
	if _, err := WriteBlock(p, "/opt/shims"); err != nil {
		t.Fatal(err)
	}
	body := read(t, p.Path)
	if !strings.Contains(body, "set -gx PATH '/opt/shims' $PATH") {
		t.Fatalf("fish syntax not used:\n%s", body)
	}
	if strings.Contains(body, "case ") {
		t.Fatalf("POSIX syntax leaked into a fish config:\n%s", body)
	}
}

func TestProfilesAlwaysIncludesDotProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PATH", home) // no shells installed
	got := Profiles(home)
	if len(got) != 1 || got[0].Path != filepath.Join(home, ".profile") {
		t.Fatalf("Profiles = %v, want just ~/.profile", got)
	}

	// An existing file is picked up even when its shell is not on PATH.
	zshrc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(zshrc, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Profiles(home); len(got) != 2 || got[1].Path != zshrc {
		t.Fatalf("Profiles = %v, want ~/.profile and the existing ~/.zshrc", got)
	}
}

func TestFishQuote(t *testing.T) {
	if got := fishQuote(`/a'b\c`); got != `'/a\'b\\c'` {
		t.Fatalf("fishQuote = %s", got)
	}
}
