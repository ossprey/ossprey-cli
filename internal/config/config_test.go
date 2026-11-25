package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/env"
)

// isolate points the config at a fresh directory and clears the variables
// that lay over it.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	t.Setenv(env.ScanDepthEnv, "")
	t.Setenv(IgnoreEnv, "")
	return dir
}

func writeConfig(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeIgnore(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"wf", "wf"},
		{"./wf/", "wf"},
		{" wf/sub ", "wf/sub"},
		{".//wf", "wf"},
		{"**/fixtures", "**/fixtures"},
		{"docs/**/*.md", "docs/**/*.md"},
		{"*.md", "*.md"},
		{"my docs", "my docs"},
		{".github", ".github"},
		{"wf/*", "wf/*"},
	} {
		got, err := NormalizeIgnore(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("NormalizeIgnore(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	// Each of these would skip the whole project, mean something else on
	// another machine, or match nothing the user meant.
	for _, in := range []string{
		"", "  ", ".", "./", "/",
		"*", "**", "**/*", "*/**", "./**",
		"/abs/path", "C:/x", "c:x",
		`wf\sub`,
		"../sibling", "wf/../other", "wf/./x", "wf//x",
		"[", "{a,b",
	} {
		if got, err := NormalizeIgnore(in); err == nil {
			t.Errorf("NormalizeIgnore(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseDepth(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "1": 1, " 3 ": 3} {
		if got, err := ParseDepth(in); err != nil || got != want {
			t.Errorf("ParseDepth(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1", "deep", "1.5", "1abc"} {
		if _, err := ParseDepth(in); err == nil {
			t.Errorf("ParseDepth(%q): want an error", in)
		}
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	isolate(t)
	s, err := Load()
	if err != nil || !s.Empty() {
		t.Fatalf("Load = %+v, %v; want empty, nil", s, err)
	}
}

func TestSaveRoundTripsAndIsPrivate(t *testing.T) {
	dir := isolate(t)
	d := 2
	want := Settings{Scan: Scan{Depth: &d, Ignore: []string{"wf", "**/fixtures"}}}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if got.Scan.Depth == nil || *got.Scan.Depth != 2 || !slices.Equal(got.Scan.Ignore, want.Scan.Ignore) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("config.json mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	// A zero depth is a setting (the whole tree), not the absence of one.
	zero := 0
	if err := Save(Settings{Scan: Scan{Depth: &zero}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadFile(); got.Scan.Depth == nil || *got.Scan.Depth != 0 {
		t.Fatalf("depth 0 did not survive a round trip: %+v", got)
	}
}

// TestLoadLaysTheEnvironmentOverTheFile pins the precedence: the variable's
// depth replaces the file's, and its patterns add to the file's.
func TestLoadLaysTheEnvironmentOverTheFile(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `{"scan":{"depth":3,"ignore":["wf"]}}`)

	s, err := Load()
	if err != nil || s.Scan.Depth == nil || *s.Scan.Depth != 3 || !slices.Equal(s.Scan.Ignore, []string{"wf"}) {
		t.Fatalf("file only: %+v, %v", s, err)
	}

	t.Setenv(env.ScanDepthEnv, "1")
	t.Setenv(IgnoreEnv, "wf, docs/my notes\n**/fixtures")
	s, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Scan.Depth == nil || *s.Scan.Depth != 1 {
		t.Errorf("depth = %v, want the variable's 1", s.Scan.Depth)
	}
	if want := []string{"wf", "docs/my notes", "**/fixtures"}; !slices.Equal(s.Scan.Ignore, want) {
		t.Errorf("ignore = %q, want %q", s.Scan.Ignore, want)
	}
}

// TestLoadKeepsWhatItCanRead pins the safe direction: a bad entry is dropped
// with an error, and what remains still applies. Dropping a pattern scans more;
// dropping a depth leaves the default.
func TestLoadKeepsWhatItCanRead(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `{"scan":{"depth":-2,"ignore":["wf","**","../up"]}}`)
	t.Setenv(env.ScanDepthEnv, "deep")
	t.Setenv(IgnoreEnv, "/abs,fixtures")

	s, err := Load()
	if err == nil {
		t.Fatal("want an error naming the bad entries")
	}
	for _, bad := range []string{"-2", `"**"`, "../up", "deep", "/abs"} {
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("error %q does not name %s", err, bad)
		}
	}
	if s.Scan.Depth != nil {
		t.Errorf("depth = %d, want unset", *s.Scan.Depth)
	}
	if want := []string{"wf", "fixtures"}; !slices.Equal(s.Scan.Ignore, want) {
		t.Errorf("ignore = %q, want %q", s.Scan.Ignore, want)
	}
}

// TestLoadFileRejectsUnknownKeys keeps a typo, or a key a newer ossprey
// wrote, from passing as read: `config set` refuses to rewrite such a file,
// and a runtime load still applies the keys it knows.
func TestLoadFileRejectsUnknownKeys(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `{"scan":{"depth":1,"ignroe":["wf"]}}`)
	s, err := LoadFile()
	if err == nil || !strings.Contains(err.Error(), "ignroe") {
		t.Fatalf("err = %v, want one naming the unknown key", err)
	}
	if s.Scan.Depth == nil || *s.Scan.Depth != 1 {
		t.Errorf("known key lost: %+v", s)
	}
}

func TestLoadFileReportsUnparseableJSON(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `{"scan":`)
	if _, err := LoadFile(); err == nil {
		t.Fatal("want a parse error")
	}
}
