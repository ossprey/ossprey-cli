package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// isolate points the config at a fresh directory and clears the variables
// that lay over it.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
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
		{".*", ".*"},
		{"*/*", "*/*"},
		// Selective patterns that a single sample name once refused.
		{"[0-9]*", "[0-9]*"},
		{"0*", "0*"},
		{"*0*", "*0*"},
		{"*.*", "*.*"},
		{"**/{fixtures,examples}", "**/{fixtures,examples}"},
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
		"?*", "*?", "**/*?", "**/?*", "{*,x}", "[!.]*",
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

func TestLoadMissingFileIsEmpty(t *testing.T) {
	isolate(t)
	s, err := Load()
	if err != nil || !s.Empty() {
		t.Fatalf("Load = %+v, %v; want empty, nil", s, err)
	}
}

func TestSaveRoundTripsAndIsPrivate(t *testing.T) {
	dir := isolate(t)
	want := Settings{Scan: Scan{Ignore: []string{"wf", "**/fixtures"}}}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Scan.Ignore, want.Scan.Ignore) {
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
}

// TestLoadAddsTheEnvironmentToTheFile pins that OSSPREY_SCAN_IGNORE adds to
// the stored patterns, split on commas and newlines so a pattern may hold a
// space, with a pattern in both listed once.
func TestLoadAddsTheEnvironmentToTheFile(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `{"scan":{"ignore":["wf"]}}`)
	t.Setenv(IgnoreEnv, "wf, docs/my notes\n**/fixtures,**/{gen,out}/x,[a,b]*")
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"wf", "docs/my notes", "**/fixtures", "**/{gen,out}/x", "[a,b]*"}; !slices.Equal(s.Scan.Ignore, want) {
		t.Errorf("ignore = %q, want %q", s.Scan.Ignore, want)
	}
}

// TestLoadKeepsWhatItCanRead pins the safe direction: a bad pattern is
// dropped with an error, which only means more is scanned, and the rest
// still apply.
func TestLoadKeepsWhatItCanRead(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `{"scan":{"ignore":["wf","**","../up"]}}`)
	t.Setenv(IgnoreEnv, "/abs,fixtures")
	s, err := Load()
	if err == nil {
		t.Fatal("want an error naming the bad patterns")
	}
	for _, bad := range []string{`"**"`, "../up", "/abs"} {
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("error %q does not name %s", err, bad)
		}
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
	writeConfig(t, dir, `{"scan":{"ignore":["wf"],"depth":1}}`)
	s, err := LoadFile()
	if err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("err = %v, want one naming the unknown key", err)
	}
	if !slices.Equal(s.Scan.Ignore, []string{"wf"}) {
		t.Errorf("known key lost: %+v", s)
	}
}

// TestLoadFileRejectsTrailingContent: Decode reads one value, so a second one
// after it was accepted as an editable file and deleted by the next edit. It
// is an error now, while a runtime load keeps the first value's patterns and
// trailing whitespace stays fine.
func TestLoadFileRejectsTrailingContent(t *testing.T) {
	dir := isolate(t)
	for _, tail := range []string{` {"future":{"x":true}}`, ` garbage`, `}`} {
		writeConfig(t, dir, `{"scan":{"ignore":["docs"]}}`+tail)
		s, err := LoadFile()
		if err == nil {
			t.Errorf("tail %q: want an error", tail)
		}
		if !slices.Equal(s.Scan.Ignore, []string{"docs"}) {
			t.Errorf("tail %q: runtime load kept %q, want docs", tail, s.Scan.Ignore)
		}
	}
	writeConfig(t, dir, "{\"scan\":{\"ignore\":[\"docs\"]}}\n\n  \t\n")
	if _, err := LoadFile(); err != nil {
		t.Errorf("trailing whitespace: %v", err)
	}
}

func TestLoadFileReportsUnparseableJSON(t *testing.T) {
	dir := isolate(t)
	writeConfig(t, dir, `{"scan":`)
	if _, err := LoadFile(); err == nil {
		t.Fatal("want a parse error")
	}
}
