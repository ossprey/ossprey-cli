package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/config"
)

func runConfig(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newConfigCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestConfigAddListRemoveUnset(t *testing.T) {
	dir := isolateConfig(t)

	out, err := runConfig(t, "list")
	if err != nil || !strings.Contains(out, "Nothing is ignored") {
		t.Fatalf("empty list: %q, %v", out, err)
	}
	if _, err := runConfig(t, "add", "scan.ignore", "./wf/", "**/fixtures"); err != nil {
		t.Fatal(err)
	}
	// Adding a pattern twice keeps one copy.
	if _, err := runConfig(t, "add", "scan.ignore", "wf"); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored config.Settings
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stored.Scan.Ignore, ",") != "wf,**/fixtures" {
		t.Fatalf("stored %s", data)
	}

	t.Setenv(config.IgnoreEnv, "docs,wf")
	out, err = runConfig(t, "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"  wf\n", "  **/fixtures\n", "docs  (from OSSPREY_SCAN_IGNORE)", filepath.Join(dir, "config.json")} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "wf  (from") {
		t.Errorf("a pattern in both the file and the variable was listed twice:\n%s", out)
	}
	t.Setenv(config.IgnoreEnv, "")

	if _, err := runConfig(t, "remove", "scan.ignore", "wf"); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfig(t, "remove", "scan.ignore", "wf"); err == nil {
		t.Error("removing a pattern that is not there should fail")
	}
	if s, err := config.LoadFile(); err != nil || strings.Join(s.Scan.Ignore, ",") != "**/fixtures" {
		t.Fatalf("after remove: %+v, %v", s, err)
	}
	if _, err := runConfig(t, "unset", "scan.ignore"); err != nil {
		t.Fatal(err)
	}
	if s, _ := config.LoadFile(); !s.Empty() {
		t.Fatalf("after unset: %+v", s)
	}
}

func TestConfigRejectsBadInputWithoutWriting(t *testing.T) {
	dir := isolateConfig(t)
	for _, args := range [][]string{
		{"add", "scan.depth", "1"},
		{"add", "scan.ignroe", "wf"},
		{"add", "scan.ignore", "wf", "**"},
		{"add", "scan.ignore", "../outside"},
		{"remove", "scan.ignore", "/abs"},
		{"unset", "scan.depth"},
	} {
		if _, err := runConfig(t, args...); err == nil {
			t.Errorf("config %q: want an error", args)
		}
	}
	// "wf" in the refused add must not have been written beside the bad "**".
	if _, err := os.Stat(filepath.Join(dir, "config.json")); !os.IsNotExist(err) {
		t.Errorf("a refused command wrote config.json (stat err %v)", err)
	}
}

// TestConfigRefusesToRewriteAFileItCannotRead: writing back only what parsed
// would delete the rest, including a key a newer ossprey wrote.
func TestConfigRefusesToRewriteAFileItCannotRead(t *testing.T) {
	dir := isolateConfig(t)
	path := filepath.Join(dir, "config.json")
	for _, content := range []string{
		`{"scan":{"ignore":["docs"]},"future":{"x":true}}`,
		`{"scan":{"ignore":["docs"]}} {"future":{"x":true}}`,
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runConfig(t, "add", "scan.ignore", "wf"); err == nil || !strings.Contains(err.Error(), "fix or remove") {
			t.Fatalf("%s: err = %v, want a refusal", content, err)
		}
		if data, _ := os.ReadFile(path); string(data) != content {
			t.Errorf("file was rewritten: %s", data)
		}
	}
}

func TestScanIgnore(t *testing.T) {
	got, err := scanIgnore([]string{"./docs/", "wf"}, []string{"wf"})
	if err != nil || strings.Join(got, ",") != "wf,docs" {
		t.Fatalf("scanIgnore = %q, %v; want the configured pattern then the new typed one", got, err)
	}
	if _, err := scanIgnore([]string{"**"}, nil); err == nil || !strings.Contains(err.Error(), "--ignore") {
		t.Errorf("a typed pattern that skips everything: err = %v, want an --ignore error", err)
	}
}

// TestScanAppliesConfiguredAndTypedIgnores runs `scan --local` end to end:
// a pattern from config.json and one typed with --ignore both keep their
// directory's dependencies out of the SBOM.
func TestScanAppliesConfiguredAndTypedIgnores(t *testing.T) {
	isolateConfig(t)
	proj := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(proj, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Exact Cargo pins catalogue offline, with no resolver and no registry
	// lookup, and the three crates share no dependencies.
	crate := func(name, dep string) string {
		return "[package]\nname = \"" + name + "\"\nversion = \"0.1.0\"\n\n[dependencies]\n" + dep + " = \"=1.0.0\"\n"
	}
	write("Cargo.toml", crate("app", "rootcrate"))
	write("wf/a/Cargo.toml", crate("a", "wfcrate"))
	write("examples/b/Cargo.toml", crate("b", "examplecrate"))
	if _, err := runConfig(t, "add", "scan.ignore", "wf"); err != nil {
		t.Fatal(err)
	}

	sbom := func(extra ...string) string {
		t.Helper()
		var runErr error
		out := captureStdout(t, func() {
			runErr = runScan(t, proj, append([]string{"--local", "--no-version-lookup"}, extra...)...)
		})
		if runErr != nil {
			t.Fatalf("scan: %v", runErr)
		}
		return out
	}
	out := sbom()
	if !strings.Contains(out, "rootcrate") || strings.Contains(out, "wfcrate") || !strings.Contains(out, "examplecrate") {
		t.Errorf("configured ignore: want rootcrate and examplecrate, not wfcrate:\n%s", out)
	}
	out = sbom("--ignore", "examples")
	if !strings.Contains(out, "rootcrate") || strings.Contains(out, "wfcrate") || strings.Contains(out, "examplecrate") {
		t.Errorf("typed --ignore did not add to the configured pattern:\n%s", out)
	}
}
