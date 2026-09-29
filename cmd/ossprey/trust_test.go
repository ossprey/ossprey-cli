package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/trust"
)

func runTrust(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newTrustCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func isolateTrust(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	t.Setenv(trust.RegistriesEnv, "")
	t.Setenv(trust.NpmScopesEnv, "")
	return dir
}

func TestTrustAddListRemove(t *testing.T) {
	isolateTrust(t)
	const reg = "https://Acme-1.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal"

	out, err := runTrust(t, "list")
	if err != nil || !strings.Contains(out, "Nothing is trusted") {
		t.Fatalf("empty list: %q, %v", out, err)
	}

	if _, err := runTrust(t, "add", "--registry", reg, "--npm-scope", "acme", "--npm-scope", "@tools"); err != nil {
		t.Fatal(err)
	}
	// Adding again is idempotent.
	if _, err := runTrust(t, "add", "--npm-scope", "@acme"); err != nil {
		t.Fatal(err)
	}
	stored, err := trust.LoadFile()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Registries) != 1 || stored.Registries[0] != "https://acme-1.d.codeartifact.eu-west-1.amazonaws.com/pypi/internal/" {
		t.Errorf("registries = %v", stored.Registries)
	}
	if strings.Join(stored.NpmScopes, " ") != "@acme @tools" {
		t.Errorf("scopes = %v", stored.NpmScopes)
	}

	t.Setenv(trust.NpmScopesEnv, "@from-env")
	out, err = runTrust(t, "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pypi/internal/", "@acme", "@from-env  (from " + trust.NpmScopesEnv + ")"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}

	if _, err := runTrust(t, "remove", "--npm-scope", "@tools", "--registry", reg); err != nil {
		t.Fatal(err)
	}
	stored, _ = trust.LoadFile()
	if len(stored.Registries) != 0 || strings.Join(stored.NpmScopes, " ") != "@acme" {
		t.Errorf("after remove: %+v", stored)
	}
	if _, err := runTrust(t, "remove", "--npm-scope", "@from-env"); err == nil {
		t.Error("removing an entry that only the environment sets should fail")
	}
}

func TestTrustAddRefusesBadInput(t *testing.T) {
	dir := isolateTrust(t)
	for _, args := range [][]string{
		{"add"},
		{"add", "--registry", "registry.example.com"},
		{"add", "--registry", "https://user:token@registry.example.com/"},
		{"add", "--npm-scope", "@bad scope"},
	} {
		if _, err := runTrust(t, args...); err == nil {
			t.Errorf("%v: want an error", args)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "trust.json")); !os.IsNotExist(err) {
		t.Error("a refused add must not write the file")
	}
}

// Writing back only what parsed would silently delete the rest of a file the
// user hand-edited, so a broken file is refused rather than overwritten.
func TestTrustAddDoesNotOverwriteAnUnreadableFile(t *testing.T) {
	dir := isolateTrust(t)
	path := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(path, []byte(`{"npm_scopes": ["@acme", "@bad scope"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runTrust(t, "add", "--npm-scope", "@new"); err == nil {
		t.Fatal("want an error")
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "@bad scope") {
		t.Errorf("file was rewritten: %s", data)
	}
}

func TestLoadTrustWarnsAndKeepsGoing(t *testing.T) {
	dir := isolateTrust(t)
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if p := loadTrust(&w); !p.Empty() {
		t.Errorf("policy = %+v, want empty", p)
	}
	if !strings.Contains(w.String(), "their packages are checked") {
		t.Errorf("warning = %q", w.String())
	}
}
