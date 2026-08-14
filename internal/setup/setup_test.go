package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteWorkflow_CreatesFile(t *testing.T) {
	dir := t.TempDir()

	path, created, err := WriteWorkflow(dir, "main")
	if err != nil {
		t.Fatalf("WriteWorkflow: %v", err)
	}
	if !created {
		t.Fatal("want created=true")
	}
	if want := filepath.Join(dir, ".github", "workflows", "ossprey.yml"); path != want {
		t.Errorf("path: got %q, want %q", path, want)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"branches: [main]",
		"secrets.OSSPREY_API_KEY",
		"ossprey scan .",
		"install.sh",
	} {
		if !strings.Contains(string(content), want) {
			t.Errorf("workflow missing %q", want)
		}
	}
}

func TestWriteWorkflow_DoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".github", "workflows", "ossprey.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("custom"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, created, err := WriteWorkflow(dir, "main")
	if err != nil {
		t.Fatalf("WriteWorkflow: %v", err)
	}
	if created {
		t.Fatal("want created=false for existing file")
	}
	content, _ := os.ReadFile(path)
	if string(content) != "custom" {
		t.Errorf("existing workflow was modified: %q", content)
	}
}

func TestWriteWorkflow_UsesBranch(t *testing.T) {
	dir := t.TempDir()
	path, _, err := WriteWorkflow(dir, "master")
	if err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if !strings.Contains(string(content), "branches: [master]") {
		t.Errorf("workflow missing master branch: %s", content)
	}
}

func TestGenerateKeyName(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		name := GenerateKeyName()
		if len(name) > 20 {
			t.Errorf("name %q longer than 20 chars", name)
		}
		if strings.ContainsAny(name, " \t\n") {
			t.Errorf("name %q contains whitespace", name)
		}
		if !strings.HasPrefix(name, "ci-") {
			t.Errorf("name %q missing ci- prefix", name)
		}
		if seen[name] {
			t.Errorf("duplicate name %q", name)
		}
		seen[name] = true
	}
}

func TestDefaultBranch_NoRepo(t *testing.T) {
	if got := DefaultBranch(t.TempDir()); got != "main" {
		t.Errorf("DefaultBranch outside a repo: got %q, want main", got)
	}
}

func TestDefaultBranch_CurrentBranch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "--initial-branch=trunk"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v (%s)", args, err, out)
		}
	}
	if got := DefaultBranch(dir); got != "trunk" {
		t.Errorf("DefaultBranch: got %q, want trunk", got)
	}
}
