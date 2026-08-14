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
		"branches: ['main']",
		"secrets.OSSPREY_API_KEY",
		"ossprey scan .",
		"install.sh",
		// install.sh does not create its target dir.
		`mkdir -p "$HOME/.local/bin"`,
		// Fork PRs get no secrets: they must skip, not fail red.
		"github.event.pull_request.head.repo.full_name == github.repository",
	} {
		if !strings.Contains(string(content), want) {
			t.Errorf("workflow missing %q", want)
		}
	}
	// pull_request_target as a *trigger* would hand secrets to untrusted fork
	// code. The template names it only in a cautionary comment, so match the
	// trigger form rather than the bare word.
	if strings.Contains(string(content), "pull_request_target:") {
		t.Error("workflow must not use the pull_request_target trigger")
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
	if !strings.Contains(string(content), "branches: ['master']") {
		t.Errorf("workflow missing master branch: %s", content)
	}
}

// Branch names are much more permissive than YAML: git accepts `main]`, `a#b`
// and embedded quotes, each of which would corrupt `branches: [%s]` if
// interpolated raw. The generated file must stay parseable YAML regardless.
func TestWriteWorkflow_QuotesHostileBranchNames(t *testing.T) {
	cases := []struct{ branch, want string }{
		{"main", `branches: ['main']`},
		{"main]", `branches: ['main]']`},
		{"feat#1", `branches: ['feat#1']`},
		{"a&b", `branches: ['a&b']`},
		{"it's", `branches: ['it''s']`},
		{"a,b", `branches: ['a,b']`},
		{"", `branches: ['main']`},          // empty falls back
		{"bad\nname", `branches: ['main']`}, // control chars fall back
	}
	for _, tc := range cases {
		dir := t.TempDir()
		path, _, err := WriteWorkflow(dir, tc.branch)
		if err != nil {
			t.Fatalf("branch %q: %v", tc.branch, err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(content), tc.want) {
			t.Errorf("branch %q: want %q in workflow, got:\n%s", tc.branch, tc.want, content)
		}
		// Whatever the branch name, the `on:` block must not gain extra lines.
		if strings.Count(string(content), "pull_request:") != 1 {
			t.Errorf("branch %q corrupted the workflow structure:\n%s", tc.branch, content)
		}
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

// `ossprey init` is often run from a feature branch. Pinning the workflow's
// push trigger to that branch would produce CI that never fires on a merge, so
// a conventional default branch must win over the checked-out one.
func TestDefaultBranch_PrefersMainOverCurrentBranch(t *testing.T) {
	dir := initRepo(t, "main")
	run(t, dir, "commit", "--allow-empty", "-qm", "initial")
	run(t, dir, "checkout", "-q", "-b", "feature/wip")

	if got := DefaultBranch(dir); got != "main" {
		t.Errorf("DefaultBranch on a feature branch: got %q, want main", got)
	}
}

func TestDefaultBranch_PrefersMasterOverCurrentBranch(t *testing.T) {
	dir := initRepo(t, "master")
	run(t, dir, "commit", "--allow-empty", "-qm", "initial")
	run(t, dir, "checkout", "-q", "-b", "topic")

	if got := DefaultBranch(dir); got != "master" {
		t.Errorf("DefaultBranch: got %q, want master", got)
	}
}

// With no conventional default branch present, the current branch is the best
// remaining answer.
func TestDefaultBranch_FallsBackToCurrentBranch(t *testing.T) {
	dir := initRepo(t, "develop")
	run(t, dir, "commit", "--allow-empty", "-qm", "initial")

	if got := DefaultBranch(dir); got != "develop" {
		t.Errorf("DefaultBranch: got %q, want develop", got)
	}
}

func initRepo(t *testing.T, branch string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run(t, dir, "init", "--initial-branch="+branch)
	run(t, dir, "config", "user.email", "t@example.com")
	run(t, dir, "config", "user.name", "t")
	return dir
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git %v: %v (%s)", args, err, out)
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
