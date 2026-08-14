package setup

import (
	"os"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The substring assertions elsewhere in this package would happily pass on a
// file YAML cannot parse, which is the exact failure a bad branch name causes:
// GitHub silently refuses to run the workflow, so the project looks scanned and
// isn't. These tests parse the generated file for real, so a regression in
// yamlQuote fails CI rather than shipping.
func TestGeneratedWorkflowParsesAsYAML(t *testing.T) {
	// Branch names git actually permits. `]`, `#`, `&`, `,` and `'` are all
	// legal in a ref name and all significant in YAML.
	branches := []string{
		"main", "master", "trunk",
		"release/v1.0",
		"main]",
		"feat#1",
		"a&b",
		"it's",
		"a,b",
		`say"hi"`,
		"back\\slash",
		"ünïcode",
	}

	for _, branch := range branches {
		t.Run(branch, func(t *testing.T) {
			dir := t.TempDir()
			path, created, err := WriteWorkflow(dir, branch)
			if err != nil || !created {
				t.Fatalf("WriteWorkflow(%q): created=%v err=%v", branch, created, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			var wf workflow
			if err := yaml.Unmarshal(data, &wf); err != nil {
				t.Fatalf("generated workflow is not valid YAML for branch %q: %v\n%s", branch, err, data)
			}

			if got := wf.On.Push.Branches; len(got) != 1 || got[0] != branch {
				t.Errorf("push branches: got %q, want exactly [%q]", got, branch)
			}
			job, ok := wf.Jobs["ossprey"]
			if !ok {
				t.Fatalf("no ossprey job; jobs=%v", wf.Jobs)
			}
			if job.If == "" {
				t.Error("job lost its fork-PR guard")
			}
			if len(job.Steps) != 3 {
				t.Errorf("want 3 steps, got %d: %+v", len(job.Steps), job.Steps)
			}
			if wf.Permissions["contents"] != "read" {
				t.Errorf("permissions: got %v, want contents: read", wf.Permissions)
			}
		})
	}
}

// The control-char and empty-string fallbacks are unreachable from
// DefaultBranch, but WriteWorkflow is exported, so a caller can still hand it
// either. Both must yield a parseable workflow rather than a corrupt one.
func TestGeneratedWorkflowParsesForFallbackBranches(t *testing.T) {
	for _, branch := range []string{"", "bad\nname", "tab\there"} {
		dir := t.TempDir()
		path, _, err := WriteWorkflow(dir, branch)
		if err != nil {
			t.Fatalf("WriteWorkflow(%q): %v", branch, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var wf workflow
		if err := yaml.Unmarshal(data, &wf); err != nil {
			t.Fatalf("branch %q produced invalid YAML: %v\n%s", branch, err, data)
		}
		if got := wf.On.Push.Branches; len(got) != 1 || got[0] != "main" {
			t.Errorf("branch %q: got branches %q, want [main]", branch, got)
		}
	}
}

// workflow is just enough of the GitHub Actions schema to assert the structure
// survives generation. Note `on` is quoted: YAML 1.1 would otherwise read the
// bare key as the boolean true.
type workflow struct {
	Name        string            `yaml:"name"`
	On          triggers          `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]job    `yaml:"jobs"`
}

type triggers struct {
	Push struct {
		Branches []string `yaml:"branches"`
	} `yaml:"push"`
	PullRequest *struct{} `yaml:"pull_request"`
}

type job struct {
	RunsOn string `yaml:"runs-on"`
	If     string `yaml:"if"`
	Steps  []struct {
		Name string `yaml:"name"`
		Uses string `yaml:"uses"`
		Run  string `yaml:"run"`
	} `yaml:"steps"`
}
