package env

import (
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// ciVars is every variable the detectors read. Each case sets all of them, blank
// included, so a test stays hermetic when it runs inside CI, where the real
// GITHUB_ACTIONS would otherwise leak in.
var ciVars = []string{
	"TF_BUILD",
	"SYSTEM_TEAMPROJECT",
	"BUILD_REPOSITORY_NAME",
	"BUILD_REPOSITORY_PROVIDER",
	"SYSTEM_PULLREQUEST_SOURCEBRANCH",
	"BUILD_SOURCEBRANCH",
	"GITHUB_ACTIONS",
	"GITHUB_REPOSITORY",
	"GITHUB_REF_NAME",
	"GITHUB_HEAD_REF",
}

func TestOverlay(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want ossbom.Environment
	}{
		{
			name: "azure repos pull request build",
			env: map[string]string{
				"TF_BUILD":                        "True",
				"SYSTEM_TEAMPROJECT":              "MyProject",
				"BUILD_REPOSITORY_NAME":           "my-repo",
				"SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/feature/foo/bar",
				"BUILD_SOURCEBRANCH":              "refs/pull/42/merge",
			},
			want: ossbom.Environment{
				GithubOrg:  "MyProject",
				GithubRepo: "my-repo",
				Branch:     "feature/foo/bar",
				ProductEnv: ProductAzureDevOps,
				Project:    "my-repo",
			},
		},
		{
			name: "azure repos ci build has no pr branch",
			env: map[string]string{
				"TF_BUILD":              "True",
				"SYSTEM_TEAMPROJECT":    "MyProject",
				"BUILD_REPOSITORY_NAME": "my-repo",
				"BUILD_SOURCEBRANCH":    "refs/heads/main",
			},
			want: ossbom.Environment{
				GithubOrg:  "MyProject",
				GithubRepo: "my-repo",
				Branch:     "main",
				ProductEnv: ProductAzureDevOps,
				Project:    "my-repo",
			},
		},
		{
			name: "azure pipeline on a github backed repo splits owner from name",
			env: map[string]string{
				"TF_BUILD":                  "True",
				"SYSTEM_TEAMPROJECT":        "MyProject",
				"BUILD_REPOSITORY_NAME":     "acme/widget",
				"BUILD_REPOSITORY_PROVIDER": "GitHub",
				"BUILD_SOURCEBRANCH":        "refs/heads/main",
			},
			want: ossbom.Environment{
				GithubOrg:  "acme",
				GithubRepo: "widget",
				Branch:     "main",
				ProductEnv: ProductAzureDevOps,
				Project:    "widget",
			},
		},
		{
			name: "azure with a missing team project still reports the platform",
			env: map[string]string{
				"TF_BUILD":              "True",
				"BUILD_REPOSITORY_NAME": "my-repo",
				"BUILD_SOURCEBRANCH":    "refs/heads/main",
			},
			want: ossbom.Environment{
				GithubRepo: "my-repo",
				Branch:     "main",
				ProductEnv: ProductAzureDevOps,
				Project:    "my-repo",
			},
		},
		{
			name: "github actions",
			env: map[string]string{
				"GITHUB_ACTIONS":    "true",
				"GITHUB_REPOSITORY": "acme/widget",
				"GITHUB_REF_NAME":   "main",
			},
			want: ossbom.Environment{
				GithubOrg:  "acme",
				GithubRepo: "widget",
				Branch:     "main",
				ProductEnv: ProductGitHubActions,
				Project:    "widget",
			},
		},
		{
			name: "github actions pull request uses the head ref",
			env: map[string]string{
				"GITHUB_ACTIONS":    "true",
				"GITHUB_REPOSITORY": "acme/widget",
				"GITHUB_REF_NAME":   "123/merge",
				"GITHUB_HEAD_REF":   "feature/foo",
			},
			want: ossbom.Environment{
				GithubOrg:  "acme",
				GithubRepo: "widget",
				Branch:     "feature/foo",
				ProductEnv: ProductGitHubActions,
				Project:    "widget",
			},
		},
		{
			name: "github actions with a malformed slug reports no org or repo",
			env: map[string]string{
				"GITHUB_ACTIONS":    "true",
				"GITHUB_REPOSITORY": "widget",
				"GITHUB_REF_NAME":   "main",
			},
			want: ossbom.Environment{
				Branch:     "main",
				ProductEnv: ProductGitHubActions,
			},
		},
		{
			name: "no ci leaves attribution empty",
			env:  map[string]string{},
			want: ossbom.Environment{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range ciVars {
				t.Setenv(k, tt.env[k])
			}

			got := ossbom.Environment{Path: "/src", MachineName: "agent-1"}
			Overlay(&got)

			// Overlay must not touch Path or MachineName.
			want := tt.want
			want.Path, want.MachineName = "/src", "agent-1"

			if got != want {
				t.Errorf("Overlay()\n got: %+v\nwant: %+v", got, want)
			}
		})
	}
}

func TestOverlayDoesNotClobberExistingAttribution(t *testing.T) {
	for _, k := range ciVars {
		t.Setenv(k, "")
	}
	t.Setenv("TF_BUILD", "True")
	t.Setenv("SYSTEM_TEAMPROJECT", "FromPipeline")
	t.Setenv("BUILD_REPOSITORY_NAME", "from-pipeline")

	got := ossbom.Environment{GithubOrg: "explicit", GithubRepo: "explicit-repo"}
	Overlay(&got)

	if got.GithubOrg != "explicit" || got.GithubRepo != "explicit-repo" {
		t.Errorf("Overlay overwrote caller-set attribution: %+v", got)
	}
	if got.ProductEnv != ProductAzureDevOps {
		t.Errorf("ProductEnv = %q, want %q", got.ProductEnv, ProductAzureDevOps)
	}
}

// The regression this guards: Azure Pipelines checks out into /home/vsts/work/1/s,
// so deriving Project from the directory showed every scan in the dashboard as "s".
func TestOverlayNamesTheScanAfterTheRepositoryNotTheCheckoutDirectory(t *testing.T) {
	for _, k := range ciVars {
		t.Setenv(k, "")
	}
	t.Setenv("TF_BUILD", "True")
	t.Setenv("SYSTEM_TEAMPROJECT", "Ossprey")
	t.Setenv("BUILD_REPOSITORY_NAME", "Ossprey")
	t.Setenv("BUILD_SOURCEBRANCH", "refs/heads/main")

	got := ossbom.Environment{Path: "/home/vsts/work/1/s", MachineName: "fv-az123"}
	Overlay(&got)

	if got.Project == "s" || got.Project == "" {
		t.Errorf("Project = %q, want the repository name", got.Project)
	}
	if got.Project != "Ossprey" {
		t.Errorf("Project = %q, want %q", got.Project, "Ossprey")
	}
}
