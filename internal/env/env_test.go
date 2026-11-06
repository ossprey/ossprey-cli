package env

import (
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Every case sets all of these, blank included, so real CI values cannot leak in.
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
	"RUNNER_ENVIRONMENT",
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
				GithubOrg:   "acme",
				GithubRepo:  "widget",
				Branch:      "main",
				ProductEnv:  ProductGitHubActions,
				MachineName: MachineGitHubSelfHosted,
				Person:      PersonGitHubActions,
				Project:     "widget",
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
				GithubOrg:   "acme",
				GithubRepo:  "widget",
				Branch:      "feature/foo",
				ProductEnv:  ProductGitHubActions,
				MachineName: MachineGitHubSelfHosted,
				Person:      PersonGitHubActions,
				Project:     "widget",
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
				Branch:      "main",
				ProductEnv:  ProductGitHubActions,
				MachineName: MachineGitHubSelfHosted,
				Person:      PersonGitHubActions,
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

			want := tt.want
			want.Path = "/src"
			if want.MachineName == "" {
				want.MachineName = "agent-1"
			}

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

// An ADO checkout directory is ".../1/s", which must not become the scan name.
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

func TestOverlayMachineName(t *testing.T) {
	tests := []struct {
		name   string
		runner string
		want   string
	}{
		{name: "github-hosted runner gets a stable name", runner: "github-hosted", want: MachineGitHubHosted},
		{name: "self-hosted runner gets a stable name", runner: "self-hosted", want: MachineGitHubSelfHosted},
		{name: "unknown runner environment gets the self-hosted name", runner: "", want: MachineGitHubSelfHosted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range ciVars {
				t.Setenv(k, "")
			}
			t.Setenv("GITHUB_ACTIONS", "true")
			t.Setenv("GITHUB_REPOSITORY", "acme/widget")
			t.Setenv("RUNNER_ENVIRONMENT", tt.runner)

			got := ossbom.Environment{Path: "/src", MachineName: "fv-az123"}
			Overlay(&got)

			if got.MachineName != tt.want {
				t.Errorf("MachineName = %q, want %q", got.MachineName, tt.want)
			}
			if got.Person != PersonGitHubActions {
				t.Errorf("Person = %q, want %q", got.Person, PersonGitHubActions)
			}
		})
	}
}

// Two jobs on different ephemeral runners must produce the same env, or the
// backend hashes each into its own SBOM.
func TestOverlayGivesEveryGitHubActionsJobTheSameIdentity(t *testing.T) {
	for _, k := range ciVars {
		t.Setenv(k, "")
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/widget")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("RUNNER_ENVIRONMENT", "self-hosted")

	first := ossbom.Environment{Path: "/__w/widget/widget", MachineName: "3fa9c1d2e4b7", Person: "root@3fa9c1d2e4b7"}
	second := ossbom.Environment{Path: "/__w/widget/widget", MachineName: "8be04f71a2c9", Person: "root@8be04f71a2c9"}
	Overlay(&first)
	Overlay(&second)

	if first != second {
		t.Errorf("jobs on different runners differ:\n first: %+v\nsecond: %+v", first, second)
	}
}

// Outside CI the hostname is the only thing naming a local scan.
func TestOverlayKeepsTheHostnameOutsideCI(t *testing.T) {
	for _, k := range ciVars {
		t.Setenv(k, "")
	}
	t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")

	got := ossbom.Environment{MachineName: "laptop", Person: "andy@laptop"}
	Overlay(&got)

	if got.MachineName != "laptop" || got.Person != "andy@laptop" {
		t.Errorf("Overlay changed a local scan's identity: %+v", got)
	}
}
