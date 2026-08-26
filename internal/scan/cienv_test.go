package scan

import (
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

func TestApplyCIEnv(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		in         ossbom.Environment
		wantOrg    string
		wantRepo   string
		wantBranch string
	}{
		{
			name: "push run",
			env: map[string]string{
				"GITHUB_REPOSITORY": "ossprey/gh-action",
				"GITHUB_REF_NAME":   "main",
			},
			wantOrg: "ossprey", wantRepo: "gh-action", wantBranch: "main",
		},
		{
			// GITHUB_REF_NAME is "123/merge" on a pull_request run, which names
			// no real branch — the head ref does.
			name: "pull request run prefers the head ref",
			env: map[string]string{
				"GITHUB_REPOSITORY": "ossprey/gh-action",
				"GITHUB_REF_NAME":   "123/merge",
				"GITHUB_HEAD_REF":   "feature/thing",
			},
			wantOrg: "ossprey", wantRepo: "gh-action", wantBranch: "feature/thing",
		},
		{
			name: "outside CI nothing is set",
			env:  map[string]string{},
		},
		{
			name: "malformed repository is ignored",
			env:  map[string]string{"GITHUB_REPOSITORY": "no-slash"},
		},
		{
			name: "caller wins",
			env: map[string]string{
				"GITHUB_REPOSITORY": "ossprey/gh-action",
				"GITHUB_REF_NAME":   "main",
			},
			in:      ossbom.Environment{GithubOrg: "mine", GithubRepo: "repo", Branch: "dev"},
			wantOrg: "mine", wantRepo: "repo", wantBranch: "dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{"GITHUB_REPOSITORY", "GITHUB_REF_NAME", "GITHUB_HEAD_REF"} {
				t.Setenv(k, tt.env[k])
			}
			env := tt.in
			ApplyCIEnv(&env)
			if env.GithubOrg != tt.wantOrg || env.GithubRepo != tt.wantRepo || env.Branch != tt.wantBranch {
				t.Errorf("got org=%q repo=%q branch=%q, want %q/%q/%q",
					env.GithubOrg, env.GithubRepo, env.Branch, tt.wantOrg, tt.wantRepo, tt.wantBranch)
			}
		})
	}
}
