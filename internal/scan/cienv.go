package scan

import (
	"os"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// ApplyCIEnv fills the repository fields of env from the variables GitHub
// Actions exports on every runner. Outside CI they are unset and env is left
// alone.
//
// Without this a CI scan reaches the dashboard identified only by the runner's
// hostname and the checkout's directory name — both throwaway — so scans of the
// same repository can't be grouped or compared across runs. Fields already set
// by the caller win; this only fills blanks.
func ApplyCIEnv(env *ossbom.Environment) {
	// GITHUB_REPOSITORY is "<owner>/<repo>".
	if owner, name, ok := strings.Cut(os.Getenv("GITHUB_REPOSITORY"), "/"); ok {
		if env.GithubOrg == "" {
			env.GithubOrg = owner
		}
		if env.GithubRepo == "" {
			env.GithubRepo = name
		}
	}
	if env.Branch == "" {
		// On a pull_request run GITHUB_REF_NAME is the synthetic merge ref
		// ("123/merge"), which names no branch anyone can check out;
		// GITHUB_HEAD_REF holds the branch the PR came from. Prefer it.
		branch := os.Getenv("GITHUB_HEAD_REF")
		if branch == "" {
			branch = os.Getenv("GITHUB_REF_NAME")
		}
		env.Branch = branch
	}
}
