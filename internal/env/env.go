// Package env fills the SCM attribution fields of an OSSBOM Environment from CI
// environment variables.
package env

import (
	"os"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Values match the Python client's, so dashboard rows stay comparable.
const (
	ProductAzureDevOps   = "AZURE_DEVOPS"
	ProductGitHubActions = "GITHUB_ACTIONS"
)

// MachineGitHubHosted stands in for the hostname on a GitHub-hosted runner.
// Each job gets a fresh VM with its own hostname, and the backend hashes the
// SBOM's env into its id, so the real hostname made every CI run of unchanged
// dependencies a distinct SBOM the service could not recognise as a repeat.
const MachineGitHubHosted = "github-hosted-runner"

type detector func() (ossbom.Environment, bool)

var detectors = []detector{detectAzureDevOps, detectGitHubActions}

// Overlay fills attribution and Project from the detected CI platform, leaving
// Path to the caller. MachineName is left to the caller too, except on an
// ephemeral hosted runner, where the platform's stable name replaces it.
func Overlay(e *ossbom.Environment) {
	for _, detect := range detectors {
		got, ok := detect()
		if !ok {
			continue
		}
		setIfEmpty(&e.GithubOrg, got.GithubOrg)
		setIfEmpty(&e.GithubRepo, got.GithubRepo)
		setIfEmpty(&e.Branch, got.Branch)
		setIfEmpty(&e.ProductEnv, got.ProductEnv)
		setIfEmpty(&e.Project, got.Project)
		if got.MachineName != "" {
			e.MachineName = got.MachineName
		}
		return
	}
}

func setIfEmpty(dst *string, v string) {
	if *dst == "" && v != "" {
		*dst = v
	}
}

func detectAzureDevOps() (ossbom.Environment, bool) {
	// TF_BUILD is the canonical marker; CI is set by too many systems.
	if os.Getenv("TF_BUILD") == "" {
		return ossbom.Environment{}, false
	}

	// ADO is org/project/repo, which does not fit two fields. The team project
	// reads better than the org and cannot collide within one org.
	org := os.Getenv("SYSTEM_TEAMPROJECT")
	repo := os.Getenv("BUILD_REPOSITORY_NAME")

	// A GitHub-backed pipeline reports BUILD_REPOSITORY_NAME as "owner/repo".
	if strings.EqualFold(os.Getenv("BUILD_REPOSITORY_PROVIDER"), "github") {
		if owner, name, ok := strings.Cut(repo, "/"); ok {
			org, repo = owner, name
		}
	}

	return ossbom.Environment{
		GithubOrg:  org,
		GithubRepo: repo,
		Branch:     azureBranch(),
		ProductEnv: ProductAzureDevOps,
		Project:    repo,
	}, true
}

func azureBranch() string {
	// On a PR build BUILD_SOURCEBRANCH is "refs/pull/<id>/merge". Not
	// BUILD_SOURCEBRANCHNAME either: it drops all but the last path segment.
	branch := os.Getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH")
	if branch == "" {
		branch = os.Getenv("BUILD_SOURCEBRANCH")
	}
	return strings.TrimPrefix(branch, "refs/heads/")
}

func detectGitHubActions() (ossbom.Environment, bool) {
	if os.Getenv("GITHUB_ACTIONS") == "" {
		return ossbom.Environment{}, false
	}

	e := ossbom.Environment{Branch: githubBranch(), ProductEnv: ProductGitHubActions}
	// Self-hosted runners keep their hostname: it is stable, so it already
	// dedupes, and it says which machine ran the scan.
	if os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" {
		e.MachineName = MachineGitHubHosted
	}
	// A half-filled org/repo pair groups nothing, so require both.
	if org, repo, ok := strings.Cut(os.Getenv("GITHUB_REPOSITORY"), "/"); ok {
		e.GithubOrg, e.GithubRepo, e.Project = org, repo, repo
	}
	return e, true
}

func githubBranch() string {
	// GITHUB_REF_NAME is the merge ref ("123/merge") on a pull_request event.
	if head := os.Getenv("GITHUB_HEAD_REF"); head != "" {
		return head
	}
	return os.Getenv("GITHUB_REF_NAME")
}
