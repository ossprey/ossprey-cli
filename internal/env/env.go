// Package env detects the CI platform from environment variables and fills in
// the SCM attribution fields of an OSSBOM Environment.
//
// The platform decides how to group a scan from those fields: asset_summary's
// scan_type only returns "github" when both org and repo are set, and only then
// does asset_key collapse a repo's branches into one asset. Left empty, every
// run lands as its own unattributed row.
package env

import (
	"os"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// Product tokens sent to the platform as product_env; these match the values the
// Python client has always sent, so existing dashboard rows stay comparable.
const (
	ProductAzureDevOps   = "AZURE_DEVOPS"
	ProductGitHubActions = "GITHUB_ACTIONS"
)

// detector reports SCM attribution for one CI platform, or false when not on it.
type detector func() (ossbom.Environment, bool)

// First match wins; each platform's marker is exclusive in practice.
var detectors = []detector{detectAzureDevOps, detectGitHubActions}

// Overlay fills the SCM attribution fields from the detected CI platform. Path,
// Project and MachineName are left alone: the caller knows those better than we do.
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
		return
	}
}

// setIfEmpty assigns v only when it has something to say and dst does not, so
// Overlay is safe to call over an Environment a caller has already populated.
func setIfEmpty(dst *string, v string) {
	if *dst == "" && v != "" {
		*dst = v
	}
}

// detectAzureDevOps maps an Azure Pipelines build. TF_BUILD is the canonical
// marker; CI is set by too many systems to discriminate on.
func detectAzureDevOps() (ossbom.Environment, bool) {
	if os.Getenv("TF_BUILD") == "" {
		return ossbom.Environment{}, false
	}

	// The ADO hierarchy is org/project/repo, which does not fit a two-field
	// model. The team project reads better in the dashboard than the org and
	// cannot collide across projects in one org, so it takes the org slot.
	org := os.Getenv("SYSTEM_TEAMPROJECT")
	repo := os.Getenv("BUILD_REPOSITORY_NAME")

	// A GitHub-backed pipeline reports BUILD_REPOSITORY_NAME as "owner/repo".
	// Split it so those scans share an asset with the GitHub App's.
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
	}, true
}

// azureBranch prefers the pull-request source branch, because on a PR build
// BUILD_SOURCEBRANCH is "refs/pull/<id>/merge", which groups nothing. Neither is
// BUILD_SOURCEBRANCHNAME an option: it is only the last path segment, so it
// reports "bar" for "feature/foo/bar" and merges unrelated branches.
func azureBranch() string {
	branch := os.Getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH")
	if branch == "" {
		branch = os.Getenv("BUILD_SOURCEBRANCH")
	}
	return strings.TrimPrefix(branch, "refs/heads/")
}

// detectGitHubActions maps a GitHub Actions run.
func detectGitHubActions() (ossbom.Environment, bool) {
	if os.Getenv("GITHUB_ACTIONS") == "" {
		return ossbom.Environment{}, false
	}
	org, repo, _ := strings.Cut(os.Getenv("GITHUB_REPOSITORY"), "/")
	return ossbom.Environment{
		GithubOrg:  org,
		GithubRepo: repo,
		Branch:     os.Getenv("GITHUB_REF_NAME"),
		ProductEnv: ProductGitHubActions,
	}, true
}
