package gitenv

import "testing"

func TestParseRemoteURL(t *testing.T) {
	tests := []struct {
		url      string
		wantOrg  string
		wantRepo string
		wantOK   bool
	}{
		{"https://github.com/ossprey/ossprey-cli.git", "ossprey", "ossprey-cli", true},
		{"https://github.com/ossprey/ossprey-cli", "ossprey", "ossprey-cli", true},
		{"git@github.com:Xpra-org/xpra.git", "Xpra-org", "xpra", true},
		{"git@github.com:Xpra-org/xpra", "Xpra-org", "xpra", true},
		{"ssh://git@github.com/pallets/click.git", "pallets", "click", true},
		{"https://github.com/owner/repo/", "owner", "repo", true},
		{"https://gitlab.com/owner/repo.git", "", "", false},
		{"git@bitbucket.org:owner/repo.git", "", "", false},
		{"https://github.com/owner", "", "", false},
		{"", "", "", false},
		{"not a url", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			org, repo, ok := ParseRemoteURL(tt.url)
			if ok != tt.wantOK || org != tt.wantOrg || repo != tt.wantRepo {
				t.Errorf("ParseRemoteURL(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.url, org, repo, ok, tt.wantOrg, tt.wantRepo, tt.wantOK)
			}
		})
	}
}

func TestDetectFromEnv(t *testing.T) {
	tests := []struct {
		name       string
		repository string
		refName    string
		codespaces string
		ghActions  string
		wantOK     bool
		want       GitHub
	}{
		{
			name:       "github actions",
			repository: "ossprey/ossprey-cli",
			refName:    "main",
			ghActions:  "true",
			wantOK:     true,
			want:       GitHub{Org: "ossprey", Repo: "ossprey-cli", Branch: "main", ProductEnv: "GITHUB_ACTIONS"},
		},
		{
			name:       "codespace wins over actions",
			repository: "acme/widget",
			refName:    "dev",
			codespaces: "true",
			ghActions:  "true",
			wantOK:     true,
			want:       GitHub{Org: "acme", Repo: "widget", Branch: "dev", ProductEnv: "CODESPACE"},
		},
		{
			name:       "no ref name",
			repository: "acme/widget",
			wantOK:     true,
			want:       GitHub{Org: "acme", Repo: "widget"},
		},
		{name: "empty repository", repository: "", wantOK: false},
		{name: "malformed repository", repository: "nopeslash", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// t.Setenv isolates and restores each var per subtest.
			t.Setenv("GITHUB_REPOSITORY", tt.repository)
			t.Setenv("GITHUB_REF_NAME", tt.refName)
			t.Setenv("CODESPACES", tt.codespaces)
			t.Setenv("GITHUB_ACTIONS", tt.ghActions)

			gh, ok := detectFromEnv()
			if ok != tt.wantOK {
				t.Fatalf("ok: got %v, want %v", ok, tt.wantOK)
			}
			if ok && gh != tt.want {
				t.Errorf("detectFromEnv() = %+v, want %+v", gh, tt.want)
			}
		})
	}
}

func TestGitHub_OK(t *testing.T) {
	if !(GitHub{Org: "a", Repo: "b"}).OK() {
		t.Error("org+repo should be OK")
	}
	if (GitHub{Org: "a"}).OK() {
		t.Error("missing repo should not be OK")
	}
	if (GitHub{Repo: "b"}).OK() {
		t.Error("missing org should not be OK")
	}
}
