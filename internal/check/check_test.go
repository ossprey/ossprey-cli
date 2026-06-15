package check

import (
	"context"
	"strings"
	"testing"
)

func TestParseSpec(t *testing.T) {
	tests := []struct {
		name          string
		ecosystem     string
		token         string
		wantEco       string
		wantNamespace string
		wantName      string
		wantVersion   string
		wantErr       bool
	}{
		{name: "npm name@version", ecosystem: "npm", token: "lodash@4.17.21", wantEco: "npm", wantName: "lodash", wantVersion: "4.17.21"},
		{name: "npm bare", ecosystem: "npm", token: "lodash", wantEco: "npm", wantName: "lodash", wantVersion: ""},
		{name: "npm scoped pinned", ecosystem: "npm", token: "@babel/core@7.0.0", wantEco: "npm", wantName: "@babel/core", wantVersion: "7.0.0"},
		{name: "npm scoped bare", ecosystem: "npm", token: "@babel/core", wantEco: "npm", wantName: "@babel/core", wantVersion: ""},
		{name: "pypi ==", ecosystem: "pypi", token: "requests==2.31.0", wantEco: "pypi", wantName: "requests", wantVersion: "2.31.0"},
		{name: "pypi bare", ecosystem: "pypi", token: "requests", wantEco: "pypi", wantName: "requests", wantVersion: ""},
		{name: "pypi range strips version", ecosystem: "pypi", token: "requests>=2.0", wantEco: "pypi", wantName: "requests", wantVersion: ""},
		{name: "pypi @ friendly form", ecosystem: "pypi", token: "requests@2.31.0", wantEco: "pypi", wantName: "requests", wantVersion: "2.31.0"},
		{name: "pypi @ url is not a version", ecosystem: "pypi", token: "mypkg@git+https://x/y", wantEco: "pypi", wantName: "mypkg@git+https://x/y", wantVersion: ""},
		{name: "pypi alias pip", ecosystem: "pip", token: "flask==3.0", wantEco: "pypi", wantName: "flask", wantVersion: "3.0"},
		{name: "npm alias yarn", ecosystem: "yarn", token: "react@18", wantEco: "npm", wantName: "react", wantVersion: "18"},
		{name: "github owner/repo defaults HEAD", ecosystem: "github", token: "Xpra-org/xpra", wantEco: "github", wantNamespace: "Xpra-org", wantName: "xpra", wantVersion: "HEAD"},
		{name: "github owner/repo@ref", ecosystem: "github", token: "ossprey/ossprey-cli@v1.0.0", wantEco: "github", wantNamespace: "ossprey", wantName: "ossprey-cli", wantVersion: "v1.0.0"},
		{name: "github https url", ecosystem: "github", token: "https://github.com/pallets/click.git", wantEco: "github", wantNamespace: "pallets", wantName: "click", wantVersion: "HEAD"},
		{name: "github ssh url", ecosystem: "github", token: "git@github.com:psf/requests.git", wantEco: "github", wantNamespace: "psf", wantName: "requests", wantVersion: "HEAD"},
		{name: "github alias gh", ecosystem: "gh", token: "acme/widget", wantEco: "github", wantNamespace: "acme", wantName: "widget", wantVersion: "HEAD"},
		{name: "github missing repo", ecosystem: "github", token: "justowner", wantErr: true},
		{name: "github too many segments", ecosystem: "github", token: "a/b/c", wantErr: true},
		{name: "bad ecosystem", ecosystem: "cargo", token: "serde", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := ParseSpec(tt.ecosystem, tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err: got %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if s.Ecosystem != tt.wantEco || s.Namespace != tt.wantNamespace || s.Name != tt.wantName || s.Version != tt.wantVersion {
				t.Errorf("ParseSpec(%q,%q) = %+v, want eco=%q namespace=%q name=%q version=%q",
					tt.ecosystem, tt.token, s, tt.wantEco, tt.wantNamespace, tt.wantName, tt.wantVersion)
			}
		})
	}
}

// TestRun_GitHubRepo verifies a single github repo check produces a
// namespace-qualified github component and sets env.github_org/repo/branch so
// the dashboard can title and link the scan.
func TestRun_GitHubRepo(t *testing.T) {
	sbom, err := Run(context.Background(), Options{
		Specs:      []Spec{{Ecosystem: "github", Namespace: "Xpra-org", Name: "xpra", Version: "HEAD"}},
		DryRunSafe: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components: got %d, want 1", len(sbom.Components))
	}
	c := sbom.Components[0]
	if c.Namespace != "Xpra-org" || c.Name != "xpra" || c.Type != "github" {
		t.Errorf("component: got %+v, want namespace=Xpra-org name=xpra type=github", c)
	}
	if want := "pkg:github/Xpra-org/xpra@HEAD"; sbom.ToMiniBOM().Components[0].Purl != want {
		t.Errorf("purl: got %q, want %q", sbom.ToMiniBOM().Components[0].Purl, want)
	}
	if sbom.Env.GithubOrg != "Xpra-org" || sbom.Env.GithubRepo != "xpra" || sbom.Env.Branch != "HEAD" {
		t.Errorf("env: got org=%q repo=%q branch=%q, want Xpra-org/xpra@HEAD",
			sbom.Env.GithubOrg, sbom.Env.GithubRepo, sbom.Env.Branch)
	}
	if want := "Xpra-org/xpra@HEAD"; sbom.Name != want {
		t.Errorf("sbom.Name: got %q, want %q", sbom.Name, want)
	}
}

func TestRun_DryRunMalicious(t *testing.T) {
	sbom, err := Run(context.Background(), Options{
		Specs:           []Spec{{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}},
		DryRunMalicious: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sbom.Components) != 1 {
		t.Fatalf("components: got %d, want 1", len(sbom.Components))
	}
	if len(sbom.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities: got %d, want 1", len(sbom.Vulnerabilities))
	}
	if !strings.Contains(sbom.Vulnerabilities[0].Purl, "pkg:pypi/requests@2.31.0") {
		t.Errorf("vuln purl: got %q", sbom.Vulnerabilities[0].Purl)
	}
}

func TestRun_DryRunSafe(t *testing.T) {
	sbom, err := Run(context.Background(), Options{
		Specs: []Spec{
			{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
			{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"},
		},
		DryRunSafe: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sbom.Components) != 2 {
		t.Fatalf("components: got %d, want 2", len(sbom.Components))
	}
	if len(sbom.Vulnerabilities) != 0 {
		t.Errorf("vulnerabilities: got %d, want 0", len(sbom.Vulnerabilities))
	}
}

func TestRun_SetsScanName(t *testing.T) {
	tests := []struct {
		name  string
		specs []Spec
		want  string
	}{
		{
			name:  "single spec",
			specs: []Spec{{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}},
			want:  "requests@2.31.0",
		},
		{
			name: "multiple specs",
			specs: []Spec{
				{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
				{Ecosystem: "pypi", Name: "flask", Version: "3.0.0"},
			},
			want: "lodash@4.17.21, flask@3.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, err := Run(context.Background(), Options{Specs: tt.specs, DryRunSafe: true})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if sbom.Name != tt.want {
				t.Errorf("sbom.Name = %q, want %q", sbom.Name, tt.want)
			}
			// env.Project drives the dashboard scan name; must not be the host.
			if sbom.Env.Project != tt.want {
				t.Errorf("env.Project = %q, want %q", sbom.Env.Project, tt.want)
			}
		})
	}
}

func TestRun_Errors(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{name: "no specs", opts: Options{DryRunSafe: true}},
		{name: "missing version", opts: Options{Specs: []Spec{{Ecosystem: "npm", Name: "lodash"}}, DryRunSafe: true}},
		{name: "bad ecosystem", opts: Options{Specs: []Spec{{Ecosystem: "cargo", Name: "serde", Version: "1.0"}}, DryRunSafe: true}},
		{name: "empty name", opts: Options{Specs: []Spec{{Ecosystem: "npm", Version: "1.0"}}, DryRunSafe: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Run(context.Background(), tt.opts); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
