package catalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchesWorkspaceGlobs(t *testing.T) {
	tests := []struct {
		name  string
		globs []string
		rel   string
		want  bool
	}{
		{"direct child", []string{"packages/*"}, "packages/a", true},
		{"not a grandchild", []string{"packages/*"}, "packages/a/b", false},
		{"doublestar reaches deeper", []string{"packages/**"}, "packages/a/b", true},
		{"unrelated tree", []string{"packages/*"}, "examples/demo", false},
		{"bare entry is exact", []string{"examples"}, "examples", true},
		{"bare entry is not a prefix", []string{"examples"}, "examples/demo", false},
		{"root itself", []string{"packages/*"}, ".", false},
		{"no globs declared", nil, "packages/a", false},

		// turborepo's real pnpm-workspace.yaml shape.
		{"negation prunes the dir", []string{"packages/*", "!packages/turbo"}, "packages/turbo", false},
		{"negation prunes the subtree", []string{"packages/**", "!packages/turbo"}, "packages/turbo/src", false},
		{"negation spares siblings", []string{"packages/*", "!packages/turbo"}, "packages/other", true},
		{"negation listed first still applies", []string{"!packages/turbo", "packages/*"}, "packages/turbo", false},

		{"leading ./ is stripped", []string{"./packages/*"}, "packages/a", true},
		{"trailing slash is stripped", []string{"packages/*/"}, "packages/a", true},
		{"blank entries ignored", []string{"", "  ", "packages/*"}, "packages/a", true},

		// Real globbers default to dot:false, so a dot-dir needs spelling out.
		{"dot dir not matched implicitly", []string{"**"}, ".github/actions/x", false},
		{"dot dir matched explicitly", []string{".github/**"}, ".github/actions/x", true},

		{"vendored path is never a member", []string{"**"}, "packages/a/node_modules/b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesWorkspaceGlobs(tt.globs, tt.rel); got != tt.want {
				t.Errorf("matchesWorkspaceGlobs(%q, %q) = %v, want %v", tt.globs, tt.rel, got, tt.want)
			}
		})
	}
}

func TestParsePackageJSONWorkspaces(t *testing.T) {
	tests := []struct {
		name string
		json string
		want []string
	}{
		{"array form", `{"workspaces":["packages/*"]}`, []string{"packages/*"}},
		{"yarn object form", `{"workspaces":{"packages":["packages/*"],"nohoist":["**/react"]}}`, []string{"packages/*"}},
		{"absent", `{"name":"x"}`, nil},
		{"empty array", `{"workspaces":[]}`, nil},
		{"malformed json", `{`, nil},
		{"wrong type", `{"workspaces":42}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePackageJSONWorkspaces([]byte(tt.json))
			if len(got) != len(tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

// A pnpm-workspace.yaml with no packages key claims no members. Verified
// against pnpm 10: it then reports the root project alone. Returning a
// catch-all here would mark every nested manifest a member and skip its
// resolve, losing transitives no lockfile carries.
func TestParsePnpmWorkspaceNoPackagesKeyClaimsNothing(t *testing.T) {
	if got := parsePnpmWorkspace([]byte("# nothing declared\n")); len(got) != 0 {
		t.Errorf("parsePnpmWorkspace(no packages key) = %q, want none", got)
	}
	got := parsePnpmWorkspace([]byte("packages:\n  - apps/*\n  - \"!apps/legacy\"\n"))
	if len(got) != 2 || got[0] != "apps/*" || got[1] != "!apps/legacy" {
		t.Errorf("parsePnpmWorkspace = %q, want [apps/* !apps/legacy]", got)
	}
}

// writeTree materialises files relative to dir; content "" means an empty file.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIsWorkspaceMember(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		dir   string
		want  bool
	}{
		{
			name: "npm workspace member under root lock",
			files: map[string]string{
				"package.json":            `{"workspaces":["packages/*"]}`,
				"package-lock.json":       `{}`,
				"packages/a/package.json": `{"name":"a"}`,
			},
			dir:  "packages/a",
			want: true,
		},
		{
			name: "non-member under the same root lock still resolves",
			files: map[string]string{
				"package.json":               `{"workspaces":["packages/*"]}`,
				"package-lock.json":          `{}`,
				"examples/demo/package.json": `{"name":"demo"}`,
			},
			dir:  "examples/demo",
			want: false,
		},
		{
			name: "declared member but the root ships no lockfile",
			files: map[string]string{
				"package.json":            `{"workspaces":["packages/*"]}`,
				"packages/a/package.json": `{"name":"a"}`,
			},
			dir:  "packages/a",
			want: false,
		},
		{
			name: "yarn root lock counts",
			files: map[string]string{
				"package.json":            `{"workspaces":["packages/*"]}`,
				"yarn.lock":               "",
				"packages/a/package.json": `{"name":"a"}`,
			},
			dir:  "packages/a",
			want: true,
		},
		{
			name: "pnpm workspace member",
			files: map[string]string{
				"package.json":            `{"name":"root"}`,
				"pnpm-lock.yaml":          "",
				"pnpm-workspace.yaml":     "packages:\n  - packages/*\n",
				"packages/a/package.json": `{"name":"a"}`,
			},
			dir:  "packages/a",
			want: true,
		},
		{
			name: "pnpm yaml wins over package.json workspaces",
			files: map[string]string{
				"package.json":            `{"workspaces":["examples/*"]}`,
				"pnpm-lock.yaml":          "",
				"pnpm-workspace.yaml":     "packages:\n  - packages/*\n",
				"examples/x/package.json": `{"name":"x"}`,
			},
			dir:  "examples/x",
			want: false,
		},
		{
			name: "pnpm yaml with no packages key claims nothing",
			files: map[string]string{
				"package.json":            `{"name":"root"}`,
				"pnpm-lock.yaml":          "",
				"pnpm-workspace.yaml":     "# nothing\n",
				"packages/a/package.json": `{"name":"a"}`,
			},
			dir:  "packages/a",
			want: false,
		},
		{
			name: "excluded member resolves",
			files: map[string]string{
				"package.json":                `{"workspaces":["packages/*","!packages/turbo"]}`,
				"package-lock.json":           `{}`,
				"packages/turbo/package.json": `{"name":"turbo"}`,
			},
			dir:  "packages/turbo",
			want: false,
		},
		{
			name: "root manifest is not its own member",
			files: map[string]string{
				"package.json":      `{"workspaces":["."]}`,
				"package-lock.json": `{}`,
			},
			dir:  ".",
			want: false,
		},
		{
			name: "nested workspace root two levels up",
			files: map[string]string{
				"package.json":                `{"name":"outer"}`,
				"sub/package.json":            `{"workspaces":["packages/*"]}`,
				"sub/yarn.lock":               "",
				"sub/packages/a/package.json": `{"name":"a"}`,
			},
			dir:  "sub/packages/a",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTree(t, root, tt.files)
			dir := filepath.Join(root, filepath.FromSlash(tt.dir))
			if got := isWorkspaceMember(dir, root); got != tt.want {
				t.Errorf("isWorkspaceMember(%s) = %v, want %v", tt.dir, got, tt.want)
			}
		})
	}
}

// The walk must stop at the scan root: a lockfile and workspace globs above it
// belong to a tree the user did not ask us to scan.
func TestIsWorkspaceMemberStopsAtScanRoot(t *testing.T) {
	outer := t.TempDir()
	writeTree(t, outer, map[string]string{
		"package.json":                  `{"workspaces":["inner/packages/*"]}`,
		"package-lock.json":             `{}`,
		"inner/packages/a/package.json": `{"name":"a"}`,
	})
	root := filepath.Join(outer, "inner")
	dir := filepath.Join(root, "packages", "a")
	if isWorkspaceMember(dir, root) {
		t.Error("membership was claimed by a workspace root above the scan root")
	}
}
