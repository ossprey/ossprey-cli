package catalog

import "testing"

func TestIsWorkspaceRoot(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"empty dir", nil, false},
		{"plain package.json", map[string]string{"package.json": `{"name":"a","dependencies":{"x":"1"}}`}, false},
		{"npm workspaces array", map[string]string{"package.json": `{"workspaces":["packages/*"]}`}, true},
		{"yarn workspaces object", map[string]string{"package.json": `{"workspaces":{"packages":["apps/*"]}}`}, true},
		{"empty workspaces", map[string]string{"package.json": `{"workspaces":[]}`}, false},
		{"unparseable package.json", map[string]string{"package.json": `{`}, true},
		{"pnpm workspace", map[string]string{"pnpm-workspace.yaml": "packages:\n  - 'packages/*'\n"}, true},
		// pnpm 10 reports the root project alone for a file with no packages key.
		{"pnpm workspace without packages", map[string]string{"pnpm-workspace.yaml": "catalog:\n  x: 1.0.0\n"}, false},
		{"pnpm yaml wins over package.json", map[string]string{
			"pnpm-workspace.yaml": "catalog:\n  x: 1.0.0\n",
			"package.json":        `{"workspaces":["packages/*"]}`,
		}, false},
		{"unparseable pnpm workspace", map[string]string{"pnpm-workspace.yaml": "packages: [\n"}, true},
		{"uv workspace", map[string]string{"pyproject.toml": "[project]\nname = \"a\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n"}, true},
		{"empty uv workspace table", map[string]string{"pyproject.toml": "[tool.uv.workspace]\n"}, true},
		{"plain pyproject", map[string]string{"pyproject.toml": "[project]\nname = \"a\"\ndependencies = [\"requests\"]\n"}, false},
		{"unparseable pyproject", map[string]string{"pyproject.toml": "[project\n"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range tc.files {
				writeFixture(t, dir, rel, content)
			}
			if got := IsWorkspaceRoot(dir); got != tc.want {
				t.Errorf("IsWorkspaceRoot = %v, want %v", got, tc.want)
			}
		})
	}
}
