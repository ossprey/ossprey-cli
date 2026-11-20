package forward

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/env"
)

// TestProjectScanDepth pins the forwarder's rule: a manager installs from the
// project directory's own manifest, so only that directory is read, except
// where the install reaches below it (a workspace root) or the scan is of
// reqFilesDir's copy, which holds each file one level down.
func TestProjectScanDepth(t *testing.T) {
	write := func(t *testing.T, rel, content string) {
		t.Helper()
		if err := os.WriteFile(rel, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		env   string
		dir   string
		want  int
	}{
		{name: "plain project", files: map[string]string{"package.json": `{"dependencies":{"x":"1"}}`}, want: 1},
		{name: "no manifest", want: 1},
		{name: "npm workspace root", files: map[string]string{"package.json": `{"workspaces":["packages/*"]}`}, want: 0},
		{name: "pnpm workspace root", files: map[string]string{"pnpm-workspace.yaml": "packages:\n  - apps/*\n"}, want: 0},
		{name: "uv workspace root", files: map[string]string{"pyproject.toml": "[tool.uv.workspace]\nmembers = [\"p/*\"]\n"}, want: 0},
		{name: "requirements copy", dir: "TEMP", want: 0},
		{name: "env widens a plain project", files: map[string]string{"package.json": `{}`}, env: "0", want: 0},
		{name: "env narrows a workspace", files: map[string]string{"package.json": `{"workspaces":["p/*"]}`}, env: "2", want: 2},
		{name: "bad env keeps the default", env: "deep", want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv(env.ScanDepthEnv, tc.env)
			for rel, content := range tc.files {
				write(t, rel, content)
			}
			dir := "."
			if tc.dir == "TEMP" {
				dir = filepath.Join(t.TempDir(), "reqs")
			}
			if got := projectScanDepth(context.Background(), dir); got != tc.want {
				t.Errorf("projectScanDepth = %d, want %d", got, tc.want)
			}
		})
	}
}
