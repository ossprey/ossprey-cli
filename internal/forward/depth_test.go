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
// where the install reaches below it (a workspace root, a dependency named by
// local path) or the scan is of reqFilesDir's copy, which holds each file one
// level down.
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
		args  []string
		want  int
	}{
		{name: "plain project", files: map[string]string{"package.json": `{"dependencies":{"x":"1"}}`}, want: 1},
		{name: "no manifest", want: 1},
		{name: "npm workspace root", files: map[string]string{"package.json": `{"workspaces":["packages/*"]}`}, want: 0},
		{name: "pnpm workspace root", files: map[string]string{"pnpm-workspace.yaml": "packages:\n  - apps/*\n"}, want: 0},
		{name: "uv workspace root", files: map[string]string{"pyproject.toml": "[tool.uv.workspace]\nmembers = [\"p/*\"]\n"}, want: 0},
		{name: "local file: dependency", files: map[string]string{"package.json": `{"dependencies":{"local":"file:./local"}}`}, want: 0},
		{name: "uv path source", files: map[string]string{"pyproject.toml": "[tool.uv.sources]\nlocal = { path = \"./local\" }\n"}, want: 0},
		{name: "poetry project with a lockfile", files: map[string]string{
			"pyproject.toml": "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"^2\"\n",
			"poetry.lock":    "",
		}, want: 1},
		{name: "settings-only pnpm yaml beside npm workspaces", files: map[string]string{
			"pnpm-workspace.yaml": "catalog:\n  x: 1.0.0\n",
			"package.json":        `{"workspaces":["p/*"]}`,
		}, want: 0},
		{name: "pnpm override to a local path", files: map[string]string{
			"pnpm-workspace.yaml": "overrides:\n  b: file:./patched-b\n",
			"package.json":        `{"dependencies":{"b":"1"}}`,
		}, want: 0},
		// The scan is of ".", so the project the flag names is read only by
		// the whole-tree scan.
		{name: "npm --prefix", files: map[string]string{"package.json": `{}`}, args: []string{"--prefix", "./app", "install"}, want: 0},
		{name: "pnpm --dir=", args: []string{"--dir=app", "install"}, want: 0},
		{name: "yarn --cwd", args: []string{"--cwd", "app", "install"}, want: 0},
		{name: "uv --directory", args: []string{"--directory", "svc", "sync"}, want: 0},
		{name: "poetry -C", args: []string{"-C", "svc", "install"}, want: 0},
		{name: "a redirect that points here", args: []string{"--prefix", ".", "install"}, want: 1},
		{name: "env narrows a redirect", args: []string{"--prefix", "./app", "install"}, env: "1", want: 1},
		{name: "requirements copy", dir: "TEMP", want: 0},
		// The copy holds each file one level down: a limit of 1 would hide
		// every one and forward the install as clean.
		{name: "env never narrows the requirements copy", dir: "TEMP", env: "1", want: 0},
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
			req := scanRequest{Dir: dir, Redirected: redirectsProject(tc.args)}
			if got := projectScanDepth(context.Background(), req); got != tc.want {
				t.Errorf("projectScanDepth = %d, want %d", got, tc.want)
			}
		})
	}
}
