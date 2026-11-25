package forward

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/config"
	"github.com/ossprey/ossprey-cli/internal/ossbom"
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
		{name: "poetry -P", args: []string{"-P", "svc", "install"}, want: 0},
		{name: "poetry --project=", args: []string{"install", "--project=svc"}, want: 0},
		{name: "poetry -P that points here", args: []string{"-P", ".", "install"}, want: 1},
		{name: "poetry -C attached", args: []string{"install", "-Capp"}, want: 0},
		{name: "poetry -C= attached", args: []string{"-C=app", "install"}, want: 0},
		{name: "attached redirect that points here", args: []string{"install", "-C."}, want: 1},
		{name: "a flag after -- is the program's", args: []string{"install", "--", "--prefix", "app"}, want: 1},
		{name: "a redirect that points here", args: []string{"--prefix", ".", "install"}, want: 1},
		{name: "env narrows a redirect", args: []string{"--prefix", "./app", "install"}, env: "1", want: 1},
		{name: "requirements copy", dir: "TEMP", want: 0},
		// The copy holds each file one level down: a limit of 1 would hide
		// every one and forward the install as clean.
		{name: "env never narrows the requirements copy", dir: "TEMP", env: "1", want: 0},
		{name: "env widens a plain project", files: map[string]string{"package.json": `{}`}, env: "0", want: 0},
		{name: "env narrows a workspace", files: map[string]string{"package.json": `{"workspaces":["p/*"]}`}, env: "2", want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			for rel, content := range tc.files {
				write(t, rel, content)
			}
			dir := "."
			if tc.dir == "TEMP" {
				dir = filepath.Join(t.TempDir(), "reqs")
			}
			req := scanRequest{Dir: dir, Redirected: redirectsProject(tc.args)}
			if tc.env != "" {
				d, err := strconv.Atoi(tc.env)
				if err != nil {
					t.Fatal(err)
				}
				req.Scan.Depth = &d
			}
			if got := projectScanDepth(req); got != tc.want {
				t.Errorf("projectScanDepth = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestProjectScanIgnore pins that configured ignore patterns reach a project
// scan of the install's directory, and never the requirements-file copy,
// where `**/requirements*.txt` would hide every file and forward the install
// as clean.
func TestProjectScanIgnore(t *testing.T) {
	scan := config.Scan{Ignore: []string{"wf", "**/requirements*.txt"}}
	if got := projectScanIgnore(scanRequest{Dir: ".", Scan: scan}); !slices.Equal(got, scan.Ignore) {
		t.Errorf("project scan ignore = %v, want %v", got, scan.Ignore)
	}
	if got := projectScanIgnore(scanRequest{Dir: filepath.Join(t.TempDir(), "reqs"), Scan: scan}); got != nil {
		t.Errorf("requirements copy ignore = %v, want none", got)
	}
}

// TestRunPassesTheScanSettingsToTheProjectScan pins the wiring: settings
// loaded in main reach every scan request a forwarded install builds, the
// blocking bare install, the passive one that scans after the install, and
// the requirements-file scan (where projectScanIgnore then drops the
// patterns, which TestProjectScanIgnore pins).
func TestRunPassesTheScanSettingsToTheProjectScan(t *testing.T) {
	d := 2
	settings := config.Scan{Depth: &d, Ignore: []string{"wf"}}
	for _, tc := range []struct {
		name    string
		bin     string
		args    []string
		passive bool
	}{
		{name: "bare npm install", bin: "npm", args: []string{"install"}},
		{name: "passive npm install", bin: "npm", args: []string{"install"}, passive: true},
		{name: "pip install -r", bin: "pip", args: []string{"install", "-r", writeReq(t)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			ex := &stubExec{}
			swap(t, ex.fn, cleanSBOM)
			var got *config.Scan
			swapScan(t, func(_ context.Context, req scanRequest) (*ossbom.SBOM, error) {
				got = &req.Scan
				return ossbom.New(ossbom.Environment{}), nil
			})
			if err := Run(context.Background(), Options{Bin: tc.bin, Args: tc.args, Passive: tc.passive, Scan: settings}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got == nil {
				t.Fatal("no project scan ran")
			}
			if got.Depth == nil || *got.Depth != 2 || !slices.Equal(got.Ignore, settings.Ignore) {
				t.Errorf("project scan got %+v, want %+v", *got, settings)
			}
		})
	}
}

func writeReq(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "requirements.txt")
	if err := os.WriteFile(p, []byte("requests==2.32.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
