package precommit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// --- git scratch-repo helpers ---

func gitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitT(t, dir, "init", "-q")
	gitT(t, dir, "config", "user.email", "test@ossprey.com")
	gitT(t, dir, "config", "user.name", "Test")
	gitT(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

func writeRepoFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func commitAll(t *testing.T, dir string) {
	t.Helper()
	gitT(t, dir, "add", "-A")
	gitT(t, dir, "commit", "-q", "-m", "commit")
}

// --- manifest fixtures ---

// npmLock renders a minimal lockfileVersion-3 package-lock.json with the
// given name -> version registry deps.
func npmLock(deps map[string]string) string {
	var b strings.Builder
	b.WriteString(`{
  "name": "app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "version": "1.0.0" }`)
	// Deterministic order not required by the parser; keep insertion simple.
	for name, ver := range deps {
		b.WriteString(`,
    "node_modules/` + name + `": {
      "version": "` + ver + `",
      "resolved": "https://registry.npmjs.org/` + name + `/-/` + name + `-` + ver + `.tgz",
      "integrity": "sha512-test"
    }`)
	}
	b.WriteString(`
  }
}
`)
	return b.String()
}

func pyproject(deps ...string) string {
	var b strings.Builder
	b.WriteString("[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\n")
	for _, d := range deps {
		b.WriteString("    \"" + d + "\",\n")
	}
	b.WriteString("]\n")
	return b.String()
}

// --- tests ---

func TestStagedDelta(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  []Package
	}{
		{
			name: "new dep added to package-lock.json",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
				commitAll(t, dir)
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0", "is-odd": "3.0.1"}))
				gitT(t, dir, "add", "package-lock.json")
			},
			want: []Package{{Type: "npm", Name: "is-odd", Version: "3.0.1", Path: "package-lock.json"}},
		},
		{
			name: "version bump in package-lock.json",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
				commitAll(t, dir)
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.4.0"}))
				gitT(t, dir, "add", "package-lock.json")
			},
			want: []Package{{Type: "npm", Name: "left-pad", Version: "1.4.0", Path: "package-lock.json"}},
		},
		{
			name: "unchanged manifest yields empty delta",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
				commitAll(t, dir)
				gitT(t, dir, "add", "package-lock.json") // content identical, nothing staged
			},
			want: nil,
		},
		{
			name: "non-manifest staged files are ignored",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "README.md", "# hi\n")
				commitAll(t, dir)
				writeRepoFile(t, dir, "README.md", "# hi\nchanged\n")
				writeRepoFile(t, dir, "main.go", "package main\n")
				gitT(t, dir, "add", "-A")
			},
			want: nil,
		},
		{
			name: "initial commit with no HEAD treats everything staged as added",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
				gitT(t, dir, "add", "-A") // no commit: unborn branch
			},
			want: []Package{{Type: "npm", Name: "left-pad", Version: "1.3.0", Path: "package-lock.json"}},
		},
		{
			name: "deleted manifest yields empty delta",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
				commitAll(t, dir)
				gitT(t, dir, "rm", "-q", "package-lock.json")
			},
			want: nil,
		},
		{
			name: "requirements.txt add",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "requirements.txt", "flask==2.0.0\n")
				commitAll(t, dir)
				writeRepoFile(t, dir, "requirements.txt", "flask==2.0.0\nrequests==2.31.0\n")
				gitT(t, dir, "add", "requirements.txt")
			},
			want: []Package{{Type: "pypi", Name: "requests", Version: "2.31.0", Path: "requirements.txt"}},
		},
		{
			name: "pyproject.toml add carries versionless range",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "pyproject.toml", pyproject("click"))
				commitAll(t, dir)
				writeRepoFile(t, dir, "pyproject.toml", pyproject("click", "requests>=2"))
				gitT(t, dir, "add", "pyproject.toml")
			},
			want: []Package{{Type: "pypi", Name: "requests", Version: "", Path: "pyproject.toml"}},
		},
		{
			name: "vendored node_modules paths are ignored",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "README.md", "# hi\n")
				commitAll(t, dir)
				writeRepoFile(t, dir, "web/node_modules/evil/package.json",
					`{"name":"evil","version":"1.0.0","dependencies":{"is-odd":"^3.0.1"}}`)
				gitT(t, dir, "add", "-f", "web/node_modules/evil/package.json")
			},
			want: nil,
		},
		{
			name: "index content wins over a differing worktree file",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
				commitAll(t, dir)
				// Stage a change adding is-odd...
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0", "is-odd": "3.0.1"}))
				gitT(t, dir, "add", "package-lock.json")
				// ...then modify the worktree differently WITHOUT staging.
				writeRepoFile(t, dir, "package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0", "sneaky-pkg": "9.9.9"}))
			},
			want: []Package{{Type: "npm", Name: "is-odd", Version: "3.0.1", Path: "package-lock.json"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := initRepo(t)
			tc.setup(t, dir)
			got, err := StagedDelta(ctx, dir)
			if err != nil {
				t.Fatalf("StagedDelta: %v", err)
			}
			if !reflect.DeepEqual(got.Packages, tc.want) {
				t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, tc.want)
			}
		})
	}
}

func TestStagedDeltaSubdirectoryPathPreserved(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, "web/package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0"}))
	commitAll(t, dir)
	writeRepoFile(t, dir, "web/package-lock.json", npmLock(map[string]string{"left-pad": "1.3.0", "is-odd": "3.0.1"}))
	gitT(t, dir, "add", "web/package-lock.json")

	got, err := StagedDelta(context.Background(), dir)
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	want := []Package{{Type: "npm", Name: "is-odd", Version: "3.0.1", Path: "web/package-lock.json"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, want)
	}
}

func TestIsManifestPath(t *testing.T) {
	cases := []struct {
		p    string
		want bool
	}{
		{"package.json", true},
		{"web/package-lock.json", true},
		{"yarn.lock", true},
		{"pnpm-lock.yaml", true},
		{"pyproject.toml", true},
		{"poetry.lock", true},
		{"Pipfile.lock", true},
		{"uv.lock", true},
		{"pdm.lock", true},
		{"setup.py", true},
		{"requirements.txt", true},
		{"dev-requirements.txt", true},
		{"requirements-dev.txt", true},
		{"Pipfile", false}, // no cataloger parses a bare Pipfile
		{"README.md", false},
		{"main.go", false},
		{"requirements.in", false},
	}
	for _, tc := range cases {
		if got := isManifestPath(tc.p); got != tc.want {
			t.Errorf("isManifestPath(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}
