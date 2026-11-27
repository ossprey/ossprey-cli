//go:build !windows

package catalog

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// A locked project is read from its lock as written: each part of the pyproject declared since is resolved beside it on its own, without a build, and the build backend never runs.
func TestUVLockDriftIsResolvedWithoutBuilding(t *testing.T) {
	bin := t.TempDir()
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("OSSPREY_TEST_UV_ARGS", argsFile)
	// Shell builtins only: PATH is this directory alone. A compile whose arguments hold $OSSPREY_TEST_UV_FAIL fails.
	writeScript(t, bin, "uv", "#!/bin/sh\n[ \"$1\" = \"--version\" ] && { echo 'uv 0.5.0'; exit 0; }\n"+
		"echo \"$*\" >> \"$OSSPREY_TEST_UV_ARGS\"\n"+
		"[ \"$1\" = export ] && { echo 'from-export==1.0.0'; exit 0; }\n"+
		"if [ -n \"$OSSPREY_TEST_UV_FAIL\" ]; then case \"$*\" in *\"$OSSPREY_TEST_UV_FAIL\"*) echo 'error: No solution found when resolving dependencies' >&2; exit 1;; esac; fi\n"+
		"case \"$*\" in *--group*) echo 'from-group==1.0.0';; *) echo 'from-compile==1.0.0';; esac\nexit 0\n")
	t.Setenv("PATH", bin)

	const project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\n"
	sixLock := rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\" }]\n")
	for _, tc := range []struct {
		name, pyproject, fail string
		want                  []string
		compiles              [][]string // what each refresh's arguments hold, in order
		warning               string
	}{
		{name: "lock made from the pyproject", pyproject: project + "dependencies = [\"six\"]\n[dependency-groups]\ndev = [\"pytest\"]\n",
			want: []string{"from-export"}},
		{name: "dependency added since the lock", pyproject: project + "dependencies = [\"six\", \"idna\"]\n[dependency-groups]\ndev = [\"pytest\"]\n",
			want:     []string{"from-compile", "from-export"},
			compiles: [][]string{{"--no-build", "--no-python-downloads", "--python-version 3.9", "pyproject.toml"}}},
		{name: "group entry added since the lock", pyproject: project + "requires-python = \">=3.10\"\ndependencies = [\"six\"]\n[dependency-groups]\ndev = [\"pytest\", \"mypy\"]\n",
			want:     []string{"from-export", "from-group"},
			compiles: [][]string{{"--no-build", "--python-version 3.10", "--group", "pyproject.toml:dev"}}},
		{name: "groups in conflict resolve apart", pyproject: project + "dependencies = [\"six\", \"idna\"]\n[dependency-groups]\na = [\"six==1.16.0\"]\nb = [\"six==1.17.0\"]\n", fail: "pyproject.toml:b",
			want:     []string{"from-compile", "from-export", "from-group"},
			compiles: [][]string{{"pyproject.toml"}, {"pyproject.toml:a"}, {"pyproject.toml:b"}},
			warning:  `uv.lock is older than pyproject.toml, whose dependency group "b" could not be resolved (no solution found when resolving dependencies)`},
		{name: "refresh that fails", pyproject: project + "dependencies = [\"six\", \"idna\"]\n", fail: "pyproject.toml",
			want:     []string{"from-export"},
			compiles: [][]string{{"pyproject.toml"}},
			warning:  "uv.lock is older than pyproject.toml, whose dependencies could not be resolved (no solution found when resolving dependencies)"},
		{name: "dependencies computed by the build backend", pyproject: project + "dynamic = [\"dependencies\"]\n[dependency-groups]\ndev = [\"pytest\"]\n",
			want: []string{"from-export"}, warning: "uv.lock read as written: its project computes its dependencies when built"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Remove(argsFile)
			t.Setenv("OSSPREY_TEST_UV_FAIL", tc.fail)
			dir := t.TempDir()
			writeFile(t, dir, "pyproject.toml", tc.pyproject)
			writeFile(t, dir, "uv.lock", sixLock)
			ctx := warn.NewContext(context.Background(), false)
			pkgs, err := Catalog(ctx, dir, Options{SkipVersionLookup: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			var names []string
			for _, p := range pkgs {
				if strings.HasPrefix(p.Name, "from-") {
					names = append(names, p.Name)
				}
			}
			slices.Sort(names)
			if !slices.Equal(names, tc.want) {
				t.Errorf("uv resolved %v, want %v", names, tc.want)
			}

			data, _ := os.ReadFile(argsFile)
			var export string
			var compiles []string
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				switch {
				case strings.HasPrefix(line, "export "):
					export = line
				case strings.HasPrefix(line, "pip "):
					compiles = append(compiles, line)
				}
			}
			if !strings.Contains(export, "--frozen") {
				t.Errorf("uv export without --frozen: %q", export)
			}
			if len(compiles) != len(tc.compiles) {
				t.Fatalf("refreshes %q, want %d", compiles, len(tc.compiles))
			}
			for i, want := range tc.compiles {
				for _, a := range want {
					if !strings.Contains(compiles[i], a) {
						t.Errorf("refresh %q lacks %q", compiles[i], a)
					}
				}
				// The project's own resolve names the pyproject as its input, a group's names it only with --group.
				if group := slices.Contains(want, "--group") || strings.Contains(strings.Join(want, " "), "toml:"); !group && strings.Contains(compiles[i], "--group") {
					t.Errorf("project refresh %q resolves a group too", compiles[i])
				}
			}
			out := warn.Drain(ctx)
			if tc.warning == "" && strings.Contains(out, "uv.lock") {
				t.Errorf("unexpected warning: %s", out)
			}
			if !strings.Contains(out, tc.warning) {
				t.Errorf("warning %q missing from %q", tc.warning, out)
			}
		})
	}
}

// The real uv never runs a locked project's build backend for a scan, nor rewrites its lock; without --frozen it does both.
func TestUVExportNeverBuildsTheProject(t *testing.T) {
	if _, err := lookTool("uv"); err != nil {
		t.Skip("uv not on PATH")
	}
	// Offline, with no user config and no interpreter downloads: only the lock and the in-tree backend are in reach.
	t.Setenv("UV_OFFLINE", "1")
	t.Setenv("UV_NO_CONFIG", "1")
	t.Setenv("UV_PYTHON_DOWNLOADS", "never")
	const head = "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n\n[project]\nname = \"app\"\nrequires-python = \">=3.9\"\n"
	for _, tc := range []struct {
		name, project string
	}{
		{"dependencies computed by the backend", "version = \"0.1.0\"\ndynamic = [\"dependencies\"]\n"},
		{"dynamic version with a dependency added since the lock", "dynamic = [\"version\"]\ndependencies = [\"six\", \"idna\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(t.TempDir(), "ran")
			writeFile(t, dir, "pyproject.toml", head+tc.project)
			writeFile(t, dir, "backend.py", fmt.Sprintf("open(%q, \"w\").write(\"ran\")\nraise SystemExit(\"backend ran\")\n", marker))
			lock := rootLock("dependencies = [{ name = \"six\" }]\n\n[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n") +
				"\n[[package]]\nname = \"six\"\nversion = \"1.17.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
			writeFile(t, dir, "uv.lock", lock)

			ctx := warn.NewContext(context.Background(), false)
			pkgs, err := Catalog(ctx, dir, Options{SkipVersionLookup: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			_ = warn.Drain(ctx)
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("the scan ran the project's build backend")
			}
			if got, _ := os.ReadFile(filepath.Join(dir, "uv.lock")); !bytes.Equal(got, []byte(lock)) {
				t.Error("the scan rewrote uv.lock")
			}
			found := false
			for _, p := range pkgs {
				found = found || (p.Name == "six" && p.Version == "1.17.0")
			}
			if !found {
				t.Errorf("six@1.17.0 from the lock missing: %v", pkgs)
			}
		})
	}
}
