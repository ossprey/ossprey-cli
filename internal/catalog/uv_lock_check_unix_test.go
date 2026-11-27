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

// A locked project is read from its lock as written: what the pyproject declares since is resolved beside it without a build, and the build backend never runs.
func TestUVLockDriftIsResolvedWithoutBuilding(t *testing.T) {
	bin := t.TempDir()
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("OSSPREY_TEST_UV_ARGS", argsFile)
	// Shell builtins only: PATH is this directory alone.
	writeScript(t, bin, "uv", "#!/bin/sh\n[ \"$1\" = \"--version\" ] && { echo 'uv 0.5.0'; exit 0; }\n"+
		"echo \"$*\" >> \"$OSSPREY_TEST_UV_ARGS\"\n"+
		"case \"$1\" in export) echo 'from-export==1.0.0';; pip) [ -n \"$OSSPREY_TEST_UV_FAIL\" ] && { echo 'error: Building source distributions is disabled' >&2; exit 2; }; echo 'from-compile==1.0.0';; esac\nexit 0\n")
	t.Setenv("PATH", bin)

	const project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\n"
	sixLock := rootLock("[package.metadata]\nrequires-dist = [{ name = \"six\" }]\n\n[package.metadata.requires-dev]\ndev = [{ name = \"pytest\" }]\n")
	for _, tc := range []struct {
		name, pyproject string
		fail            bool
		want            []string
		compile         []string // in the refresh's arguments, nil when there must be none
		warning         string
	}{
		{name: "lock made from the pyproject", pyproject: project + "dependencies = [\"six\"]\n[dependency-groups]\ndev = [\"pytest\"]\n", want: []string{"from-export"}},
		{name: "dependency added since the lock", pyproject: project + "dependencies = [\"six\", \"idna\"]\n[dependency-groups]\ndev = [\"pytest\"]\n",
			want: []string{"from-compile", "from-export"}, compile: []string{"--no-build", "--group", "pyproject.toml:dev"}},
		{name: "group entry added since the lock", pyproject: project + "dependencies = [\"six\"]\n[dependency-groups]\ndev = [\"pytest\", \"mypy\"]\n",
			want: []string{"from-compile", "from-export"}, compile: []string{"--no-build", "pyproject.toml:dev"}},
		{name: "refresh that needs a build", pyproject: project + "dependencies = [\"six\", \"idna\"]\n", fail: true,
			want: []string{"from-export"}, compile: []string{"--no-build"}, warning: "uv.lock is older than pyproject.toml, which could not be resolved (building source distributions is disabled)"},
		{name: "dependencies computed by the build backend", pyproject: project + "dynamic = [\"dependencies\"]\n[dependency-groups]\ndev = [\"pytest\"]\n",
			want: []string{"from-export"}, warning: "uv.lock read as written: its project computes its dependencies when built"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.Remove(argsFile)
			if tc.fail {
				t.Setenv("OSSPREY_TEST_UV_FAIL", "1")
			}
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
			var export, compile string
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				switch {
				case strings.HasPrefix(line, "export "):
					export = line
				case strings.HasPrefix(line, "pip "):
					compile = line
				}
			}
			if !strings.Contains(export, "--frozen") {
				t.Errorf("uv export without --frozen: %q", export)
			}
			if tc.compile == nil && compile != "" {
				t.Errorf("refreshed a lock it should have read alone: %q", compile)
			}
			for _, a := range tc.compile {
				if !strings.Contains(compile, a) {
					t.Errorf("refresh %q lacks %q", compile, a)
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
