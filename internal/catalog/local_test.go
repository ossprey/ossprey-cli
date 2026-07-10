package catalog

import (
	"testing"
)

func TestCanonicalPackageName(t *testing.T) {
	tests := map[string]string{
		"Common":       "common",
		"  Models ":    "models",
		"my_pkg":       "my-pkg",
		"my.pkg":       "my-pkg",
		"My__Weird..P": "my-weird-p",
		"already-dash": "already-dash",
	}
	for in, want := range tests {
		if got := canonicalPackageName(in); got != want {
			t.Errorf("canonicalPackageName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectLocalNames_UVSources(t *testing.T) {
	// Mirrors the OSS-1389 report: internal packages wired to local paths /
	// workspace, alongside a git source that must stay remote.
	body := []byte(`
[project]
name = "app"
dependencies = ["common", "models", "shared", "fastapi>=0.127.0", "requests"]

[tool.uv.sources]
models = { path = "../models", editable = true }
common = { path = "../common", editable = true }
shared = { workspace = true }
somelib = { git = "https://github.com/x/somelib" }
`)
	out := map[string]struct{}{}
	collectLocalNames(body, out)

	for _, want := range []string{"models", "common", "shared"} {
		if _, ok := out[want]; !ok {
			t.Errorf("expected %q flagged local; got %v", want, keysOf(out))
		}
	}
	// git source and normal pypi deps are remote — never flagged.
	for _, notWant := range []string{"somelib", "fastapi", "requests"} {
		if _, ok := out[notWant]; ok {
			t.Errorf("%q is remote and must not be flagged local; got %v", notWant, keysOf(out))
		}
	}
}

func TestCollectLocalNames_UVSourceArray(t *testing.T) {
	// uv allows per-marker arrays of source tables; any local entry counts.
	body := []byte(`
[tool.uv.sources]
mixed = [
  { path = "../mixed", marker = "sys_platform == 'linux'" },
  { index = "pypi", marker = "sys_platform == 'win32'" },
]
remote = [
  { git = "https://github.com/x/remote" },
]
`)
	out := map[string]struct{}{}
	collectLocalNames(body, out)

	if _, ok := out["mixed"]; !ok {
		t.Errorf("array source with a path entry should be local; got %v", keysOf(out))
	}
	if _, ok := out["remote"]; ok {
		t.Errorf("array source with only remote entries must not be local; got %v", keysOf(out))
	}
}

func TestCollectLocalNames_PoetryPathDeps(t *testing.T) {
	body := []byte(`
[tool.poetry]
name = "app"

[tool.poetry.dependencies]
python = "^3.11"
internal = { path = "../internal", develop = true }
requests = "^2.31.0"
django = { git = "https://github.com/django/django.git" }
`)
	out := map[string]struct{}{}
	collectLocalNames(body, out)

	if _, ok := out["internal"]; !ok {
		t.Errorf("poetry path dep should be local; got %v", keysOf(out))
	}
	// python, a versioned dep, and a git dep are all remote/non-packages.
	for _, notWant := range []string{"python", "requests", "django"} {
		if _, ok := out[notWant]; ok {
			t.Errorf("%q must not be flagged local; got %v", notWant, keysOf(out))
		}
	}
}

func TestCollectLocalNames_NoSources(t *testing.T) {
	body := []byte(`
[project]
name = "app"
dependencies = ["requests", "flask"]
`)
	out := map[string]struct{}{}
	collectLocalNames(body, out)
	if len(out) != 0 {
		t.Errorf("no local sources declared; got %v", keysOf(out))
	}
}

func TestCollectLocalNames_MalformedIsIgnored(t *testing.T) {
	out := map[string]struct{}{}
	collectLocalNames([]byte("not = = valid toml"), out)
	if len(out) != 0 {
		t.Errorf("malformed manifest should yield nothing; got %v", keysOf(out))
	}
}

func TestMarkLocalPackages(t *testing.T) {
	pkgs := []Package{
		{Name: "common", Type: "pypi"},
		{Name: "Models", Type: "pypi"},   // canonicalised match despite casing
		{Name: "requests", Type: "pypi"}, // not local
		{Name: "common", Type: "npm"},    // same name, wrong ecosystem — untouched
	}
	local := map[string]struct{}{"common": {}, "models": {}}
	markLocalPackages(pkgs, local)

	if !pkgs[0].Local {
		t.Error("common (pypi) should be marked local")
	}
	if !pkgs[1].Local {
		t.Error("Models (pypi) should be marked local via canonical match")
	}
	if pkgs[2].Local {
		t.Error("requests should not be marked local")
	}
	if pkgs[3].Local {
		t.Error("npm common must not be marked local (pypi-only)")
	}
}

func TestMarkLocalPackages_EmptySet(t *testing.T) {
	pkgs := []Package{{Name: "common", Type: "pypi"}}
	markLocalPackages(pkgs, nil)
	if pkgs[0].Local {
		t.Error("empty local set should mark nothing")
	}
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
