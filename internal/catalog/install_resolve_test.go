package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

// The staged copy of a project resolves from registries alone: dependencies
// npm could only find on the project's disk, and the workspaces that name
// its directories, are not there.
func TestLocalFreePackageJSON(t *testing.T) {
	in := `{
		"name": "app", "workspaces": ["packages/*"],
		"dependencies": {"express": "^5", "shared": "file:../shared", "ui": "workspace:*", "tool": "link:./tool"},
		"devDependencies": {"jest": "^29", "local": "./local"},
		"peerDependencies": {"react": "*"}
	}`
	out, err := localFreePackageJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["workspaces"]; ok {
		t.Error("workspaces kept")
	}
	want := map[string]any{"express": "^5"}
	if got := doc["dependencies"]; !reflect.DeepEqual(got, want) {
		t.Errorf("dependencies = %v, want %v", got, want)
	}
	if got := doc["devDependencies"]; !reflect.DeepEqual(got, map[string]any{"jest": "^29"}) {
		t.Errorf("devDependencies = %v", got)
	}
	if got := doc["peerDependencies"]; !reflect.DeepEqual(got, map[string]any{"react": "*"}) {
		t.Errorf("peerDependencies = %v", got)
	}
}

func TestIsLocalNpmSpec(t *testing.T) {
	for spec, want := range map[string]bool{
		"^5.0.0": false, "latest": false, "npm:other@1": false, "github:a/b": false,
		"https://x/y.tgz": false, "file:../a": true, "link:./a": true, "workspace:*": true,
		"portal:./a": true, "./a": true, "../a": true, "/abs": true, "~/a": true, ".": true,
	} {
		if got := isLocalNpmSpec(spec); got != want {
			t.Errorf("%q: got %v, want %v", spec, got, want)
		}
	}
}

// A package the project's lockfile already named comes back Locked; a git
// dependency, which no registry can be asked about, is dropped.
func TestResolvedFromPackages(t *testing.T) {
	pkgs := []pkg.Package{
		{Name: "express", Version: "5.1.0", Metadata: registrySource{URL: "https://registry.npmjs.org/express/-/express-5.1.0.tgz"}},
		{Name: "accepts", Version: "2.0.0", Metadata: registrySource{URL: "https://registry.npmjs.org/accepts/-/accepts-2.0.0.tgz"}},
		{Name: "fork", Version: "1.0.0", Metadata: registrySource{URL: "git+ssh://git@github.com/a/fork.git#abc"}},
	}
	got := resolvedFromPackages(pkgs, map[string]bool{"accepts@2.0.0": true})
	want := []Resolved{
		{Name: "express", Version: "5.1.0", Registry: "https://registry.npmjs.org/express/-/express-5.1.0.tgz"},
		{Name: "accepts", Version: "2.0.0", Registry: "https://registry.npmjs.org/accepts/-/accepts-2.0.0.tgz", Locked: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// A resolver's failure is one line, with the tool's own output kept apart.
func TestResolveFailure(t *testing.T) {
	head, detail := ResolveFailure(newToolError("uv", "resolve",
		"warning: deprecated thing\n  × No solution found when resolving dependencies:\n  ╰─▶ Because x was not found"))
	if head != "uv: × No solution found when resolving dependencies:" {
		t.Errorf("headline = %q", head)
	}
	if len(detail) != 3 {
		t.Errorf("detail = %v", detail)
	}
	head, detail = ResolveFailure(errors.New("plain"))
	if head != "plain" || detail != nil {
		t.Errorf("plain error: got %q, %v", head, detail)
	}
}

// Against a real npm and registry: resolving in a project's context keeps the
// versions its lockfile pins and marks what it already had, so only what the
// install adds is new; a project with no lockfile resolves the whole tree.
func TestResolveNpmInstallUsesTheProjectLockfile(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	if _, err := lookTool("npm"); err != nil {
		t.Skip("no npm")
	}
	ctx := context.Background()

	// A project that already locks is-number at 6.0.0, with a local dep npm
	// could not find from the copy.
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"app","version":"1.0.0","dependencies":{"is-number":"6.0.0","shared":"file:../shared"}}`)
	write("package-lock.json", `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
		"": {"name":"app","version":"1.0.0","dependencies":{"is-number":"6.0.0"}},
		"node_modules/is-number": {"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz","integrity":"sha512-Wu1VHeILBK8KAWJUAiSZQX94GmOE45Rg6/538fKwiloUNqMK8Vzsl1CuMwkT7Dbko9jncHE5mvTKLZCTz1Lz/g=="}}}`)

	got, err := ResolveNpmInstall(ctx, dir, "", []string{"is-odd@3.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Resolved{}
	for _, r := range got {
		byName[r.Name] = r
	}
	if r := byName["is-odd"]; r.Version != "3.0.1" || r.Locked {
		t.Errorf("is-odd = %+v, want 3.0.1 and not locked", r)
	}
	if r := byName["is-number"]; r.Version != "6.0.0" || !r.Locked {
		t.Errorf("is-number = %+v, want the locked 6.0.0", r)
	}
	if _, ok := byName["shared"]; ok {
		t.Error("the local dependency was resolved")
	}

	// No project: the named package and its tree, nothing locked.
	got, err = ResolveNpmInstall(ctx, "", "", []string{"is-odd@3.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, r := range got {
		if r.Locked || !strings.HasPrefix(r.Registry, "https://") {
			t.Errorf("unexpected %+v", r)
		}
		names = append(names, r.Name+"@"+r.Version)
	}
	for _, want := range []string{"is-odd@3.0.1", "is-number@6.0.0"} {
		if !contains(names, want) {
			t.Errorf("missing %s in %v", want, names)
		}
	}
}

// With no working uv, a uv command that adds an index is not resolved by
// pip in its place: pip picks releases by a different rule, so the caller
// gets ErrNeedsUV and checks the names.
func TestResolvePythonInstallWithUVNeedsUV(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	got, err := ResolvePythonInstallWithUV(context.Background(), t.TempDir(), []string{"ruff"}, []string{"--index", "https://i.example"})
	if !errors.Is(err, ErrNeedsUV) || got != nil {
		t.Errorf("got %v, %v; want ErrNeedsUV", got, err)
	}
}

// Against a real uv: a tool run is resolved with no project configuration,
// as uvx runs with none, so a uv.toml in the working directory that `uv pip
// compile` would otherwise read — here pointing at an index that does not
// exist — changes nothing. The project-aware form reads it and fails.
func TestResolvePythonInstallWithUVIgnoresProjectConfigWithoutADir(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	ctx := context.Background()
	if _, ok := lookupUV(ctx); !ok {
		t.Skip("no uv")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "uv.toml"), []byte("index-url = \"https://ossprey-no-such-index.invalid/simple\"\n"), 0o644)
	t.Chdir(dir)

	got, err := ResolvePythonInstallWithUV(ctx, "", []string{"cowsay==6.1"}, nil)
	if err != nil || len(got) == 0 {
		t.Fatalf("tool run read the project's uv.toml: %v, %v", got, err)
	}
	if _, err := ResolvePythonInstallWithUV(ctx, ".", []string{"cowsay==6.1"}, nil); err == nil {
		t.Error("the project-aware resolve ignored uv.toml, so this test proves nothing")
	}
}

// Against a real resolver: the Python tree for a named requirement, extras
// included, with nothing built.
func TestResolvePythonInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	got, err := ResolvePythonInstall(context.Background(), t.TempDir(), []string{"requests[socks]==2.32.3"}, nil, nil)
	if errors.Is(err, ErrNoResolver) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, r := range got {
		names = append(names, r.Name)
	}
	for _, want := range []string{"requests", "urllib3", "pysocks"} {
		if !contains(names, want) {
			t.Errorf("missing %s in %v", want, names)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// The .npmrc where the command runs is staged with or without a project, so
// a scoped private registry reaches the dry run for `npx @org/cli` and
// `npm install -g` as it reaches npm itself.
func TestStageNpmrc(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	if err := stageNpmrc(src, dst); err != nil {
		t.Fatalf("no .npmrc: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, ".npmrc")); err == nil {
		t.Error("an .npmrc was staged from nothing")
	}
	os.WriteFile(filepath.Join(src, ".npmrc"), []byte("@acme:registry=https://npm.acme.internal/\n"), 0o600)
	if err := stageNpmrc(src, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dst, ".npmrc"))
	if err != nil || !strings.Contains(string(got), "npm.acme.internal") {
		t.Errorf("staged .npmrc = %q, %v", got, err)
	}
}
