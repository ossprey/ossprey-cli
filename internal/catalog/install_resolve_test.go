package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/syft/file"
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

// npm marks each dependency's kind in the lock it writes, and the resolver
// carries the marks so an install that omits a kind can be checked as it
// installs. A release at several paths carries a kind only if every copy
// does, whichever copy the lock's map yields first.
func TestParseNpmLockCarriesDependencyKinds(t *testing.T) {
	lock := []byte(`{"lockfileVersion":3,"packages":{
		"": {"name":"p"},
		"node_modules/needed": {"version":"1.0.0","resolved":"https://registry.npmjs.org/needed/-/needed-1.0.0.tgz"},
		"node_modules/extra": {"version":"2.0.0","resolved":"https://registry.npmjs.org/extra/-/extra-2.0.0.tgz","optional":true},
		"node_modules/devonly": {"version":"3.0.0","resolved":"https://registry.npmjs.org/devonly/-/devonly-3.0.0.tgz","dev":true},
		"node_modules/both": {"version":"4.0.0","resolved":"https://registry.npmjs.org/both/-/both-4.0.0.tgz","devOptional":true},
		"node_modules/peer": {"version":"6.0.0","resolved":"https://registry.npmjs.org/peer/-/peer-6.0.0.tgz","peer":true},
		"node_modules/renamed": {"name":"left-pad","version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
		"node_modules/twice": {"version":"5.0.0","resolved":"https://registry.npmjs.org/twice/-/twice-5.0.0.tgz","optional":true},
		"node_modules/a/node_modules/twice": {"version":"5.0.0","resolved":"https://registry.npmjs.org/twice/-/twice-5.0.0.tgz"},
		"node_modules/b/node_modules/twice": {"version":"5.0.0","resolved":"https://registry.npmjs.org/twice/-/twice-5.0.0.tgz","optional":true},
		"node_modules/mixed": {"version":"1.0.0","resolved":"https://npm.acme.internal/mixed/-/mixed-1.0.0.tgz"},
		"node_modules/c/node_modules/mixed-alias": {"name":"mixed","version":"1.0.0","resolved":"https://registry.npmjs.org/mixed/-/mixed-1.0.0.tgz"},
		"node_modules/unresolved": {"version":"7.0.0"},
		"node_modules/member": {"resolved":"packages/member","link":true},
		"packages/member": {"version":"0.0.1"}}}`)
	type kinds struct {
		Registry                         string
		Dev, Optional, DevOptional, Peer bool
	}
	reg := func(name string) string { return "https://registry.npmjs.org/" + name }
	want := map[string]kinds{
		"needed": {Registry: reg("needed/-/needed-1.0.0.tgz")}, "extra": {Registry: reg("extra/-/extra-2.0.0.tgz"), Optional: true},
		"devonly": {Registry: reg("devonly/-/devonly-3.0.0.tgz"), Dev: true}, "both": {Registry: reg("both/-/both-4.0.0.tgz"), DevOptional: true},
		"twice": {Registry: reg("twice/-/twice-5.0.0.tgz")}, "peer": {Registry: reg("peer/-/peer-6.0.0.tgz"), Peer: true},
		// An alias is the real package, named by the entry, not its directory.
		"left-pad": {Registry: reg("left-pad/-/left-pad-1.3.0.tgz")},
		// Copies fetched from different registries record none: one public
		// copy is enough to need a check, whichever copy is read first.
		"mixed": {},
		// An installed package whose lock omits "resolved" (npm's
		// omit-lockfile-registry-resolved) is kept with no registry; a link
		// and the local package it points at are not.
		"unresolved": {},
	}
	// Map iteration order varies per run; the merge must not depend on it.
	for range 20 {
		pkgs, err := parseNpmLock(lock, file.Location{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]kinds{}
		for _, r := range resolvedFromPackages(pkgs, nil) {
			got[r.Name] = kinds{r.Registry, r.Dev, r.Optional, r.DevOptional, r.Peer}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("kinds = %v, want %v", got, want)
		}
	}
}

// Against a real npm: the kinds npm's effective omit policy leaves out,
// read as the command would read them — the project's .npmrc from its
// directory (optional=false counted as an omit), none in global mode, and
// an --include on the line winning over a configured omit.
func TestNpmConfigOmits(t *testing.T) {
	if _, err := lookTool("npm"); err != nil {
		t.Skip("no npm")
	}
	ctx := context.Background()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("optional=false\nomit[]=dev\n"), 0o644)
	got, err := NpmConfigOmits(ctx, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if !reflect.DeepEqual(got, []string{"dev", "optional"}) {
		t.Errorf("project omits = %v", got)
	}
	got, err = NpmConfigOmits(ctx, dir, []string{"--include=optional"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"dev"}) {
		t.Errorf("--include=optional over the project's optional=false: omits = %v", got)
	}
	got, err = NpmConfigOmits(ctx, dir, []string{"-g"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("global mode read the project's omits: %v", got)
	}
}

// `npm config get` answers for the command's own configuration: the
// project's .npmrc in local mode, not in global mode, and the default where
// nothing is configured.
func TestNpmConfigGet(t *testing.T) {
	if _, err := lookTool("npm"); err != nil {
		t.Skip("no npm")
	}
	ctx := context.Background()
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom-cache")
	os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("cache="+filepath.ToSlash(custom)+"\n"), 0o644)
	got, err := NpmConfigGet(ctx, dir, "cache", nil)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != custom {
		t.Errorf("project cache = %q, want %q", got, custom)
	}
	got, err = NpmConfigGet(ctx, dir, "cache", []string{"-g"})
	if err != nil {
		t.Fatal(err)
	}
	if got == "" || filepath.Clean(got) == custom {
		t.Errorf("global mode cache = %q, want npm's default", got)
	}
	// A relative cache, which `npm config get cache` refuses as protected,
	// is answered resolved against the directory npm runs in: from an
	// .npmrc and from the environment alike.
	os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("cache=./rel-cache\n"), 0o644)
	got, err = NpmConfigGet(ctx, dir, "cache", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFile(t, got, filepath.Join(dir, "rel-cache")) {
		t.Errorf("relative project cache = %q, want %q", got, filepath.Join(dir, "rel-cache"))
	}
	t.Setenv("npm_config_cache", "./env-cache")
	got, err = NpmConfigGet(ctx, dir, "cache", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFile(t, got, filepath.Join(dir, "env-cache")) {
		t.Errorf("relative environment cache = %q, want %q", got, filepath.Join(dir, "env-cache"))
	}
}

// sameFile compares two paths that need not exist, symlinks in their
// existing ancestors resolved (macOS /var, Windows short names).
func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	clean := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return filepath.Clean(p)
	}
	return clean(a) == clean(b)
}

// The npx cache key is libnpmexec's: known answers computed with node's
// crypto over the same sorted, newline-joined specs.
func TestNpxCacheKey(t *testing.T) {
	for _, tt := range []struct {
		packages []string
		want     string
	}{
		{[]string{"cowsay@1.6.0"}, "e3e1d528ee105f80"},
		{[]string{"b@1", "a@2"}, "e26dd66f86ee88a6"},
		{[]string{"cowsay"}, "8f497369b2d6166e"},
	} {
		if got := NpxCacheKey(tt.packages); got != tt.want {
			t.Errorf("NpxCacheKey(%v) = %s, want %s", tt.packages, got, tt.want)
		}
	}
}

// What an earlier npx run left in the cache is read back as a tree, aliases
// by their real name; no cache, no tree.
func TestNpxCachedTree(t *testing.T) {
	cache := t.TempDir()
	if got, err := NpxCachedTree(cache, []string{"cowsay@1.6.0"}); err != nil || got != nil {
		t.Fatalf("empty cache: %v, %v", got, err)
	}
	dir := filepath.Join(cache, "_npx", NpxCacheKey([]string{"cowsay@1.6.0"}))
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{
		"": {"name":"x"},
		"node_modules/cowsay": {"version":"1.6.0","resolved":"https://registry.npmjs.org/cowsay/-/cowsay-1.6.0.tgz"},
		"node_modules/old": {"name":"get-stdin","version":"8.0.0","resolved":"https://registry.npmjs.org/get-stdin/-/get-stdin-8.0.0.tgz"},
		"node_modules/skipped": {"version":"1.0.0","resolved":"https://registry.npmjs.org/skipped/-/skipped-1.0.0.tgz","optional":true}}}`), 0o644)
	read := func() map[string]string {
		t.Helper()
		got, err := NpxCachedTree(cache, []string{"cowsay@1.6.0"})
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]string{}
		for _, r := range got {
			names[r.Name] = r.Version
		}
		return names
	}
	// Without a node_modules to check against, the lock is read as written.
	if got := read(); !reflect.DeepEqual(got, map[string]string{"cowsay": "1.6.0", "get-stdin": "8.0.0", "skipped": "1.0.0"}) {
		t.Errorf("cached tree = %v", got)
	}
	// With one, only what the earlier run put on disk can run: a release the
	// lock records but its omit policy left out is not read.
	for _, d := range []string{"cowsay", "old"} {
		os.MkdirAll(filepath.Join(dir, "node_modules", d), 0o755)
	}
	if got := read(); !reflect.DeepEqual(got, map[string]string{"cowsay": "1.6.0", "get-stdin": "8.0.0"}) {
		t.Errorf("installed cached tree = %v", got)
	}
	if got, _ := NpxCachedTree(cache, []string{"cowsay@1.5.0"}); got != nil {
		t.Errorf("another request found the tree: %v", got)
	}
}

// Against a real npm: the tree a real `npx` run leaves is found under the
// key this package computes.
func TestNpxCachedTreeMatchesARealRun(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	npm, err := lookTool("npm")
	if err != nil {
		t.Skip("no npm")
	}
	cache := t.TempDir()
	npx := filepath.Join(filepath.Dir(npm), "npx")
	if _, err := os.Stat(npx); err != nil {
		t.Skip("no npx beside npm")
	}
	cmd := exec.Command(npx, "--yes", "--cache", cache, "cowsay@1.6.0", "hi")
	cmd.Env = toolEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("npx: %v: %s", err, out)
	}
	got, err := NpxCachedTree(cache, []string{"cowsay@1.6.0"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range got {
		if r.Name == "cowsay" && r.Version == "1.6.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("the real run's cache was not found: %v", got)
	}

	// Several packages are keyed in npm's sort order, which is not byte
	// order: `is_js` sorts before `is-odd` for npm and after it for bytes.
	cmd = exec.Command(npx, "--yes", "--cache", cache, "--package", "is-odd@3.0.1", "--package", "is_js@0.9.0", "--", "node", "-e", "")
	cmd.Env = toolEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("npx: %v: %s", err, out)
	}
	got, err = NpxCachedTree(cache, []string{"is-odd@3.0.1", "is_js@0.9.0"})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range got {
		names[r.Name+"@"+r.Version] = true
	}
	if !names["is-odd@3.0.1"] || !names["is_js@0.9.0"] {
		t.Errorf("the two-package run's cache was not found under npm's key: %v", got)
	}
}

// "==" compares versions as PEP 440 normalises them, not as strings; a
// spelling the specification does not describe is retained rather than
// skipped.
func TestPep440Equal(t *testing.T) {
	for _, tt := range []struct {
		want, have string
		equal      bool
	}{
		{"6.1.0", "6.1", true}, {"6.1", "6.1.0.0", true}, {"01.2", "1.2", true}, {"1.0", "1.1", false},
		{"1.0a1", "1.0-alpha1", true}, {"1.0rc1", "1.0c1", true}, {"1.0preview1", "1.0rc1", true}, {"1.0a", "1.0a0", true},
		{"1.0", "1.0.post0", false}, {"1.0.post1", "1.0-1", true}, {"1.0.rev1", "1.0.post1", true}, {"1.0preview1", "1.0rc1.post0", false},
		{"1.0.dev0", "1.0dev", true}, {"1.0", "1.0.dev0", false},
		{"2.0", "2.0+local", true}, {"2.0+local", "2.0+other", false}, {"2.0+a-b", "2.0+a.b", true}, {"2.0+local", "2.0", false},
		{"1.0+build.01", "1.0+build.1", true}, {"1.0+build.1", "1.0+build.10", false}, {"1.0+abc01", "1.0+abc1", false},
		{"1!1.0", "1.0", false}, {"0!1.0", "1.0", true}, {"V1.0", "1.0", true},
		{"weird", "1.0", true}, {"1.0", "weird", true},
	} {
		if got := pep440Equal(tt.want, tt.have); got != tt.equal {
			t.Errorf("pep440Equal(%q, %q) = %v, want %v", tt.want, tt.have, got, tt.equal)
		}
	}
}

// A tool run's resolution reads uv's configuration as the run does: the
// [pip] table, which `uv pip compile` would apply and uvx ignores, is
// stripped from a copy of the file the run reads.
func TestUVToolRunConfig(t *testing.T) {
	scratch := t.TempDir()
	withPip := filepath.Join(t.TempDir(), "custom.toml")
	os.WriteFile(withPip, []byte("index-url = \"https://top.example/simple\"\n\n[pip]\nindex-url = \"https://pip.example/simple\"\n"), 0o644)
	withoutPip := filepath.Join(t.TempDir(), "plain.toml")
	os.WriteFile(withoutPip, []byte("index-url = \"https://top.example/simple\"\n"), 0o644)
	t.Setenv("UV_CONFIG_FILE", filepath.Join(t.TempDir(), "absent.toml"))

	got, err := uvToolRunConfig([]string{"--offline", "--config-file", withPip}, scratch)
	if err != nil {
		t.Fatal(err)
	}
	stripped := filepath.Join(scratch, "uv.toml")
	if want := []string{"--offline", "--config-file", stripped}; !reflect.DeepEqual(got, want) {
		t.Errorf("flags = %v, want %v", got, want)
	}
	data, _ := os.ReadFile(stripped)
	if s := string(data); !strings.Contains(s, "top.example") || strings.Contains(s, "pip") {
		t.Errorf("stripped copy:\n%s", s)
	}
	for _, flags := range [][]string{
		{"--config-file=" + withoutPip},
		{"--no-config", "--config-file", withPip},
		{"--offline"},
	} {
		if got, err := uvToolRunConfig(flags, scratch); err != nil || !reflect.DeepEqual(got, flags) {
			t.Errorf("%v: flags = %v, err = %v, want unchanged", flags, got, err)
		}
	}
	// The file UV_CONFIG_FILE names is read when none is named on the line.
	t.Setenv("UV_CONFIG_FILE", withPip)
	if got, err := uvToolRunConfig([]string{"--offline"}, scratch); err != nil || !reflect.DeepEqual(got, []string{"--offline", "--config-file", stripped}) {
		t.Errorf("UV_CONFIG_FILE: flags = %v, err = %v", got, err)
	}

	// Discovered configuration is the user-level file over the system-level
	// one, merged as uv merges them: the user's value wins where both set
	// one, the rest is kept, and the [pip] table of either is dropped.
	t.Setenv("UV_CONFIG_FILE", "")
	sys, usr := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_DIRS", sys)
	t.Setenv("XDG_CONFIG_HOME", usr)
	os.MkdirAll(filepath.Join(sys, "uv"), 0o755)
	os.MkdirAll(filepath.Join(usr, "uv"), 0o755)
	os.WriteFile(filepath.Join(sys, "uv", "uv.toml"), []byte("index-url = \"https://sys.example/simple\"\npython-preference = \"managed\"\nextra-index-url = [\"https://sysextra.example/simple\"]\n\n[[index]]\nname = \"sysidx\"\nurl = \"https://sysidx.example/simple\"\n\n[pip]\nindex-url = \"https://syspip.example/simple\"\n"), 0o644)
	os.WriteFile(filepath.Join(usr, "uv", "uv.toml"), []byte("index-url = \"https://usr.example/simple\"\nextra-index-url = [\"https://usrextra.example/simple\"]\n\n[[index]]\nname = \"usridx\"\nurl = \"https://usridx.example/simple\"\n"), 0o644)
	got, err = uvToolRunConfig([]string{"--offline"}, scratch)
	if err != nil || !reflect.DeepEqual(got, []string{"--offline", "--config-file", stripped}) {
		t.Fatalf("discovered config: flags = %v, err = %v", got, err)
	}
	data, _ = os.ReadFile(stripped)
	if s := string(data); !strings.Contains(s, "usr.example") || !strings.Contains(s, "managed") || strings.Contains(s, "sys.example") || strings.Contains(s, "pip") {
		t.Errorf("merged copy:\n%s", s)
	}
	// Arrays are joined as uv joins them, the user's entries first: a plain
	// array and an array of tables alike.
	for _, pair := range [][2]string{{"usrextra.example", "sysextra.example"}, {"usridx", "sysidx"}} {
		u, y := strings.Index(string(data), pair[0]), strings.Index(string(data), pair[1])
		if u < 0 || y < 0 || u > y {
			t.Errorf("merged copy keeps %s before %s (at %d, %d):\n%s", pair[0], pair[1], u, y, data)
		}
	}
	// With no [pip] table anywhere the discovered files are still merged
	// and named, and with none at all an empty file is: a named file stops
	// uv discovering a project's configuration above scratch, which may sit
	// under a project when TMPDIR points inside one.
	os.WriteFile(filepath.Join(sys, "uv", "uv.toml"), []byte("python-preference = \"managed\"\n"), 0o644)
	if got, err := uvToolRunConfig([]string{"--offline"}, scratch); err != nil || !reflect.DeepEqual(got, []string{"--offline", "--config-file", stripped}) {
		t.Errorf("no [pip] anywhere: flags = %v, err = %v", got, err)
	}
	data, _ = os.ReadFile(stripped)
	if s := string(data); !strings.Contains(s, "managed") || !strings.Contains(s, "usr.example") {
		t.Errorf("merged copy without [pip]:\n%s", s)
	}
	os.Remove(filepath.Join(sys, "uv", "uv.toml"))
	os.Remove(filepath.Join(usr, "uv", "uv.toml"))
	inProject := filepath.Join(t.TempDir(), "proj", ".tmp", "scratch")
	os.MkdirAll(inProject, 0o755)
	os.WriteFile(filepath.Join(inProject, "..", "..", "uv.toml"), []byte("index-url = \"https://project.invalid/simple\"\n"), 0o644)
	empty := filepath.Join(inProject, "uv.toml")
	if got, err := uvToolRunConfig([]string{"--offline"}, inProject); err != nil || !reflect.DeepEqual(got, []string{"--offline", "--config-file", empty}) {
		t.Errorf("no configuration at all, scratch under a project: flags = %v, err = %v", got, err)
	}
	if data, err := os.ReadFile(empty); err != nil || strings.TrimSpace(string(data)) != "" {
		t.Errorf("empty named file: %q, %v", data, err)
	}

	// A relative UV_CONFIG_FILE is read against the directory uv runs in,
	// and the resolver runs in scratch: the file is named absolutely, with
	// or without a [pip] table, and a missing one is left for uv to report.
	here := t.TempDir()
	t.Chdir(here)
	os.WriteFile(filepath.Join(here, "rel.toml"), []byte("index-url = \"https://top.example/simple\"\n"), 0o644)
	t.Setenv("UV_CONFIG_FILE", "rel.toml")
	if got, err := uvToolRunConfig([]string{"--offline"}, scratch); err != nil || !reflect.DeepEqual(got, []string{"--offline", "--config-file", filepath.Join(here, "rel.toml")}) {
		t.Errorf("relative UV_CONFIG_FILE: flags = %v, err = %v", got, err)
	}
	os.WriteFile(filepath.Join(here, "rel.toml"), []byte("[pip]\nindex-url = \"https://pip.example/simple\"\n"), 0o644)
	if got, err := uvToolRunConfig([]string{"--offline"}, scratch); err != nil || !reflect.DeepEqual(got, []string{"--offline", "--config-file", stripped}) {
		t.Errorf("relative UV_CONFIG_FILE with [pip]: flags = %v, err = %v", got, err)
	}
	t.Setenv("UV_CONFIG_FILE", "absent.toml")
	if got, err := uvToolRunConfig([]string{"--offline"}, scratch); err != nil || !reflect.DeepEqual(got, []string{"--offline", "--config-file", filepath.Join(here, "absent.toml")}) {
		t.Errorf("missing relative UV_CONFIG_FILE: flags = %v, err = %v", got, err)
	}
}

// Configuration that changes what resolves, from the environment or a file
// uv reads, is reported; configuration that does not is not.
func TestUVConfigShapesResolution(t *testing.T) {
	for _, v := range uvResolutionEnv {
		t.Setenv(v, "")
	}
	t.Setenv("UV_CONFIG_FILE", "")
	sys, usr := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_DIRS", sys)
	t.Setenv("XDG_CONFIG_HOME", usr)
	os.MkdirAll(filepath.Join(usr, "uv"), 0o755)
	proj := t.TempDir()
	write := func(path, body string) {
		os.MkdirAll(filepath.Dir(path), 0o755)
		os.WriteFile(path, []byte(body), 0o644)
	}

	if UVConfigShapesResolution(nil, "") {
		t.Error("nothing configured: shapes")
	}
	t.Setenv("UV_INDEX_URL", "https://i.example/simple")
	if !UVConfigShapesResolution(nil, "") || !UVConfigShapesResolution([]string{"--no-config"}, "") {
		t.Error("UV_INDEX_URL: does not shape (--no-config stops files, not variables)")
	}
	t.Setenv("UV_INDEX_URL", "")

	write(filepath.Join(usr, "uv", "uv.toml"), "python-preference = \"managed\"\n")
	if !UVConfigShapesResolution(nil, "") {
		t.Error("user python-preference: does not shape")
	}
	write(filepath.Join(usr, "uv", "uv.toml"), "cache-dir = \"/tmp/c\"\n")
	if UVConfigShapesResolution(nil, "") {
		t.Error("user cache-dir only: shapes")
	}
	write(filepath.Join(usr, "uv", "uv.toml"), "[pip]\nindex-url = \"https://pip.example/simple\"\n")
	if !UVConfigShapesResolution(nil, "") {
		t.Error("user [pip] index-url: does not shape")
	}
	if UVConfigShapesResolution([]string{"--no-config"}, "") {
		t.Error("--no-config: the user file still shapes")
	}
	named := filepath.Join(t.TempDir(), "named.toml")
	write(named, "link-mode = \"copy\"\n")
	if UVConfigShapesResolution([]string{"--config-file", named}, "") {
		t.Error("--config-file names a harmless file, yet the user file shapes")
	}
	write(named, "[[index]]\nurl = \"https://i.example/simple\"\n")
	if !UVConfigShapesResolution([]string{"--config-file=" + named}, "") {
		t.Error("--config-file with [[index]]: does not shape")
	}
	if !UVConfigShapesResolution([]string{"--config-file", filepath.Join(t.TempDir(), "absent.toml")}, "") {
		t.Error("an unreadable file: does not shape (cannot be reproduced for pip)")
	}

	// A project's configuration counts for a named install at its
	// directory (uv.toml, or pyproject.toml's [tool.uv]), not for a tool run.
	write(filepath.Join(usr, "uv", "uv.toml"), "")
	write(filepath.Join(proj, "pyproject.toml"), "[project]\nname = \"x\"\n\n[tool.uv]\nextra-index-url = [\"https://i.example/simple\"]\n")
	sub := filepath.Join(proj, "src")
	os.MkdirAll(sub, 0o755)
	if !UVConfigShapesResolution(nil, proj) || !UVConfigShapesResolution(nil, sub) {
		t.Error("project [tool.uv] extra-index-url: does not shape")
	}
	if UVConfigShapesResolution(nil, "") {
		t.Error("tool run: the project file shapes")
	}
	write(filepath.Join(proj, "pyproject.toml"), "[project]\nname = \"x\"\n\n[tool.uv]\ndev-dependencies = []\n")
	if UVConfigShapesResolution(nil, proj) {
		t.Error("project [tool.uv] without resolution keys: shapes")
	}
	write(filepath.Join(proj, "uv.toml"), "resolution = \"lowest\"\n")
	if !UVConfigShapesResolution(nil, proj) {
		t.Error("project uv.toml resolution: does not shape")
	}
}

// Against a real uv: a [pip] index that would break `uv pip compile` does
// not reach a tool run's resolution, since uvx does not read it either.
func TestResolvePythonInstallWithUVReadsConfigAsAToolRun(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	if _, ok := lookupUV(context.Background()); !ok {
		t.Skip("no uv")
	}
	custom := filepath.Join(t.TempDir(), "custom.toml")
	os.WriteFile(custom, []byte("[pip]\nindex-url = \"https://pip.invalid/simple\"\n"), 0o644)
	got, err := ResolvePythonInstallWithUV(context.Background(), "", []string{"cowsay==6.1"}, []string{"--config-file", custom})
	if err != nil {
		if strings.Contains(err.Error(), "pip.invalid") {
			t.Fatalf("the [pip] index reached the tool run's resolution: %v", err)
		}
		t.Skipf("uv: %v", err)
	}
	found := false
	for _, r := range got {
		if canonicalPackageName(r.Name) == "cowsay" && r.Version == "6.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("cowsay 6.1 not resolved: %v", got)
	}
}

// uv's cached tool environments: two levels of hashed directories, each a
// venv whose site-packages (lib/pythonX.Y on POSIX, Lib on Windows) name
// the installed releases. Only an environment holding every wanted package
// at the pinned version counts, and names match as PyPI matches them.
func TestUVCachedTree(t *testing.T) {
	// Brackets in the cache path are path characters, not a glob class.
	cache := filepath.Join(t.TempDir(), "uv[1]")
	venv := func(path string, pkgs map[string]string, windows bool) {
		site := filepath.Join(path, "lib", "python3.13", "site-packages")
		if windows {
			site = filepath.Join(path, "Lib", "site-packages")
		}
		os.MkdirAll(site, 0o755)
		os.WriteFile(filepath.Join(path, "pyvenv.cfg"), []byte("uv = 0.11\n"), 0o644)
		for name, version := range pkgs {
			dir := filepath.Join(site, strings.ReplaceAll(name, "-", "_")+"-"+version+".dist-info")
			os.MkdirAll(dir, 0o755)
			os.WriteFile(filepath.Join(dir, "METADATA"), []byte("Metadata-Version: 2.1\nName: "+name+"\nVersion: "+version+"\n\nbody\n"), 0o644)
		}
	}
	envs := filepath.Join(cache, "environments-v2")
	venv(filepath.Join(envs, "k1", "e1"), map[string]string{"CowSay": "6.1", "six": "1.16.0"}, false)
	venv(filepath.Join(envs, "k2", "e2"), map[string]string{"cowsay": "6.1", "six": "1.17.0", "rich": "13.0.0"}, true)
	venv(filepath.Join(envs, "k3", "e3"), map[string]string{"cowsay": "6.0", "six": "1.15.0"}, false)
	venv(filepath.Join(envs, "k4", "e4"), map[string]string{"ruff": "0.6.0"}, false)
	os.MkdirAll(filepath.Join(envs, "k5", "notavenv"), 0o755)
	// A damaged environment (sorted first) hides only itself: its METADATA
	// is a directory, which cannot be read. One with a single unreadable
	// dist-info beside a readable one still reports the readable one.
	venv(filepath.Join(envs, "k0", "e0"), map[string]string{"cowsay": "6.1"}, false)
	os.RemoveAll(filepath.Join(envs, "k0", "e0", "lib", "python3.13", "site-packages", "cowsay-6.1.dist-info", "METADATA"))
	os.MkdirAll(filepath.Join(envs, "k0", "e0", "lib", "python3.13", "site-packages", "cowsay-6.1.dist-info", "METADATA"), 0o755)
	venv(filepath.Join(envs, "k6", "e6"), map[string]string{"cowsay": "6.1", "broken": "1.0"}, false)
	os.RemoveAll(filepath.Join(envs, "k6", "e6", "lib", "python3.13", "site-packages", "broken-1.0.dist-info", "METADATA"))
	os.MkdirAll(filepath.Join(envs, "k6", "e6", "lib", "python3.13", "site-packages", "broken-1.0.dist-info", "METADATA"), 0o755)

	names := func(rs []Resolved) []string {
		var out []string
		for _, r := range rs {
			out = append(out, canonicalPackageName(r.Name)+"@"+r.Version)
		}
		slices.Sort(out)
		return out
	}
	got, err := UVCachedTree(cache, map[string]string{"cowsay": "6.1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cowsay@6.1", "rich@13.0.0", "six@1.16.0", "six@1.17.0"}; !reflect.DeepEqual(names(got), want) {
		t.Errorf("cowsay==6.1: %v, want %v", names(got), want)
	}
	got, err = UVCachedTree(cache, map[string]string{"cowsay": "", "rich": ""})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cowsay@6.1", "rich@13.0.0", "six@1.17.0"}; !reflect.DeepEqual(names(got), want) {
		t.Errorf("cowsay --with rich: %v, want %v", names(got), want)
	}
	if got, err := UVCachedTree(cache, map[string]string{"cowsay": "5.0"}); err != nil || got != nil {
		t.Errorf("unheld version: %v, %v", got, err)
	}
	// A pin is matched as PEP 440 reads it: ==6.1.0 is the 6.1 installed.
	got, err = UVCachedTree(cache, map[string]string{"cowsay": "6.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cowsay@6.1", "rich@13.0.0", "six@1.16.0", "six@1.17.0"}; !reflect.DeepEqual(names(got), want) {
		t.Errorf("cowsay==6.1.0: %v, want %v", names(got), want)
	}
	if got, err := UVCachedTree(filepath.Join(cache, "missing"), map[string]string{"cowsay": ""}); err != nil || got != nil {
		t.Errorf("no cache: %v, %v", got, err)
	}
}

// `uv tool install` keeps a venv per tool under the tool directory, found
// by the tool's canonical name; a tool not installed there is nil.
func TestUVInstalledTree(t *testing.T) {
	tools := t.TempDir()
	env := filepath.Join(tools, "cow-say")
	site := filepath.Join(env, "lib", "python3.13", "site-packages")
	os.MkdirAll(site, 0o755)
	os.WriteFile(filepath.Join(env, "pyvenv.cfg"), []byte("uv = 0.11\n"), 0o644)
	os.WriteFile(filepath.Join(env, "uv-receipt.toml"), []byte("[tool]\n"), 0o644)
	// Core metadata field names are case-insensitive: one distribution
	// spells them in lowercase, the other in upper.
	for name, version := range map[string]string{"Cow-Say": "6.0", "six": "1.15.0"} {
		d := filepath.Join(site, strings.ReplaceAll(name, "-", "_")+"-"+version+".dist-info")
		os.MkdirAll(d, 0o755)
		header := "name: " + name + "\nversion: " + version + "\n\n"
		if name == "six" {
			header = "Metadata-Version: 2.1\nNAME: " + name + "\nVERSION: " + version + "\n\n"
		}
		os.WriteFile(filepath.Join(d, "METADATA"), []byte(header), 0o644)
	}
	got, err := UVInstalledTree(tools, "Cow_Say")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, r := range got {
		names[canonicalPackageName(r.Name)] = r.Version
	}
	if want := map[string]string{"cow-say": "6.0", "six": "1.15.0"}; !reflect.DeepEqual(names, want) {
		t.Errorf("installed tree = %v, want %v", names, want)
	}
	if got, err := UVInstalledTree(tools, "ruff"); err != nil || got != nil {
		t.Errorf("tool not installed: %v, %v", got, err)
	}
	if got, err := UVInstalledTree(filepath.Join(tools, "missing"), "cowsay"); err != nil || got != nil {
		t.Errorf("no tool dir: %v, %v", got, err)
	}
}

// Against a real uv: an installed tool's environment is found under the
// tool directory uv reports, by the tool's name.
func TestUVInstalledTreeMatchesARealInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	uv, err := lookTool("uv")
	if err != nil {
		t.Skip("no uv")
	}
	tools := t.TempDir()
	t.Setenv("UV_TOOL_DIR", tools)
	t.Setenv("UV_TOOL_BIN_DIR", t.TempDir()) // the install links an executable; not into the host's bin
	if got, err := UVToolDir(context.Background(), nil); err != nil || filepath.Clean(got) != tools {
		t.Errorf("uv tool dir: %q, %v", got, err)
	}
	cmd := exec.Command(uv, "tool", "install", "--cache-dir", t.TempDir(), "cowsay==6.0")
	cmd.Env = toolEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("uv tool install: %v: %s", err, out)
	}
	got, err := UVInstalledTree(tools, "cowsay")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range got {
		if canonicalPackageName(r.Name) == "cowsay" && r.Version == "6.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("the installed tool's environment was not found: %v", got)
	}
}

// Against a real uv: a tool run leaves an environment the lookup finds under
// the cache it was told to use, and `uv cache dir` reports that cache.
func TestUVCachedTreeMatchesARealRun(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	uv, err := lookTool("uv")
	if err != nil {
		t.Skip("no uv")
	}
	cache := t.TempDir()
	// uv rejects an empty UV_CACHE_DIR outright, so the variable is unset
	// rather than blanked; t.Setenv restores whatever the host had.
	t.Setenv("UV_CACHE_DIR", "unset-below")
	os.Unsetenv("UV_CACHE_DIR")
	if got, err := UVCacheDir(context.Background(), []string{"--cache-dir", cache}); err != nil || filepath.Clean(got) != cache {
		t.Errorf("uv cache dir --cache-dir: %q, %v", got, err)
	}
	// A cache-dir in an explicitly named configuration file is where the
	// run reuses from; one in the working directory's uv.toml is not, since
	// a tool run reads no project configuration.
	custom := filepath.Join(t.TempDir(), "custom.toml")
	os.WriteFile(custom, []byte("cache-dir = \""+filepath.ToSlash(filepath.Join(cache, "custom"))+"\"\n"), 0o644)
	if got, err := UVCacheDir(context.Background(), []string{"--config-file", custom}); err != nil || filepath.Clean(got) != filepath.Join(cache, "custom") {
		t.Errorf("uv cache dir --config-file: %q, %v", got, err)
	}
	project := t.TempDir()
	os.WriteFile(filepath.Join(project, "uv.toml"), []byte("cache-dir = \"./project-cache\"\n"), 0o644)
	t.Chdir(project)
	if got, err := UVCacheDir(context.Background(), nil); err != nil || strings.Contains(got, "project-cache") {
		t.Errorf("uv cache dir read the working directory's uv.toml: %q, %v", got, err)
	}
	cmd := exec.Command(uv, "tool", "run", "--cache-dir", cache, "--from", "cowsay==6.1", "cowsay", "-t", "hi")
	cmd.Env = toolEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("uv tool run: %v: %s", err, out)
	}
	got, err := UVCachedTree(cache, map[string]string{"cowsay": "6.1"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range got {
		if canonicalPackageName(r.Name) == "cowsay" && r.Version == "6.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("the real run's environment was not found: %v", got)
	}
}

// npm sorts the specs with node's localeCompare('en'); the port is held to
// the installed node over every printable ASCII character and a set of
// specs that tell byte order and collation apart.
func TestNpmCollateMatchesNode(t *testing.T) {
	node, err := lookTool("node")
	if err != nil {
		t.Skip("no node")
	}
	var chars []string
	for c := ' '; c < 127; c++ {
		chars = append(chars, string(c))
	}
	specs := []string{"a-b", "a_b", "a.b", "ab", "a b", "aB", "Ab", "AB", "a1", "a@1", "@s/x", "@s-x",
		"a-b@1.0.0", "a_b@1.0.0", "x", "x-", "x_", "x.", "x0", "xa", "xA", "X", "b", "B", "a--b", "a-_b",
		"a_-b", "left-pad", "left_pad", "is-odd", "is_js", "lodash._baseuniq", "lodash-es", "-a", "_a",
		".a", "~a", "a~", "a^1", "a>1", "a=1", "a<1", "a|1", "a$", "a#", "a%", "a&", "a*", "a+", "a,b",
		"a;b", "a:b", "a!b", "a?b", "a/b", "a\\b", "a(b", "a)b", "a[b", "a]b", "a{b", "a}b", "a`b",
		"a\"b", "a'b", "cowsay@1.6.0", "cowsay@latest", "cowsay", "@scope/tool@^2", "tool@>=1 <2"}
	for _, in := range [][]string{chars, specs} {
		input, _ := json.Marshal(in)
		cmd := exec.Command(node, "-e", `process.stdout.write(JSON.stringify(JSON.parse(process.argv[1]).sort((a, b) => a.localeCompare(b, "en"))))`, string(input))
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		if err := json.Unmarshal(out, &want); err != nil {
			t.Fatal(err)
		}
		got := slices.Clone(in)
		slices.SortFunc(got, npmCollate)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("collation differs from node:\n got %q\nwant %q", got, want)
		}
	}
}
