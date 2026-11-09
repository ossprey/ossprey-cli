package precommit

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/catalog"
	"github.com/ossprey/ossprey-cli/internal/trust"
	"github.com/ossprey/ossprey-cli/internal/warn"
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
	// A developer's global core.hooksPath would run their hooks on these commits.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
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

// cargoLock renders a v4 Cargo.lock: the project's own root crate, then one entry per {name, version, source}.
func cargoLock(crates ...[3]string) string {
	var b strings.Builder
	b.WriteString("version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n")
	for _, c := range crates {
		fmt.Fprintf(&b, "\n[[package]]\nname = %q\nversion = %q\nsource = %q\n", c[0], c[1], c[2])
	}
	return b.String()
}

const (
	cratesIoSource = "registry+https://github.com/rust-lang/crates.io-index"
	forkCommit     = "0123456789abcdef0123456789abcdef01234567"
	forkSource     = "git+https://git.example.com/acme/forked-crate?branch=main#" + forkCommit
)

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
		{
			name: "new Cargo.lock: crates pinned, a git crate marked, the root crate left out",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "README.md", "# hi\n")
				commitAll(t, dir)
				writeRepoFile(t, dir, "Cargo.lock", cargoLock(
					[3]string{"serde", "1.0.228", cratesIoSource},
					[3]string{"forked-crate", "2.0.0", forkSource},
				))
				gitT(t, dir, "add", "Cargo.lock")
			},
			want: []Package{
				{Type: "cargo", Name: "forked-crate", Version: "2.0.0", Path: "Cargo.lock",
					Qualifiers: map[string]string{"vcs_url": "git+https://git.example.com/acme/forked-crate@" + forkCommit}},
				{Type: "cargo", Name: "serde", Version: "1.0.228", Path: "Cargo.lock"},
			},
		},
		{
			name: "a crate moved from git to crates.io at the same version is new",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, "Cargo.lock", cargoLock([3]string{"forked-crate", "2.0.0", forkSource}))
				commitAll(t, dir)
				writeRepoFile(t, dir, "Cargo.lock", cargoLock([3]string{"forked-crate", "2.0.0", cratesIoSource}))
				gitT(t, dir, "add", "Cargo.lock")
			},
			want: []Package{{Type: "cargo", Name: "forked-crate", Version: "2.0.0", Path: "Cargo.lock"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := initRepo(t)
			tc.setup(t, dir)
			got, err := StagedDelta(ctx, dir, trust.Policy{})
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

	got, err := StagedDelta(context.Background(), dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	want := []Package{{Type: "npm", Name: "is-odd", Version: "3.0.1", Path: "web/package-lock.json"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, want)
	}
}

func TestStagedDeltaReadsAnUnstagedCargoWorkspaceRoot(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, "Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\nserde = \"=1.0.228\"\nrand = \"=0.8.5\"\n")
	member := "[package]\nname = \"core\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { workspace = true }\n"
	writeRepoFile(t, dir, "crates/core/Cargo.toml", member)
	commitAll(t, dir)
	writeRepoFile(t, dir, "crates/core/Cargo.toml", member+"rand = { workspace = true }\n")
	gitT(t, dir, "add", "crates/core/Cargo.toml")

	ctx := warn.NewContext(context.Background(), false)
	got, err := StagedDelta(ctx, dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	want := []Package{{Type: "cargo", Name: "rand", Version: "0.8.5", Path: "crates/core/Cargo.toml"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, want)
	}
	if out := warn.Drain(ctx); out != "" {
		t.Errorf("a commit touching only a member warned:\n%s", out)
	}
}

// git reads ":0:../x" as stage 0 of a path outside the repo, so a directory named "0:.." must still read as a path.
func TestStagedDeltaReadsAPathThatLooksLikeAStage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a colon cannot be in a Windows file name")
	}
	dir := initRepo(t)
	writeRepoFile(t, dir, "README.md", "x")
	commitAll(t, dir)
	writeRepoFile(t, dir, "0:../a/Cargo.toml", "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n")
	gitT(t, dir, "add", "-A")
	got, err := StagedDelta(context.Background(), dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	want := []Package{{Type: "cargo", Name: "serde", Version: "1.0.228", Path: "0:../a/Cargo.toml"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, want)
	}
}

// cat-file reads one name per line, so a workspace root whose path holds a newline is sized on its own rather than skipped for the root above it.
func TestStagedDeltaReadsAWorkspaceRootWhosePathHoldsANewline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a newline cannot be in a Windows file name")
	}
	dir := initRepo(t)
	writeRepoFile(t, dir, "Cargo.toml", "[workspace]\n\n[workspace.dependencies]\nitoa = \"=1.0.10\"\n")
	writeRepoFile(t, dir, "a\nb/Cargo.toml", "[workspace]\nmembers = [\"m\"]\n\n[workspace.dependencies]\nitoa = \"=1.0.11\"\n")
	member := "[package]\nname = \"m\"\nversion = \"0.1.0\"\n\n[dependencies]\n"
	writeRepoFile(t, dir, "a\nb/m/Cargo.toml", member)
	commitAll(t, dir)
	writeRepoFile(t, dir, "a\nb/m/Cargo.toml", member+"itoa = { workspace = true }\n")
	gitT(t, dir, "add", "-A")
	got, err := StagedDelta(context.Background(), dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	want := []Package{{Type: "cargo", Name: "itoa", Version: "1.0.11", Path: "a\nb/m/Cargo.toml"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, want)
	}
}

// A name holding a newline that has no object is unsized, but one git fails to look up fails the call, since its root's pins would drop unseen.
func TestBlobSizesSkipsOnlyAMissingNameHoldingANewline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a newline cannot be in a Windows file name")
	}
	ctx := context.Background()
	dir := initRepo(t)
	writeRepoFile(t, dir, "a\nb/Cargo.toml", "[workspace]\n")
	commitAll(t, dir)
	present := []string{":0:a\nb/Cargo.toml", "HEAD:a\nb/Cargo.toml"}
	missing := []string{":0:x\ny/Cargo.toml", "HEAD:x\ny/Cargo.toml"}
	got, err := blobSizes(ctx, dir, append(slices.Clone(present), missing...))
	if err != nil {
		t.Fatalf("blobSizes: %v", err)
	}
	if len(got) != len(present) || got[present[0]].oid == "" || got[present[1]].oid == "" {
		t.Errorf("sized %+v, want %q alone", got, present)
	}
	// rev-parse exits 128 on a corrupt index, where a missing name exits 1.
	if err := os.WriteFile(filepath.Join(dir, ".git", "index"), []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := blobSizes(ctx, dir, missing[:1]); err == nil {
		t.Errorf("a failed lookup sized %+v with no error", got)
	}
}

// stagedRootDelta commits files, stages the root Cargo.toml as next, and returns the delta with any warnings.
func stagedRootDelta(t *testing.T, files map[string]string, next string) ([]Package, string) {
	t.Helper()
	dir := initRepo(t)
	for rel, content := range files {
		writeRepoFile(t, dir, rel, content)
	}
	commitAll(t, dir)
	writeRepoFile(t, dir, "Cargo.toml", next)
	gitT(t, dir, "add", "Cargo.toml")
	ctx := warn.NewContext(context.Background(), false)
	got, err := StagedDelta(ctx, dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	return got.Packages, warn.Drain(ctx)
}

func TestStagedDeltaChecksAPinChangedOnlyInAStagedCargoWorkspacePool(t *testing.T) {
	member := func(m string) string {
		return "[package]\nname = \"" + m + "\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { workspace = true }\nrand = { workspace = true }\n"
	}
	virtual := "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\nserde = \"=%s\"\nrand = \"=0.8.5\"\n"
	// An empty [workspace] still roots one, and a path dependency under it is a member Cargo adds on its own.
	implicit := "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nrand = { workspace = true }\nmylib = { path = \"mylib\" }\n\n[workspace]\n\n[workspace.dependencies]\nserde = \"=%s\"\nrand = \"=0.8.5\"\n"
	for name, tc := range map[string]struct {
		files map[string]string
		root  string
	}{
		"virtual root":          {map[string]string{"crates/a/Cargo.toml": member("a"), "crates/b/Cargo.toml": member("b")}, virtual},
		"empty workspace table": {map[string]string{"mylib/Cargo.toml": "[package]\nname = \"mylib\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { workspace = true }\n"}, implicit},
	} {
		t.Run(name, func(t *testing.T) {
			tc.files["Cargo.toml"] = fmt.Sprintf(tc.root, "1.0.228")
			got, warned := stagedRootDelta(t, tc.files, fmt.Sprintf(tc.root, "1.0.229"))
			want := []Package{{Type: "cargo", Name: "serde", Version: "1.0.229", Path: "Cargo.toml"}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got, want)
			}
			if warned != "" {
				t.Errorf("a root-only pin change warned:\n%s", warned)
			}
		})
	}
}

func TestStagedDeltaReportsNothingForACargoWorkspaceRootEditOutsideItsPool(t *testing.T) {
	member := "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { workspace = true }\n"
	pool := "\n[workspace.dependencies]\nserde = \"=1.0.228\"\n"
	got, warned := stagedRootDelta(t, map[string]string{
		"Cargo.toml":          "[workspace]\nmembers = [\"crates/a\"]\n\n[workspace.package]\nversion = \"0.1.0\"\n" + pool,
		"crates/a/Cargo.toml": member,
		// A crate the edit makes a member brings no new pin, since its own were already committed.
		"tools/x/Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nrand = \"=0.8.5\"\n",
	}, "[workspace]\nmembers = [\"crates/a\", \"tools/x\"]\n\n[workspace.package]\nversion = \"0.2.0\"\n"+pool)
	if len(got) != 0 || warned != "" {
		t.Errorf("a root edit outside the pool reported %+v, warned %q", got, warned)
	}
}

func TestStagedDeltaReportsNothingForAPathGitOrRegistryPoolEntryChange(t *testing.T) {
	root := "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\n" +
		"bar = { path = \"crates/bar\", version = \"=%[1]s\" }\n" +
		"foo = { git = \"https://github.com/example/foo\", version = \"=%[1]s\" }\n" +
		"baz = { version = \"=%[1]s\", registry = \"internal\" }\n" +
		"qux = { version = \"=%[1]s\", registry-index = \"sparse+https://cargo.example.com/index/\" }\n"
	member := "[package]\nname = \"a\"\nversion = \"0.1.0\"\n\n[dependencies]\nfoo = { workspace = true }\nbaz = { workspace = true }\nqux = { workspace = true }\n"
	got, warned := stagedRootDelta(t, map[string]string{
		"Cargo.toml":            fmt.Sprintf(root, "0.1.0"),
		"crates/a/Cargo.toml":   member,
		"crates/bar/Cargo.toml": "[package]\nname = \"bar\"\nversion = \"0.1.0\"\n",
	}, fmt.Sprintf(root, "0.2.0"))
	if len(got) != 0 || warned != "" {
		t.Errorf("a path, git or registry pool entry change reported %+v, warned %q", got, warned)
	}
}

// lockedCrates renders a Cargo.lock of crates.io crates, each {name, version, checksum}.
func lockedCrates(crates ...[3]string) string {
	var b strings.Builder
	b.WriteString("version = 4\n")
	for _, c := range crates {
		fmt.Fprintf(&b, "\n[[package]]\nname = %q\nversion = %q\nsource = %q\nchecksum = %q\n", c[0], c[1], cratesIoSource, c[2])
	}
	return b.String()
}

// vendorCrate writes dir as `cargo vendor` does: the crate's manifest, a marker recording sum, and the crate's own lock.
func vendorCrate(t *testing.T, repo, dir, name, version, sum, lock string) {
	t.Helper()
	writeRepoFile(t, repo, dir+"/Cargo.toml", fmt.Sprintf("[package]\nname = %q\nversion = %q\n", name, version))
	writeRepoFile(t, repo, dir+"/.cargo-checksum.json", `{"files":{},"package":"`+sum+`"}`)
	writeRepoFile(t, repo, dir+"/Cargo.lock", lock)
}

// appManifest is the Cargo.toml of the project that vendors.
const appManifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n"

// stageSymlink stages p as a symlink whose target text is target.
func stageSymlink(t *testing.T, dir, p, target string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(target)
	blob, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}
	gitT(t, dir, "update-index", "--add", "--cacheinfo", "120000,"+strings.TrimSpace(string(blob))+","+p)
}

// vendorConfig is the .cargo/config.toml `cargo vendor` prints, replacing crates.io with dir.
func vendorConfig(dir string) string {
	return "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"" + dir + "\"\n"
}

func TestStagedDeltaVendoredCrateLocks(t *testing.T) {
	sumOld, sumSerde, sumOther := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	devLock := lockedCrates([3]string{"criterion", "0.5.1", strings.Repeat("d", 64)})
	evilLock := lockedCrates([3]string{"evil-crate", "6.6.6", strings.Repeat("e", 64)})
	serdeBump := func(t *testing.T, dir, project, marker string) {
		writeRepoFile(t, dir, path.Join(project, "Cargo.toml"), appManifest)
		writeRepoFile(t, dir, path.Join(project, "Cargo.lock"), lockedCrates([3]string{"serde", "1.0.228", sumOld}))
		commitAll(t, dir)
		writeRepoFile(t, dir, path.Join(project, "Cargo.lock"), lockedCrates([3]string{"serde", "1.0.229", sumSerde}))
		vendorCrate(t, dir, path.Join(project, "vendor/serde"), "serde", "1.0.229", marker, devLock)
		gitT(t, dir, "add", "-A")
	}
	// plantedProject stages a nested project at tools/x with a marker matching the root lock's pin of x.
	plantedProject := func(t *testing.T, dir string) {
		writeRepoFile(t, dir, "Cargo.toml", appManifest)
		writeRepoFile(t, dir, "Cargo.lock", lockedCrates([3]string{"x", "1.0.0", sumSerde}))
		commitAll(t, dir)
		vendorCrate(t, dir, "tools/x", "x", "1.0.0", sumSerde, evilLock)
		gitT(t, dir, "add", "-A")
	}
	serde := Package{Type: "cargo", Name: "serde", Version: "1.0.229", Path: "Cargo.lock"}
	criterion := Package{Type: "cargo", Name: "criterion", Version: "0.5.1", Path: "vendor/serde/Cargo.lock"}
	plantedEvil := []Package{{Type: "cargo", Name: "evil-crate", Version: "6.6.6", Path: "tools/x/Cargo.lock"}}

	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  []Package
	}{
		{
			name: "a vendored crate's own lock is skipped and the project's lock still checked",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				serdeBump(t, dir, ".", sumSerde)
			},
			want: []Package{serde},
		},
		{
			name: "a marker whose checksum the project's lock does not pin skips nothing",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				serdeBump(t, dir, ".", sumOther)
			},
			want: []Package{criterion, serde},
		},
		{
			name: "a nested project's nearest config sets the vendor directory, relative to that project",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("third_party"))
				writeRepoFile(t, dir, "app/.cargo/config.toml", "[source.vendored-sources]\ndirectory = \"vendor\"\n")
				serdeBump(t, dir, "app", sumSerde)
			},
			want: []Package{{Type: "cargo", Name: "serde", Version: "1.0.229", Path: "app/Cargo.lock"}},
		},
		{
			name:  "a planted marker beside a nested project the root lock pins skips nothing without a cargo config",
			setup: plantedProject,
			want:  plantedEvil,
		},
		{
			name: "a planted marker beside a nested project outside the configured vendor directory skips nothing",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				plantedProject(t, dir)
			},
			want: plantedEvil,
		},
		{
			name: "a project lock nested past the bound proves nothing and does not crash the hook",
			setup: func(t *testing.T, dir string) {
				deep := strings.Repeat("[", 4<<20) + strings.Repeat("]", 4<<20)
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				writeRepoFile(t, dir, "Cargo.toml", appManifest)
				writeRepoFile(t, dir, "Cargo.lock", "deep = "+deep+"\n"+lockedCrates([3]string{"serde", "1.0.229", sumSerde}))
				commitAll(t, dir)
				vendorCrate(t, dir, "vendor/serde", "serde", "1.0.229", sumSerde, devLock)
				gitT(t, dir, "add", "-A")
			},
			want: []Package{criterion},
		},
		{
			name: "a marker at the repo root does not hide the root lock, even with a config vendoring into the root",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("."))
				commitAll(t, dir)
				vendorCrate(t, dir, ".", "app", "0.1.0", sumOther, lockedCrates([3]string{"app", "0.1.0", sumOther}, [3]string{"evil-crate", "6.6.6", sumOld}))
				gitT(t, dir, "add", "-A")
			},
			want: []Package{
				{Type: "cargo", Name: "app", Version: "0.1.0", Path: "Cargo.lock"},
				{Type: "cargo", Name: "evil-crate", Version: "6.6.6", Path: "Cargo.lock"},
			},
		},
		{
			name: "a marker copying a vendored crate's checksum does not hide a crate of another name",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				writeRepoFile(t, dir, "Cargo.toml", appManifest)
				writeRepoFile(t, dir, "Cargo.lock", lockedCrates([3]string{"serde", "1.0.229", sumSerde}))
				commitAll(t, dir)
				vendorCrate(t, dir, "vendor/x", "x", "1.0.229", sumSerde, evilLock)
				gitT(t, dir, "add", "-A")
			},
			want: []Package{{Type: "cargo", Name: "evil-crate", Version: "6.6.6", Path: "vendor/x/Cargo.lock"}},
		},
		{
			name: "a lock with no Cargo.toml beside it proves nothing, even with its own config",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				writeRepoFile(t, dir, "Cargo.toml", appManifest)
				writeRepoFile(t, dir, "tools/Cargo.lock", lockedCrates([3]string{"x", "1.0.0", sumSerde}))
				writeRepoFile(t, dir, "tools/.cargo/config.toml", vendorConfig("."))
				commitAll(t, dir)
				vendorCrate(t, dir, "tools/x", "x", "1.0.0", sumSerde, evilLock)
				gitT(t, dir, "add", "-A")
			},
			want: plantedEvil,
		},
		{
			name: "a lock in a directory holding a marker proves nothing",
			setup: func(t *testing.T, dir string) {
				vendorCrate(t, dir, "tools", "tools", "0.1.0", sumOther, lockedCrates([3]string{"x", "1.0.0", sumSerde}))
				writeRepoFile(t, dir, "tools/.cargo/config.toml", vendorConfig("."))
				commitAll(t, dir)
				vendorCrate(t, dir, "tools/x", "x", "1.0.0", sumSerde, evilLock)
				gitT(t, dir, "add", "-A")
			},
			want: plantedEvil,
		},
		{
			name: "a cargo config staged as a symlink proves nothing, though its target text vendors into tools",
			setup: func(t *testing.T, dir string) {
				plantedProject(t, dir)
				stageSymlink(t, dir, ".cargo/config.toml", vendorConfig("tools"))
			},
			want: plantedEvil,
		},
		{
			name: "a vendor directory with .. after a named directory proves nothing",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor/../tools"))
				plantedProject(t, dir)
			},
			want: plantedEvil,
		},
		{
			name: "a crate whose Cargo.toml declares [workspace] keeps its own lock checked, though it passes every other proof",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				writeRepoFile(t, dir, "Cargo.toml", appManifest)
				writeRepoFile(t, dir, "Cargo.lock", lockedCrates([3]string{"serde", "1.0.229", sumSerde}))
				commitAll(t, dir)
				vendorCrate(t, dir, "vendor/serde", "serde", "1.0.229", sumSerde, evilLock)
				writeRepoFile(t, dir, "vendor/serde/Cargo.toml", "[package]\nname = \"serde\"\nversion = \"1.0.229\"\n\n[workspace]\n\n[dependencies]\nevil-crate = \"6\"\n")
				gitT(t, dir, "add", "-A")
			},
			want: []Package{{Type: "cargo", Name: "evil-crate", Version: "6.6.6", Path: "vendor/serde/Cargo.lock"}},
		},
		{
			name: "an exact pin hand-added to a vendored manifest is still checked",
			setup: func(t *testing.T, dir string) {
				writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
				writeRepoFile(t, dir, "Cargo.toml", appManifest)
				writeRepoFile(t, dir, "Cargo.lock", lockedCrates([3]string{"serde", "1.0.229", sumSerde}))
				vendorCrate(t, dir, "vendor/serde", "serde", "1.0.229", sumSerde, devLock)
				commitAll(t, dir)
				writeRepoFile(t, dir, "vendor/serde/Cargo.toml", "[package]\nname = \"serde\"\nversion = \"1.0.229\"\n\n[dependencies]\nanyhow = \"=1.0.100\"\n")
				gitT(t, dir, "add", "-A")
			},
			want: []Package{{Type: "cargo", Name: "anyhow", Version: "1.0.100", Path: "vendor/serde/Cargo.toml"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := initRepo(t)
			tc.setup(t, dir)
			got, err := StagedDelta(context.Background(), dir, trust.Policy{})
			if err != nil {
				t.Fatalf("StagedDelta: %v", err)
			}
			if !reflect.DeepEqual(got.Packages, tc.want) {
				t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, tc.want)
			}
		})
	}
}

func TestStagedDeltaNeverReadsAProofLockOverItsBound(t *testing.T) {
	ctx := context.Background()
	sum := strings.Repeat("b", 64)
	dir := initRepo(t)
	writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
	writeRepoFile(t, dir, "Cargo.toml", appManifest)
	// A lock that would otherwise prove the vendored copy, one byte over the bound.
	writeRepoFile(t, dir, "Cargo.lock", padTOML(t, lockedCrates([3]string{"serde", "1.0.229", sum}), catalog.CargoProofLimit+1))
	commitAll(t, dir)
	vendorCrate(t, dir, "vendor/serde", "serde", "1.0.229", sum, lockedCrates([3]string{"criterion", "0.5.1", strings.Repeat("d", 64)}))
	gitT(t, dir, "add", "-A")
	oid, err := gitOutput(ctx, dir, "rev-parse", ":Cargo.lock")
	if err != nil {
		t.Fatal(err)
	}
	asked := logBlobReads(t)
	got, err := StagedDelta(ctx, dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	want := []Package{{Type: "cargo", Name: "criterion", Version: "0.5.1", Path: "vendor/serde/Cargo.lock"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, want)
	}
	if asked == nil {
		return
	}
	log := asked()
	if strings.TrimSpace(log) == "" {
		t.Fatal("the hook read no blob through git cat-file --batch")
	}
	if strings.Contains(log, strings.TrimSpace(string(oid))) {
		t.Errorf("the hook read the lock over the bound:\n%s", log)
	}
}

// logBlobReads puts a git on PATH that logs every name the hook's cat-file --batch is asked for, and returns the log so far.
func logBlobReads(t *testing.T) func() string {
	t.Helper()
	// The logging git is a shell script, so on Windows the caller checks the delta alone.
	if runtime.GOOS == "windows" {
		return nil
	}
	real, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin, log := t.TempDir(), filepath.Join(t.TempDir(), "asked")
	script := "#!/bin/sh\nif [ \"$3 $4\" = \"cat-file --batch\" ]; then tee -a '" + log + "' | '" + real + "' \"$@\"; else exec '" + real + "' \"$@\"; fi\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() string {
		data, _ := os.ReadFile(log)
		return string(data)
	}
}

// A cargo vendor commit holds a few files per crate, and a git per file took seconds, so every blob goes through one git.
func TestStagedDeltaReadsAVendoredCommitWithAFewGits(t *testing.T) {
	dir := initRepo(t)
	writeRepoFile(t, dir, ".cargo/config.toml", vendorConfig("vendor"))
	writeRepoFile(t, dir, "Cargo.toml", appManifest)
	var locked [][3]string
	for i := range 40 {
		name, sum := fmt.Sprintf("crate%d", i), fmt.Sprintf("%064x", i)
		vendorCrate(t, dir, "vendor/"+name, name, "1.0.0", sum, lockedCrates([3]string{"dev-only", "1.0.0", strings.Repeat("d", 64)}))
		locked = append(locked, [3]string{name, "1.0.0", sum})
	}
	writeRepoFile(t, dir, "Cargo.lock", lockedCrates(locked...))
	gitT(t, dir, "add", "-A")
	trace := filepath.Join(t.TempDir(), "trace")
	t.Setenv("GIT_TRACE", trace)
	got, err := StagedDelta(context.Background(), dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	// Every crate from the project's lock, and no vendored copy's own dev-only lock.
	if len(got.Packages) != 40 || slices.ContainsFunc(got.Packages, func(p Package) bool { return p.Name == "dev-only" }) {
		t.Errorf("delta: %+v", got.Packages)
	}
	log, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(log), "trace: built-in: git"); n > 10 {
		t.Errorf("read 40 vendored crates with %d gits, want a fixed few:\n%s", n, log)
	}
}

// A blob over its limit is refused without stopping the next read.
func TestBlobReaderRefusesABlobOverItsLimitAndReadsOn(t *testing.T) {
	ctx := context.Background()
	dir := initRepo(t)
	// Larger than a pipe's buffer, so git is still writing when the read stops.
	big, small := strings.Repeat("x", 1<<20), "small\n"
	writeRepoFile(t, dir, "big", big)
	writeRepoFile(t, dir, "small", small)
	gitT(t, dir, "add", "-A")
	blobs := &blobReader{ctx: ctx, repoDir: dir}
	defer blobs.close()
	if _, ok := blobs.read(":big", int64(len(big))-1); ok {
		t.Error("read a blob one byte over its limit")
	}
	if blob, ok := blobs.read(":small", 64); !ok || string(blob) != small {
		t.Errorf("after a refusal, read %q (ok %v), want %q", blob, ok, small)
	}
	if blob, ok := blobs.read(":big", int64(len(big))); !ok || string(blob) != big {
		t.Errorf("refused a blob at its limit (ok %v, %d bytes)", ok, len(blob))
	}
	if _, err := blobs.show(":absent"); err == nil {
		t.Error("showed a path the index does not hold")
	}
}

// padTOML pads s with comment lines to exactly n bytes.
func padTOML(t *testing.T, s string, n int) string {
	t.Helper()
	line := "#" + strings.Repeat(" ", 1022) + "\n"
	pad := n - len(s)
	s += strings.Repeat(line, pad/len(line))
	if r := pad % len(line); r > 0 {
		s += "#" + strings.Repeat(" ", r-1)
	}
	if len(s) != n {
		t.Fatalf("padded file is %d bytes, want %d", len(s), n)
	}
	return s
}

func TestStagedDeltaNeverReadsAWorkspaceRootOverItsBound(t *testing.T) {
	dir := initRepo(t)
	// A committed root whose pool the member inherits, one byte over the manifest bound.
	root := "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\nserde = \"=1.0.228\"\n"
	writeRepoFile(t, dir, "Cargo.toml", padTOML(t, root, catalog.CargoManifestLimit+1))
	member := "[package]\nname = \"core\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { workspace = true }\n"
	writeRepoFile(t, dir, "crates/core/Cargo.toml", member)
	commitAll(t, dir)
	writeRepoFile(t, dir, "crates/core/Cargo.toml", member+"tokio = \"=1.40.0\"\n")
	gitT(t, dir, "add", "crates/core/Cargo.toml")
	ctx := warn.NewContext(context.Background(), false)
	oid, err := gitOutput(ctx, dir, "rev-parse", ":Cargo.toml")
	if err != nil {
		t.Fatal(err)
	}
	trace := filepath.Join(t.TempDir(), "trace")
	t.Setenv("GIT_TRACE", trace)
	asked := logBlobReads(t)
	got, err := StagedDelta(ctx, dir, trust.Policy{})
	if err != nil {
		t.Fatalf("StagedDelta: %v", err)
	}
	want := []Package{{Type: "cargo", Name: "tokio", Version: "1.40.0", Path: "crates/core/Cargo.toml"}}
	if !reflect.DeepEqual(got.Packages, want) {
		t.Errorf("delta mismatch:\n got: %+v\nwant: %+v", got.Packages, want)
	}
	// As with an unreadable root, the inherited pin is skipped out loud.
	if out := warn.Drain(ctx); !strings.Contains(out, "workspace root could not be read") {
		t.Errorf("no warning for the inherited pin:\n%s", out)
	}
	log, err := os.ReadFile(trace)
	if err != nil || !strings.Contains(string(log), "cat-file --batch-check") {
		t.Fatalf("git trace holds no sizing call (%v):\n%s", err, log)
	}
	reads := ""
	if asked != nil {
		if reads = asked(); strings.TrimSpace(reads) == "" {
			t.Fatal("the hook read no blob through git cat-file --batch")
		}
	}
	for _, read := range []string{strings.TrimSpace(string(oid)), ":0:Cargo.toml", "HEAD:Cargo.toml"} {
		if strings.Contains(string(log), "show "+read) || slices.Contains(strings.Split(reads, "\n"), read) {
			t.Errorf("the hook read the root over the bound (%s):\n%s\n%s", read, log, reads)
		}
	}
}

func TestReadBlobStopsAtItsLimit(t *testing.T) {
	ctx := context.Background()
	dir := initRepo(t)
	// Larger than a pipe's buffer, so git is still writing when the read stops.
	content := strings.Repeat("x", 1<<20)
	writeRepoFile(t, dir, "f", content)
	gitT(t, dir, "add", "f")
	oid, err := gitOutput(ctx, dir, "rev-parse", ":f")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(oid))
	if _, ok := readBlob(ctx, dir, id, int64(len(content))-1); ok {
		t.Error("read a blob one byte over its limit")
	}
	if blob, ok := readBlob(ctx, dir, id, int64(len(content))); !ok || string(blob) != content {
		t.Errorf("refused a blob at its limit (ok %v, %d bytes)", ok, len(blob))
	}
}

// TestRepoRelLocation exercises every location spelling the resolvers are
// known to produce, on every platform — including the Windows-only forms that
// broke on CI (OSS-1564): the function is pure string work, so the
// Windows-shaped inputs run verbatim on unix.
func TestRepoRelLocation(t *testing.T) {
	// As in diffPackages: longest-first so nested manifests win.
	known := []string{"web/package-lock.json", "package-lock.json"}
	root := `C:\Users\RUNNER~1\AppData\Local\Temp\ossprey-precommit-1\staged`

	cases := []struct {
		name string
		locs []string
		want string
	}{
		{
			name: "posix scan-root-relative path",
			locs: []string{"package-lock.json"},
			want: "package-lock.json",
		},
		{
			name: "posix relative subdirectory path",
			locs: []string{"web/package-lock.json"},
			want: "web/package-lock.json",
		},
		{
			name: "windows absolute long-name path under a short-name MkdirTemp root",
			// GitHub runners set %TMP% to the 8.3 short form (RUNNER~1); the
			// resolver reports the long form. filepath.Rel between the two
			// produced ..-laden garbage — suffix matching must not care.
			locs: []string{`C:\Users\runneradmin\AppData\Local\Temp\ossprey-precommit-1\staged\package-lock.json`},
			want: "package-lock.json",
		},
		{
			name: "windows path with case-variant prefix",
			locs: []string{`C:\USERS\RunnerAdmin\AppData\Local\Temp\ossprey-precommit-1\staged\web\package-lock.json`},
			want: "web/package-lock.json",
		},
		{
			name: "posix-converted windows path (/c/... form)",
			locs: []string{"/c/Users/runneradmin/AppData/Local/Temp/ossprey-precommit-1/staged/package-lock.json"},
			want: "package-lock.json",
		},
		{
			name: "symlink-resolved root differing from MkdirTemp root",
			// e.g. macOS /var/folders vs /private/var/folders.
			locs: []string{"/private/var/folders/ab/T/ossprey-precommit-1/staged/web/package-lock.json"},
			want: "web/package-lock.json",
		},
		{
			name: "nested manifest prefers the longest known suffix",
			locs: []string{"staged/web/package-lock.json"},
			want: "web/package-lock.json",
		},
		{
			name: "dot-slash prefixed relative path",
			locs: []string{"./package-lock.json"},
			want: "package-lock.json",
		},
		{
			name: "empty locations",
			locs: nil,
			want: "",
		},
		{
			name: "unknown location falls back to slash-normalized trim",
			locs: []string{"something-else.json"},
			want: "something-else.json",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := repoRelLocation(tc.locs, root, known); got != tc.want {
				t.Errorf("repoRelLocation(%v) = %q, want %q", tc.locs, got, tc.want)
			}
		})
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
		{"Cargo.toml", true},
		{"crates/core/Cargo.lock", true},
		{"Cargo.toml.orig", false}, // cargo package's copy of the manifest, which no cataloger reads
	}
	for _, tc := range cases {
		if got := isManifestPath(tc.p); got != tc.want {
			t.Errorf("isManifestPath(%q) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

// A trusted package is neither in the delta nor sent to the malware check; it
// is counted so a verbose hook can say so.
func TestDiffPackagesLeavesTrustedOut(t *testing.T) {
	staged := []catalog.Package{
		{Type: "npm", Name: "@acme/web", Version: "1.0.0", Trusted: true},
		{Type: "npm", Name: "left-pad", Version: "1.3.0"},
	}
	got := diffPackages(staged, nil, t.TempDir(), nil)
	if len(got.Packages) != 1 || got.Packages[0].Name != "left-pad" || got.Trusted != 1 {
		t.Errorf("delta = %+v", got)
	}
}
