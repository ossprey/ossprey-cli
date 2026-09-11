package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// PipCataloger resolves transitive Python deps by running
// `pip install --dry-run --report`, which resolves the full transitive tree and
// writes it as JSON without installing anything.
//
// It is the fallback for the uv catalogers, and Catalog builds it only for a
// host with no uv (uv is faster, and resolves universally across platforms
// rather than for the running interpreter alone). Without it such a host
// degrades silently to PyProjectCataloger — direct dependencies only, every
// unpinned one left versionless. pip ships with essentially every Python
// installation, including GitHub-hosted runners, so the fallback closes that gap
// for the common case.
type PipCataloger struct {
	root string
}

func NewPipCataloger(root string) *PipCataloger { return &PipCataloger{root: root} }

func (c *PipCataloger) Name() string { return "ossprey-pip-cataloger" }

// pipMinimum is the oldest pip that understands `--dry-run` and `--report`
// (both landed in 22.2). Older pips would treat them as unknown options and
// fail every manifest identically, so we check once and skip instead.
var pipMinimum = pipVersion{major: 22, minor: 2}

func (c *PipCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	python, ok := findPython(ctx)
	if !ok {
		warnNoPythonResolver(resolver, "no Python interpreter on PATH")
		return nil, nil, nil
	}
	if v, ok := pipReportVersion(ctx, python); !ok {
		warnNoPythonResolver(resolver, python+" has no usable pip")
		return nil, nil, nil
	} else if v.olderThan(pipMinimum) {
		warnNoPythonResolver(resolver, fmt.Sprintf("pip %s is older than %s (needs --dry-run --report)", v, pipMinimum))
		return nil, nil, nil
	}

	cache, err := os.MkdirTemp("", "ossprey-pip-cache-")
	if err != nil {
		return nil, nil, fmt.Errorf("pip cache: %w", err)
	}
	defer os.RemoveAll(cache)

	// requirements.txt goes to pip as-is: pip honours the `-r` includes,
	// index URLs and constraints declared inside it, exactly as an install would.
	reqParse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		return runPipResolve(ctx, python, cache, filepath.Dir(absPath), []string{"-r", absPath}, loc)
	}
	reqs, err := catalogByGlob(ctx, resolver, c.root, "**/requirements.txt", "pip", reqParse)
	if err != nil {
		return nil, nil, err
	}

	// pyproject.toml is resolved from its *parsed* requirement strings, never by
	// pointing pip at the project directory. `pip install --dry-run .` builds the
	// project's metadata, which executes its PEP 517 backend (setup.py, hatch
	// hooks) — code from the very tree we are scanning for malware.
	projParse := func(absPath string, loc file.Location) ([]pkg.Package, error) {
		specs, err := pyprojectRequirementSpecs(absPath)
		if err != nil || len(specs) == 0 {
			return nil, err
		}
		reqFile := filepath.Join(cache, "req-"+requirementsFileID(absPath)+".txt")
		if err := os.WriteFile(reqFile, []byte(strings.Join(specs, "\n")+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("pip %s: write requirements: %w", absPath, err)
		}
		return runPipResolve(ctx, python, cache, filepath.Dir(absPath), []string{"-r", reqFile}, loc)
	}
	projs, err := catalogByGlob(ctx, resolver, c.root, "**/pyproject.toml", "pip", projParse)
	if err != nil {
		return nil, nil, err
	}

	return append(reqs, projs...), nil, nil
}

// pyprojectRequirementSpecs returns the PEP 508 requirement strings declared in
// a pyproject.toml's [project] table, which pip accepts verbatim.
//
// [tool.poetry.dependencies] is deliberately not converted: poetry's caret and
// tilde shorthand is not PEP 508, so feeding it to pip would fail the whole
// manifest. That matches uv, whose `pip compile` reads [project] too — a
// poetry-only project is covered by its poetry.lock via syft instead.
func pyprojectRequirementSpecs(path string) ([]string, error) {
	pp, err := readPyProject(path)
	if err != nil || pp == nil {
		return nil, err
	}
	rootName := canonicalPackageName(pp.Project.Name)
	seen := map[string]struct{}{}
	var out []string
	add := func(spec string) {
		spec = strings.TrimSpace(spec)
		if spec == "" || strings.HasPrefix(spec, "#") {
			return
		}
		name, _ := parsePEP508(spec)
		// A project listing itself (a self-referential extra) would make pip
		// resolve the project as a registry package.
		if name == "" || canonicalPackageName(name) == rootName {
			return
		}
		if _, ok := seen[spec]; ok {
			return
		}
		seen[spec] = struct{}{}
		out = append(out, spec)
	}
	for _, dep := range pp.Project.Dependencies {
		add(dep)
	}
	for _, group := range pp.Project.OptionalDependencies {
		for _, dep := range group {
			add(dep)
		}
	}
	return out, nil
}

// requirementsFileID gives each manifest a distinct temp-requirements name.
// Manifests are resolved concurrently and every monorepo has many files called
// pyproject.toml, so the name has to come from the full path.
func requirementsFileID(path string) string {
	var b strings.Builder
	for _, r := range filepath.ToSlash(path) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// runPipResolve resolves one manifest and parses pip's installation report.
//
// pip is invoked as `<python> -m pip`, never as the `pip` binary: `pip` may be
// an ossprey shim (see internal/shim), and a shim would route this straight back
// into `ossprey pip install`, which scans the project again — an unbounded
// recursion. `python` is not a shimmed manager.
func runPipResolve(ctx context.Context, python, cache, dir string, specArgs []string, loc file.Location) ([]pkg.Package, error) {
	budget := resolverTimeout()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	report := filepath.Join(cache, "report-"+strconv.FormatInt(time.Now().UnixNano(), 36)+".json")
	defer os.Remove(report)

	args := append([]string{
		"-m", "pip", "install",
		"--dry-run",
		// Without this pip omits anything already present in the ambient
		// environment from the report, so the SBOM would silently depend on
		// whatever the host happens to have installed.
		"--ignore-installed",
		"--quiet",
		"--disable-pip-version-check",
		"--no-input",
		"--report", report,
	}, specArgs...)

	cmd := exec.CommandContext(ctx, python, args...)
	cmd.Dir = dir // relative -r includes and local paths resolve against the manifest
	cmd.Env = append(os.Environ(),
		"PIP_CACHE_DIR="+cache,
		// A user or image with require-virtualenv set refuses every pip
		// invocation outside a venv, including one that installs nothing.
		"PIP_REQUIRE_VIRTUALENV=0",
		"PIP_DISABLE_PIP_VERSION_CHECK=1",
	)
	cmd.WaitDelay = 5 * time.Second // the kill lands on pip, but Output still waits on pipes a PEP 517 build backend may hold

	if _, err := cmd.Output(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("pip %s: timed out after %s (raise OSSPREY_RESOLVE_TIMEOUT)", dir, budget)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("pip %s: %s", dir, lastLines(string(ee.Stderr), 3))
		}
		return nil, fmt.Errorf("pip %s: %w", dir, err)
	}

	data, err := os.ReadFile(report)
	if err != nil {
		return nil, fmt.Errorf("pip %s: read report: %w", dir, err)
	}
	return parsePipReport(data, loc)
}

// pipReport is the subset of pip's installation report we read.
// https://pip.pypa.io/en/stable/reference/installation-report/
type pipReport struct {
	Install []struct {
		Metadata struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"metadata"`
		DownloadInfo struct {
			URL string `json:"url"`
		} `json:"download_info"`
	} `json:"install"`
}

// parsePipReport turns an installation report into packages, dropping anything
// resolved from a local path. A `file:` URL is the project itself or a path
// dependency (`-e ./libs/foo`) — the repo's own code, not a registry package,
// so emitting it would only yield a spurious NOT_FOUND finding.
func parsePipReport(data []byte, loc file.Location) ([]pkg.Package, error) {
	var report pipReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse pip report: %w", err)
	}
	seen := map[string]struct{}{}
	var pkgs []pkg.Package
	for _, entry := range report.Install {
		name := strings.ToLower(strings.TrimSpace(entry.Metadata.Name))
		version := strings.TrimSpace(entry.Metadata.Version)
		if name == "" || version == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(entry.DownloadInfo.URL), "file:") {
			continue
		}
		key := name + "@" + version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, pkg.Package{
			Name:      name,
			Version:   version,
			Type:      pkg.PythonPkg,
			Locations: file.NewLocationSet(loc),
		})
	}
	return pkgs, nil
}

// findPython returns the first Python interpreter on PATH that actually runs.
// Existence is not enough: Windows ships `python.exe` App Execution Aliases that
// exit non-zero and open the Microsoft Store instead of running anything.
func findPython(ctx context.Context) (string, bool) {
	candidates := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "python3", "py"}
	}
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = exec.CommandContext(probe, path, "-c", "pass").Run()
		cancel()
		if err == nil {
			return path, true
		}
	}
	return "", false
}

// pipVersion is a pip release, compared on major.minor only — pip's
// feature gates land on minor releases.
type pipVersion struct {
	major int
	minor int
}

func (v pipVersion) olderThan(other pipVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	return v.minor < other.minor
}

func (v pipVersion) String() string { return fmt.Sprintf("%d.%d", v.major, v.minor) }

// pipReportVersion reports the pip version behind an interpreter, or false when
// pip is absent or its version is unreadable.
func pipReportVersion(ctx context.Context, python string) (pipVersion, bool) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, python, "-m", "pip", "--version").Output()
	if err != nil {
		return pipVersion{}, false
	}
	return parsePipVersion(string(out))
}

// parsePipVersion reads the version out of `pip 24.0 from /path (python 3.12)`.
func parsePipVersion(out string) (pipVersion, bool) {
	fields := strings.Fields(out)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "pip") {
		return pipVersion{}, false
	}
	parts := strings.SplitN(fields[1], ".", 3)
	if len(parts) < 2 {
		return pipVersion{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return pipVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return pipVersion{}, false
	}
	return pipVersion{major: major, minor: minor}, true
}

// warnOnce keeps the no-resolver warning to one line per scan; every Python
// manifest in the tree would otherwise produce the same message.
var warnOnce sync.Once

// warnNoPythonResolver tells the user, once, that this scan will report direct
// dependencies only — but only when the tree actually declares Python
// dependencies, so a pure JavaScript repo stays quiet. Silence here is what let
// a customer's CI ship manifest-only SBOMs for weeks without noticing.
//
// Reaching this means the host had no uv either: Catalog builds this cataloger
// only in uv's absence.
func warnNoPythonResolver(resolver file.Resolver, reason string) {
	if !hasPythonManifest(resolver) {
		return
	}
	warnOnce.Do(func() {
		fmt.Fprintf(os.Stderr,
			"ossprey: no Python resolver available (%s) — reporting direct Python dependencies only, without their transitive tree.\n"+
				"ossprey: install uv (https://docs.astral.sh/uv/) or pip %s+ for full resolution.\n",
			reason, pipMinimum)
	})
}

// hasPythonManifest reports whether the tree declares Python dependencies
// anywhere outside a vendored directory.
func hasPythonManifest(resolver file.Resolver) bool {
	for _, glob := range []string{"**/requirements.txt", "**/pyproject.toml", "**/setup.py"} {
		locs, err := resolver.FilesByGlob(glob)
		if err != nil {
			continue
		}
		for _, loc := range locs {
			if !isVendoredPath(loc.RealPath) {
				return true
			}
		}
	}
	return false
}

// lastLines keeps the tail of a tool's stderr. pip's resolution errors end with
// the useful line ("No matching distribution found for …") after a long
// backtracking trace.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, "; "))
}
