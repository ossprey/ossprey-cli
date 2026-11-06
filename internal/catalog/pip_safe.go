package catalog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// pip's --only-binary=:all: does not stop it building everything. Verified
// against pip 24.0: a requirements file can turn it back off (`--no-binary
// :all:` inside the file wins over the command line), and a local path, an
// editable (`-e ./x`) or a direct URL (`name @ file:///x`) is built whatever
// the flag says. All of that is repository content, so pip is never handed a
// requirements file from the tree: pipSanitizer writes a copy holding only
// registry requirements and the index options, and reports what it left out.

// pipSafeRequirementRE is a registry requirement and nothing else: a name,
// optional extras and version clauses. No '@', '/', '\' or ':', so no direct
// reference, path or URL gets through.
var pipSafeRequirementRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\s*(?:\[[A-Za-z0-9._,\s-]*\])?\s*(?:[<>=!~(][<>=!~(),.*+!0-9A-Za-z_\s-]*)?$`)

var pipLineOption = regexp.MustCompile(`\s-`)

// pipArchiveSuffixes are the names pip takes as a local archive, which it
// builds (pip's is_archive_file).
var pipArchiveSuffixes = []string{".zip", ".whl", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma", ".tar.gz", ".tgz", ".tar"}

// pipSafeRequirement returns the requirement to hand pip, without per-line
// options, or false when resolving it could build something.
func pipSafeRequirement(line string) (string, bool) {
	line = strings.TrimSpace(line)
	// Per-requirement options (--hash, --config-settings) matter only to an
	// install or a build.
	if i := pipLineOption.FindStringIndex(line); i != nil {
		line = strings.TrimSpace(line[:i[0]])
	}
	spec, marker, hasMarker := strings.Cut(line, ";")
	spec = strings.TrimSpace(spec)
	if !pipSafeRequirementRE.MatchString(spec) {
		return "", false
	}
	lower := strings.ToLower(spec)
	for _, suf := range pipArchiveSuffixes {
		if strings.HasSuffix(lower, suf) {
			return "", false
		}
	}
	if hasMarker {
		return spec + " ;" + marker, true
	}
	return spec, true
}

// pipSanitizer writes build-free copies of requirements files into dir.
// Not safe for concurrent use; one per manifest.
type pipSanitizer struct {
	dir     string
	written map[string]string // source path -> copy
	dropped []string          // lines left out, for the warning
}

func newPipSanitizer(dir string) *pipSanitizer {
	return &pipSanitizer{dir: dir, written: map[string]string{}}
}

// file writes the copy of the requirements file at src (and of every file it
// includes) and returns the copy's path.
func (s *pipSanitizer) file(src string) (string, error) {
	if out, ok := s.written[src]; ok {
		return out, nil // an include cycle points at the copy in progress
	}
	out := filepath.Join(s.dir, "req-"+requirementsFileID(src)+".txt")
	s.written[src] = out
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, line := range requirementLines(data) {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "-"):
			kept, err := s.option(src, line)
			if err != nil {
				return "", err
			}
			if kept != "" {
				b.WriteString(kept + "\n")
			}
		default:
			if req, ok := pipSafeRequirement(line); ok {
				b.WriteString(req + "\n")
			} else {
				s.dropped = append(s.dropped, line)
			}
		}
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write requirements: %w", err)
	}
	return out, nil
}

// pipPassOptions are the requirements-file options that only say where to look.
var pipPassOptions = map[string]string{
	"-i": "--index-url", "--index-url": "--index-url",
	"--extra-index-url": "--extra-index-url",
	"--no-index":        "--no-index",
	"-f":                "--find-links", "--find-links": "--find-links",
	"--pre":           "--pre",
	"--prefer-binary": "--prefer-binary",
	"--trusted-host":  "--trusted-host",
}

// option rewrites one option line of src, or returns "" to drop it. Includes
// are copied in turn; every option not known to be harmless is dropped, since
// several (--no-binary, -e, --use-pep517) bring back a build.
func (s *pipSanitizer) option(src, line string) (string, error) {
	name, value := splitPipOption(line)
	switch name {
	case "-r", "--requirement", "-c", "--constraint":
		if strings.Contains(value, "://") {
			s.dropped = append(s.dropped, line) // fetched, not read from the tree
			return "", nil
		}
		path := value
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(src), path) // pip reads includes beside the including file
		}
		copyPath, err := s.file(path)
		if err != nil {
			return "", err
		}
		if name == "-c" || name == "--constraint" {
			return "--constraint " + copyPath, nil
		}
		return "--requirement " + copyPath, nil
	case "-e", "--editable":
		s.dropped = append(s.dropped, line)
		return "", nil
	}
	long, ok := pipPassOptions[name]
	if !ok {
		return "", nil
	}
	if long == "--find-links" && !strings.Contains(value, "://") && !filepath.IsAbs(value) {
		// pip prefers a find-links path relative to the file it was read
		// from, and the copy lives elsewhere.
		if p := filepath.Join(filepath.Dir(src), value); pathExists(p) {
			value = p
		}
	}
	if value == "" {
		return long, nil
	}
	return long + " " + value, nil
}

// splitPipOption splits "-r file", "-rfile", "--requirement=file" and
// "--requirement file" into the option and its value.
func splitPipOption(line string) (name, value string) {
	if strings.HasPrefix(line, "--") {
		first := strings.Fields(line)[0]
		if i := strings.IndexByte(first, '='); i >= 0 {
			return first[:i], strings.TrimSpace(line[i+1:])
		}
		return first, strings.TrimSpace(line[len(first):])
	}
	if len(line) < 2 {
		return line, ""
	}
	return line[:2], strings.TrimSpace(line[2:])
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
