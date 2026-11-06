package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
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
	// A line break would let a marker smuggle a second requirement line
	// (a TOML string may hold one); no control character belongs here.
	if strings.IndexFunc(line, unicode.IsControl) >= 0 {
		return "", false
	}
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

// Bounds on what one manifest's includes may cost before pip starts: the
// files are repository content, read before the resolver's own timeout runs.
const (
	maxPipRequirementsBytes = 4 << 20
	maxPipIncludeFiles      = 256
	maxPipIncludeDepth      = 32
)

// pipSanitizer writes build-free copies of requirements files into dir.
// Not safe for concurrent use; one per manifest.
type pipSanitizer struct {
	ctx     context.Context
	dir     string
	written map[string]string // source path -> copy
	dropped []string          // what was left out, described without its text (it may hold a credential)
}

func newPipSanitizer(ctx context.Context, dir string) *pipSanitizer {
	return &pipSanitizer{ctx: ctx, dir: dir, written: map[string]string{}}
}

// file writes the copy of the requirements file at src (and of every file it
// includes) and returns the copy's path.
func (s *pipSanitizer) file(src string) (string, error) {
	return s.fileAt(src, 0)
}

func (s *pipSanitizer) fileAt(src string, depth int) (string, error) {
	if out, ok := s.written[src]; ok {
		return out, nil // an include cycle points at the copy in progress
	}
	if err := s.ctx.Err(); err != nil {
		return "", err
	}
	if depth > maxPipIncludeDepth || len(s.written) >= maxPipIncludeFiles {
		return "", fmt.Errorf("%s: includes nest deeper than %d or number over %d", src, maxPipIncludeDepth, maxPipIncludeFiles)
	}
	// Numbered, not named after src: two sources can map to one name.
	out := filepath.Join(s.dir, fmt.Sprintf("req-%d-%s.txt", len(s.written), requirementsFileID(filepath.Base(src))))
	s.written[src] = out
	data, err := readRequirementsFile(src)
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
			kept, err := s.options(src, line, depth)
			if err != nil {
				return "", err
			}
			for _, k := range kept {
				b.WriteString(k + "\n")
			}
		default:
			if req, ok := pipSafeRequirement(line); ok {
				b.WriteString(req + "\n")
			} else {
				s.dropped = append(s.dropped, describeUnsafeRequirement(line))
			}
		}
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write requirements: %w", err)
	}
	return out, nil
}

// readRequirementsFile reads a regular file of bounded size. A device or FIFO
// named by an include could otherwise never end or never answer.
func readRequirementsFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPipRequirementsBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPipRequirementsBytes {
		return nil, fmt.Errorf("%s is over %d bytes", path, maxPipRequirementsBytes)
	}
	return data, nil
}

// pipPassOptions are the requirements-file options that only say where to
// look, mapped to their long name and whether they take a value.
var pipPassOptions = map[string]struct {
	long  string
	value bool
}{
	"-i": {"--index-url", true}, "--index-url": {"--index-url", true},
	"--extra-index-url": {"--extra-index-url", true},
	"--no-index":        {"--no-index", false},
	"-f":                {"--find-links", true}, "--find-links": {"--find-links", true},
	"--pre":           {"--pre", false},
	"--prefer-binary": {"--prefer-binary", false},
	"--trusted-host":  {"--trusted-host", true},
}

// pipSilentOptions change nothing about which releases resolve, so dropping
// them costs no fidelity and is not reported.
var pipSilentOptions = map[string]bool{"--require-hashes": true}

// options rewrites one option line of src into the options to keep, one per
// line. pip splits an option line with shlex and reads every option on it,
// so every token is judged, not just the first: `--no-index --no-binary
// :all:` must not carry the second through. Includes are copied in turn;
// any option not known to be harmless is dropped and reported, since several
// (--no-binary, -e, --use-pep517) bring back a build and the rest change
// which releases resolve.
func (s *pipSanitizer) options(src, line string, depth int) ([]string, error) {
	tokens, err := shlexSplit(line)
	if err != nil {
		s.dropped = append(s.dropped, "an option line that does not parse")
		return nil, nil
	}
	var kept []string
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if !strings.HasPrefix(tok, "-") {
			continue // a stray value; pip would refuse the line
		}
		name, value, attached := splitPipToken(tok)
		takesValue := false
		switch name {
		case "-r", "--requirement", "-c", "--constraint", "-e", "--editable":
			takesValue = true
		default:
			if o, ok := pipPassOptions[name]; ok {
				takesValue = o.value
			}
		}
		if takesValue && !attached {
			if i+1 >= len(tokens) {
				s.dropped = append(s.dropped, name+" with no value")
				continue
			}
			i++
			value = tokens[i]
		}
		switch name {
		case "-r", "--requirement", "-c", "--constraint":
			if strings.Contains(value, "://") {
				s.dropped = append(s.dropped, "a remote include ("+name+" <url>)") // fetched, not read from the tree
				continue
			}
			path := value
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(src), path) // pip reads includes beside the including file
			}
			copyPath, err := s.fileAt(path, depth+1)
			if err != nil {
				return nil, err
			}
			long := "--requirement"
			if name == "-c" || name == "--constraint" {
				long = "--constraint"
			}
			kept = append(kept, long+" "+shlexQuote(copyPath))
			continue
		case "-e", "--editable":
			s.dropped = append(s.dropped, "an editable ("+name+")")
			continue
		}
		o, ok := pipPassOptions[name]
		if ok && strings.Contains(value, "${") {
			// pip expands ${VAR} from its environment in a requirements file,
			// so a repository's index URL could carry a runner secret to a
			// host of its choosing.
			s.dropped = append(s.dropped, name+" naming an environment variable")
			continue
		}
		if !ok {
			if !pipSilentOptions[name] {
				s.dropped = append(s.dropped, "option "+name)
			}
			continue
		}
		if !o.value {
			kept = append(kept, o.long)
			continue
		}
		if o.long == "--find-links" && !strings.Contains(value, "://") && !filepath.IsAbs(value) {
			// pip prefers a find-links path relative to the file it was read
			// from, and the copy lives elsewhere.
			if p := filepath.Join(filepath.Dir(src), value); pathExists(p) {
				value = p
			}
		}
		kept = append(kept, o.long+" "+shlexQuote(value))
	}
	return kept, nil
}

// splitPipToken splits "--name=value", "-xvalue" and "--name"/"-x" into the
// option and any value attached to it.
func splitPipToken(tok string) (name, value string, attached bool) {
	if strings.HasPrefix(tok, "--") {
		if n, v, ok := strings.Cut(tok, "="); ok {
			return n, v, true
		}
		return tok, "", false
	}
	if len(tok) > 2 {
		return tok[:2], tok[2:], true
	}
	return tok, "", false
}

var errShlexQuote = errors.New("unterminated quote")

// shlexSplit splits as Python's shlex.split does in POSIX mode, which is how
// pip splits a requirements file's option line.
func shlexSplit(s string) ([]string, error) {
	var (
		out   []string
		cur   strings.Builder
		inTok bool
		quote rune
	)
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case quote == '"':
			switch {
			case r == '"':
				quote = 0
			case r == '\\' && i+1 < len(rs) && (rs[i+1] == '"' || rs[i+1] == '\\'):
				i++
				cur.WriteRune(rs[i])
			default:
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inTok = r, true
		case r == '\\':
			inTok = true
			if i+1 < len(rs) {
				i++
				cur.WriteRune(rs[i])
			}
		case unicode.IsSpace(r):
			if inTok {
				out = append(out, cur.String())
				cur.Reset()
				inTok = false
			}
		default:
			inTok = true
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, errShlexQuote
	}
	if inTok {
		out = append(out, cur.String())
	}
	return out, nil
}

// shlexQuote quotes a value so shlexSplit (and pip) reads it back as one
// token: a temp directory with a space in it, or a Windows path, intact.
func shlexQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// describeUnsafeRequirement says what kind of requirement was left out,
// without its text: a direct reference or an included file outside the scan
// can carry a credential, and warnings reach CI logs.
func describeUnsafeRequirement(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.IndexFunc(line, unicode.IsControl) >= 0:
		return "a requirement with a line break"
	case strings.Contains(line, "://") || strings.Contains(line, "@"):
		return "a URL or direct reference"
	case strings.HasPrefix(line, ".") || strings.HasPrefix(line, "~") || strings.ContainsAny(line, `/\`):
		return "a local path"
	}
	for _, suf := range pipArchiveSuffixes {
		if strings.HasSuffix(lower, suf) {
			return "a local archive"
		}
	}
	return "a requirement pip could build"
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
