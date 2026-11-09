package catalog

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// pip's --only-binary=:all: does not stop it building everything. Verified
// against pip 24.0: a requirements file can turn it back off (`--no-binary
// :all:` inside the file wins over the command line), and a local path, an
// editable (`-e ./x`) or a direct URL (`name @ file:///x`) is built whatever
// the flag says. All of that is repository content, so pip is never handed a
// requirements file from the tree: pipSanitizer writes a copy holding only
// registry requirements and the index options, and reports what it left out.

// pipNameRE is the distribution-name part of a requirement.
var pipNameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`)

// pipSafeRequirementRE is a registry requirement and nothing else: a name,
// optional extras and version clauses. No '@', '/', '\' or ':', so no direct
// reference, path or URL gets through.
var pipSafeRequirementRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\s*(?:\[[A-Za-z0-9._,\s-]*\])?\s*(?:[<>=!~(][<>=!~(),.*+!0-9A-Za-z_\s-]*)?$`)

var pipLineOption = regexp.MustCompile(`\s-`)

// pipArchiveSuffixes are the names pip takes as a local archive, which it
// builds (pip's is_archive_file).
var pipArchiveSuffixes = []string{".zip", ".whl", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma", ".tar.gz", ".tgz", ".tar"}

// pipLineBreak reports a rune Python's splitlines (which pip reads a
// requirements file with) may split on: every control character, and U+2028
// and U+2029, which unicode.IsControl does not cover.
func pipLineBreak(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

// pipSafeRequirement returns the requirement to hand pip, without per-line
// options, or false when resolving it could build something.
func pipSafeRequirement(line string) (string, bool) {
	// A line break would let a marker smuggle a second requirement line
	// (a TOML string may hold one); no control character belongs here.
	// Invalid UTF-8 too: pip may decode the file in a locale where a stray
	// byte is one of those (0x85 in Latin-1).
	if strings.IndexFunc(line, pipLineBreak) >= 0 || !utf8.ValidString(line) {
		return "", false
	}
	// pip expands ${VAR} on every line, a marker's string included, and the
	// marker is copied as written.
	if strings.Contains(line, "${") {
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
	if pipArchiveName(spec) {
		return "", false
	}
	if hasMarker {
		return spec + " ;" + marker, true
	}
	return spec, true
}

// pipArchiveName reports a requirement whose name pip may take for a local
// archive. pip strips extras first, so `x-1.0.tar.gz[e]` is the archive too.
func pipArchiveName(spec string) bool {
	name := strings.ToLower(pipNameRE.FindString(spec))
	for _, suf := range pipArchiveSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
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
	root    string            // the scan root; no file outside it is read
	written map[string]string // source path -> copy
	dropped []string          // what was left out, described without its text (it may hold a credential)
	// ownIndex is set when a file names an index or find-links location. A
	// wheel there can declare `Requires-Dist: x @ <sdist URL>`, which pip
	// builds whatever --only-binary says (verified against pip 24.0), so pip
	// must not resolve the manifest at all.
	ownIndex bool
}

func newPipSanitizer(ctx context.Context, dir, root string) *pipSanitizer {
	return &pipSanitizer{ctx: ctx, dir: dir, root: root, written: map[string]string{}}
}

// errPipOwnIndex refuses a requirements file pip cannot resolve without
// possibly building code.
var errPipOwnIndex = errors.New("names its own index or find-links location, where a wheel can declare an sdist pip would build; not resolved by pip (uv resolves it)")

// errOutsideRoot refuses a requirements file, or an include, outside the scan.
var errOutsideRoot = errors.New("is outside the scan root or cannot be read; not resolved")

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
	id := requirementsFileID(filepath.Base(src))
	if len(id) > 40 {
		id = id[:40] // the counter keeps it unique; this only keeps it readable
	}
	out := filepath.Join(s.dir, fmt.Sprintf("req-%d-%s.txt", len(s.written), id))
	s.written[src] = out
	// An include may name any path, through .. or a link; what it reads
	// would go to pip as requirements, and on to the index.
	if !withinRoot(src, s.root) {
		return "", fmt.Errorf("%s %w", src, errOutsideRoot)
	}
	data, err := readRequirementsFile(src)
	if err != nil {
		return "", err
	}
	lines, err := scanRequirementLines(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", src, err)
	}
	var b strings.Builder
	for _, line := range lines {
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
	return readRegularFile(path, maxPipRequirementsBytes)
}

// pipPassOptions are the requirements-file options that only say where to
// look, mapped to their long name and whether they take a value. The index
// and find-links ones are recognised only to refuse the file (ownIndex).
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

// pipIndexOptions name where pip fetches from.
var pipIndexOptions = map[string]bool{"--index-url": true, "--extra-index-url": true, "--find-links": true}

// pipNamedOptions are pip options a warning may name. Anything else is
// described generically: an unknown token is repository text, and may be a
// secret from a file the include named.
var pipNamedOptions = map[string]bool{
	"--no-binary": true, "--only-binary": true, "--use-feature": true, "--use-pep517": true,
	"--no-use-pep517": true, "--global-option": true, "--install-option": true,
	"--config-settings": true, "--hash": true, "--no-build-isolation": true,
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
			switch {
			case pipSilentOptions[name]:
			case pipNamedOptions[name]:
				s.dropped = append(s.dropped, "option "+name)
			default:
				s.dropped = append(s.dropped, "an unrecognised option")
			}
			continue
		}
		if pipIndexOptions[o.long] {
			s.ownIndex = true
			continue
		}
		if !o.value {
			kept = append(kept, o.long)
			continue
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
		case r == ' ' || r == '\t' || r == '\r' || r == '\n': // Python shlex's whitespace, not Unicode's
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
	switch {
	case strings.IndexFunc(line, pipLineBreak) >= 0 || !utf8.ValidString(line):
		return "a requirement with a line break"
	case strings.Contains(line, "${"):
		return "a requirement naming an environment variable"
	case strings.Contains(line, "://") || strings.Contains(line, "@"):
		return "a URL or direct reference"
	case strings.HasPrefix(line, ".") || strings.HasPrefix(line, "~") || strings.ContainsAny(line, `/\`):
		return "a local path"
	}
	if pipArchiveName(line) {
		return "a local archive"
	}
	return "a requirement pip could build"
}

// errNamesEnvVar refuses a manifest uv would fill in from this machine's
// environment.
var errNamesEnvVar = errors.New("names an environment variable (${...}), which the resolver would fill in from this machine; not resolved")

// uvExpandsEnv reports, as an error, a requirements file (or any file it
// includes) with a ${VAR} on any line. uv expands those from its environment
// in requirement and option lines alike (verified against uv 0.11: an
// --index-url and a direct URL each sent the variable's value to the host),
// so a repository could send a runner secret anywhere. uv reads the file
// itself, so the whole file is refused rather than rewritten.
//
// Includes outside root are refused the same way: uv would read them and send
// their lines to the index as requirements.
func uvExpandsEnv(ctx context.Context, path, root string) error {
	seen := map[string]bool{}
	var walk func(p string, depth int) error
	walk = func(p string, depth int) error {
		if seen[p] {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > maxPipIncludeDepth || len(seen) >= maxPipIncludeFiles {
			return fmt.Errorf("%s: includes nest deeper than %d or number over %d", p, maxPipIncludeDepth, maxPipIncludeFiles)
		}
		seen[p] = true
		if !withinRoot(p, root) {
			return fmt.Errorf("%s %w", p, errOutsideRoot)
		}
		data, err := readRequirementsFile(p)
		if err != nil {
			return err
		}
		lines, err := scanRequirementLines(data)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		for _, line := range lines {
			if strings.Contains(line, "${") {
				return fmt.Errorf("%s %w", p, errNamesEnvVar)
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-") {
				continue
			}
			tokens, err := shlexSplit(line)
			if err != nil {
				continue // uv refuses it too
			}
			for i, tok := range tokens {
				name, value, attached := splitPipToken(tok)
				switch name {
				case "-r", "--requirement", "-c", "--constraint":
				default:
					continue
				}
				if !attached {
					if i+1 >= len(tokens) {
						continue
					}
					value = tokens[i+1]
				}
				if strings.Contains(value, "://") {
					continue
				}
				if !filepath.IsAbs(value) {
					value = filepath.Join(filepath.Dir(p), value)
				}
				if err := walk(value, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(path, 0)
}

// pyprojectExpandsEnv is uvExpandsEnv for a pyproject's [project]
// dependencies, which uv expands the same way.
// It reads the raw lists: an entry naming the project itself, which
// pyprojectRequirementSpecs drops, is still read by uv.
func pyprojectExpandsEnv(path string) error {
	pp, err := readPyProject(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if pp == nil {
		return nil
	}
	deps := slices.Clone(pp.Project.Dependencies)
	for _, group := range pp.Project.OptionalDependencies {
		deps = append(deps, group...)
	}
	for _, s := range deps {
		if strings.Contains(s, "${") {
			return fmt.Errorf("%s %w", path, errNamesEnvVar)
		}
	}
	return nil
}
