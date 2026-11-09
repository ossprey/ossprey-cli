package catalog

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/ossprey/ossprey-cli/internal/warn"
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
	key := fileKey(src)
	if out, ok := s.written[key]; ok {
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
	s.written[key] = out
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
	return readBoundedFile(path, maxPipRequirementsBytes)
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
			path, err := includePath(src, value) // pip reads includes beside the including file
			if err != nil {
				return nil, err
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

// errRemoteInclude refuses a requirements file including a URL: uv fetches it
// (verified against uv 0.11) and expands any ${VAR} in what comes back, so the
// repository's host would choose what this machine's environment fills in.
var errRemoteInclude = errors.New("includes a URL, where uv would expand environment variables; not resolved")

// fileKey names the file at path as the OS resolves it, so one file reached
// by two spellings (./r.txt, a link, a ..) is one entry when spotting cycles.
func fileKey(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return filepath.Clean(path)
}

// includePath is where pip and uv read an include named value in the file at
// src: os.path.join of the including file's directory and value, with no
// lexical cleaning, so the OS applies a .. after following the link before it
// (both verified: jump/../deps.txt reads the deps.txt beside jump's target).
// filepath.Join cleans the .. away first and reads another file. The
// directory is resolved here, as the OS resolves it, so the result can be
// read and judged as it stands.
func includePath(src, value string) (string, error) {
	if filepath.IsAbs(value) {
		return value, nil
	}
	cut := strings.LastIndexAny(src, "/"+string(filepath.Separator))
	dir := src[:max(cut, 0)]
	if cut == 0 {
		dir = src[:1]
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("%s %w", dir, errOutsideRoot)
	}
	return real + string(filepath.Separator) + value, nil
}

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
	var projects []string
	project := func(p, ref string) error {
		found, err := localProjects(p, ref, root)
		projects = append(projects, found...)
		return err
	}
	seen := map[string]bool{}
	var walk func(p string, depth int) error
	walk = func(p string, depth int) error {
		if seen[fileKey(p)] {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > maxPipIncludeDepth || len(seen) >= maxPipIncludeFiles {
			return fmt.Errorf("%s: includes nest deeper than %d or number over %d", p, maxPipIncludeDepth, maxPipIncludeFiles)
		}
		seen[fileKey(p)] = true
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
				if ref := localProjectRef(line); ref != "" {
					if err := project(p, ref); err != nil {
						return err
					}
				}
				continue
			}
			tokens, err := shlexSplit(line)
			if err != nil {
				continue // uv refuses it too
			}
			for i, tok := range tokens {
				name, value, attached := splitPipToken(tok)
				switch name {
				case "-r", "--requirement", "-c", "--constraint", "-e", "--editable":
				default:
					continue
				}
				if !attached {
					if i+1 >= len(tokens) {
						continue
					}
					value = tokens[i+1]
				}
				if name == "-e" || name == "--editable" {
					ref := localProjectRef(value)
					if ref == "" && !strings.Contains(value, "://") {
						ref = value // an editable is a path whatever it looks like
					}
					if ref != "" {
						if err := project(p, ref); err != nil {
							return err
						}
					}
					continue
				}
				if strings.Contains(value, "://") {
					return fmt.Errorf("%s %w", p, errRemoteInclude)
				}
				value, err := includePath(p, value)
				if err != nil {
					return err
				}
				if err := walk(value, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(path, 0); err != nil {
		return err
	}
	return uvProjectsExpandEnv(projects, root)
}

// projectManifest is the pyproject.toml of the directory at dir as the OS
// resolves it, symlinks first: past a link, jump/../lib names the lib beside
// the link's target, which is what uv reads, while filepath.Join would clean
// the .. away and name another directory. false when dir is not a directory.
func projectManifest(dir string) (string, bool) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", false
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return "", false
	}
	return filepath.Join(real, "pyproject.toml"), true
}

// localProjectRef returns the path a requirement line names as a local
// project (./lib, lib/, /abs/lib, file:./lib, name @ file:///abs/lib), or ""
// for a registry requirement or a remote URL. uv reads such a project's
// pyproject and expands ${VAR} in it (verified against uv 0.11).
func localProjectRef(v string) string {
	v, _, _ = strings.Cut(v, " #")
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "@"); i > 0 && !strings.ContainsAny(v[:i], `/\`) {
		v = strings.TrimSpace(v[i+1:])
	}
	v, _, _ = strings.Cut(v, ";")
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, "]") {
		if i := strings.LastIndex(v, "["); i > 0 {
			v = v[:i] // extras
		}
	}
	if strings.HasPrefix(strings.ToLower(v), "file:") {
		u, err := url.Parse(v)
		if err != nil {
			return v // judged as a path, so it is looked for rather than skipped
		}
		p := u.Path
		if p == "" {
			p = u.Opaque
		}
		if unescaped, err := url.PathUnescape(p); err == nil {
			p = unescaped
		}
		return filepath.FromSlash(fileURLDrive(u.Host, p))
	}
	if strings.Contains(v, "://") {
		return ""
	}
	if strings.HasPrefix(v, ".") || strings.HasPrefix(v, "~") || strings.ContainsAny(v, `/\`) || filepath.IsAbs(v) {
		return v
	}
	return ""
}

// fileURLDrive puts a Windows drive back on a file URL's path: file:///C:/x
// parses to /C:/x and file://C:/x to host C:, neither of which names C:\x.
func fileURLDrive(host, p string) string {
	isDrive := func(s string) bool {
		return len(s) == 2 && s[1] == ':' && (s[0]|0x20) >= 'a' && (s[0]|0x20) <= 'z'
	}
	if isDrive(host) {
		return host + p
	}
	if len(p) >= 3 && p[0] == '/' && isDrive(p[1:3]) {
		return p[1:]
	}
	return p
}

// localProjects returns the pyproject of each directory a local project ref,
// named in the requirements file at src, can mean: uv reads a relative one
// against its working directory, which is the scan's (verified: runUV sets
// no directory), and the file's own directory is checked as well. A project
// outside root is refused like an include outside it.
func localProjects(src, ref, root string) ([]string, error) {
	if strings.HasPrefix(ref, "~") {
		return nil, fmt.Errorf("%s %w", ref, errOutsideRoot)
	}
	candidates := []string{ref}
	if !filepath.IsAbs(ref) {
		candidates = nil
		if wd, err := os.Getwd(); err == nil {
			candidates = append(candidates, wd+string(filepath.Separator)+ref)
		}
		if p, err := includePath(src, ref); err == nil {
			candidates = append(candidates, p)
		}
	}
	var out []string
	for _, c := range candidates {
		project, ok := projectManifest(c)
		if !ok {
			continue // a missing path fails uv, and a local archive is not read for metadata here
		}
		if !withinRoot(c, root) {
			return nil, fmt.Errorf("%s %w", c, errOutsideRoot)
		}
		out = append(out, project)
	}
	return out, nil
}

// pyprojectExpandsEnv is uvExpandsEnv for a pyproject's dependency lists,
// which uv expands the same way: [project] dependencies and extras, and what
// uv export re-locks a stale uv.lock from besides them, [dependency-groups]
// and [tool.uv]'s dev, override and constraint lists (verified against uv
// 0.11; [tool.uv.sources] URLs are not expanded).
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
	uvLists, err := readUVLists(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	uv := uvLists.Tool.UV
	if anyStringNamesEnv(uvLists.Groups, uv.Dev, uv.Override, uv.Constraint, uv.BuildConstraint) {
		return fmt.Errorf("%s %w", path, errNamesEnvVar)
	}
	return nil
}

// uvLists is what uv reads from a pyproject besides [project]. Decoded
// loosely: a group may hold {include-group = ...} tables, and a source may be
// a table or a list of them.
type uvLists struct {
	Groups map[string]any `toml:"dependency-groups"`
	Tool   struct {
		UV struct {
			Dev             any            `toml:"dev-dependencies"`
			Override        any            `toml:"override-dependencies"`
			Constraint      any            `toml:"constraint-dependencies"`
			BuildConstraint any            `toml:"build-constraint-dependencies"`
			Sources         map[string]any `toml:"sources"`
			Workspace       *struct {
				Members []string `toml:"members"`
				Exclude []string `toml:"exclude"`
			} `toml:"workspace"`
		} `toml:"uv"`
	} `toml:"tool"`
}

// readUVLists reads a pyproject's uv tables; a missing file has none.
func readUVLists(path string) (*uvLists, error) {
	data, err := readPyProjectData(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return &uvLists{}, nil
	}
	var l uvLists
	if err := toml.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// declaresUVDependencies reports a pyproject with a dependency group or uv
// dev-dependencies naming anything: dependencies no [project] reader sees.
// One that cannot be read counts as declaring some.
func declaresUVDependencies(path string) bool {
	l, err := readUVLists(path)
	if err != nil {
		return true
	}
	return anyString(l.Groups) || anyString(l.Tool.UV.Dev)
}

// groupsLeftOut marks a pyproject unresolved when it declares dependency
// groups or uv dev-dependencies and no lock beside it holds their tree: a
// resolver handed [project] (pip's requirement list, or uv pip compile with
// no uv.lock) leaves them out.
func groupsLeftOut(ctx context.Context, root, tool, manifest string) {
	if !declaresUVDependencies(manifest) || pythonCovered(root)(manifest) {
		return
	}
	markUnresolved(ctx, root, manifest)
	warn.Add(ctx, warn.Entry{
		Class: tool + ":groups",
		One:   fmt.Sprintf("%s: %s: dependency groups not resolved without a lock", tool, manifest),
		Many:  tool + ": %d pyprojects' dependency groups not resolved without a lock (OSSPREY_VERBOSE=1 lists them)",
		Item:  manifest,
	})
}

// maxUVProjects bounds the pyprojects uvProjectExpandsEnv reads for one
// manifest; a workspace past it is refused rather than read without end.
const maxUVProjects = 256

// errUVProjectUnplaced refuses a manifest whose workspace or sources name
// projects uvProjectExpandsEnv cannot list.
var errUVProjectUnplaced = errors.New("names workspace members or sources that cannot be listed; not resolved")

// uvProjectExpandsEnv is pyprojectExpandsEnv for every pyproject uv reads
// when it resolves the one at path, not that one alone: uv locks every member
// of the workspace (a stale root uv.lock re-locked by uv export), and reads
// the pyproject of every path source and file: direct reference, expanding
// ${VAR} in each (all verified against uv 0.11, export and pip compile).
// A workspace root above path inside the scan is read with all its members,
// since uv discovers it from a member. Members are listed by their globs
// without applying exclude, so an excluded member can only refuse more.
func uvProjectExpandsEnv(path, root string) error {
	return uvProjectsExpandEnv([]string{path}, root)
}

// uvProjectsExpandEnv is uvProjectExpandsEnv for several pyprojects at once,
// under one cap.
func uvProjectsExpandEnv(paths []string, root string) error {
	if len(paths) == 0 {
		return nil
	}
	path := paths[0]
	var queue []string
	for _, p := range paths {
		queue = append(queue, p)
		for d := filepath.Dir(filepath.Dir(p)); withinRoot(d, root); d = filepath.Dir(d) {
			if l, err := readUVLists(filepath.Join(d, "pyproject.toml")); err != nil || l.Tool.UV.Workspace != nil {
				queue = append(queue, filepath.Join(d, "pyproject.toml"))
			}
			if d == filepath.Dir(d) {
				break
			}
		}
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if k := fileKey(p); seen[k] {
			continue
		} else {
			seen[k] = true
		}
		if len(seen) > maxUVProjects {
			return fmt.Errorf("%s: more than %d projects in its workspace and sources; not resolved", path, maxUVProjects)
		}
		if err := pyprojectExpandsEnv(p); err != nil {
			return err
		}
		more, err := uvProjectRefs(p)
		if err != nil {
			return err
		}
		queue = append(queue, more...)
	}
	return nil
}

// uvProjectRefs lists the pyprojects uv reads on behalf of the one at path:
// its workspace members, its path sources, and its file: direct references.
func uvProjectRefs(path string) ([]string, error) {
	l, err := readUVLists(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	dir := filepath.Dir(path)
	var out []string
	project := func(p string) {
		if !filepath.IsAbs(p) {
			p = dir + string(filepath.Separator) + p
		}
		if project, ok := projectManifest(p); ok {
			out = append(out, project)
		}
	}
	if ws := l.Tool.UV.Workspace; ws != nil {
		for _, g := range ws.Members {
			// Go's glob has no recursive **, which uv's has.
			if strings.Contains(g, "**") {
				return nil, fmt.Errorf("%s %w", path, errUVProjectUnplaced)
			}
			matches, err := filepath.Glob(filepath.Join(dir, g))
			if err != nil {
				return nil, fmt.Errorf("%s %w", path, errUVProjectUnplaced)
			}
			for _, m := range matches {
				project(m)
			}
		}
	}
	var sources []any
	for _, v := range l.Tool.UV.Sources {
		if list, ok := v.([]any); ok {
			sources = append(sources, list...)
		} else {
			sources = append(sources, v)
		}
	}
	for _, v := range sources {
		if t, ok := v.(map[string]any); ok {
			if p, ok := t["path"].(string); ok {
				project(p)
			}
		}
	}
	pp, err := readPyProject(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var reqs []string
	if pp != nil {
		reqs = append(reqs, pp.Project.Dependencies...)
		for _, g := range pp.Project.OptionalDependencies {
			reqs = append(reqs, g...)
		}
	}
	collectStrings(&reqs, l.Groups, l.Tool.UV.Dev, l.Tool.UV.Override, l.Tool.UV.Constraint, l.Tool.UV.BuildConstraint)
	for _, r := range reqs {
		_, ref, ok := strings.Cut(r, "@")
		if !ok {
			continue
		}
		ref = strings.TrimSpace(ref)
		ref, _, _ = strings.Cut(ref, ";")
		if ref = strings.TrimSpace(ref); !strings.HasPrefix(strings.ToLower(ref), "file:") {
			continue
		}
		u, err := url.Parse(ref)
		if err != nil {
			return nil, fmt.Errorf("%s %w", path, errUVProjectUnplaced)
		}
		p := u.Path
		if p == "" {
			p = u.Opaque
		}
		if p, err = url.PathUnescape(p); err != nil {
			return nil, fmt.Errorf("%s %w", path, errUVProjectUnplaced)
		}
		project(filepath.FromSlash(fileURLDrive(u.Host, p)))
	}
	return out, nil
}

// collectStrings appends every string held, at any depth, by vs.
func collectStrings(out *[]string, vs ...any) {
	for _, v := range vs {
		switch v := v.(type) {
		case string:
			*out = append(*out, v)
		case []any:
			collectStrings(out, v...)
		case map[string]any:
			for _, e := range v {
				collectStrings(out, e)
			}
		}
	}
}

// anyString reports whether vs hold any string at any depth.
func anyString(vs ...any) bool {
	var all []string
	collectStrings(&all, vs...)
	return len(all) > 0
}

// anyStringNamesEnv reports a ${ in any string held, at any depth, by vs.
func anyStringNamesEnv(vs ...any) bool {
	for _, v := range vs {
		switch v := v.(type) {
		case string:
			if strings.Contains(v, "${") {
				return true
			}
		case []any:
			if anyStringNamesEnv(v...) {
				return true
			}
		case map[string]any:
			for _, e := range v {
				if anyStringNamesEnv(e) {
					return true
				}
			}
		}
	}
	return false
}
