package catalog

import (
	"context"
	"io/fs"
	"maps"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// cratesIoIndex is crates.io's index host and path for each Cargo.lock source kind.
var cratesIoIndex = map[string][2]string{
	"registry": {"github.com", "/rust-lang/crates.io-index"},
	"sparse":   {"index.crates.io", "/"},
}

// defaultPort is the port the WHATWG URL parser drops for each special scheme.
var defaultPort = map[string]uint64{"ftp": 21, "http": 80, "https": 443, "ws": 80, "wss": 443}

// trimC0 strips the leading and trailing C0 controls and spaces the WHATWG URL parser ignores.
func trimC0(s string) string { return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' }) }

// crateURLCleaner applies the WHATWG URL parser's tab and newline removal and its reading of '\' as '/'.
var crateURLCleaner = strings.NewReplacer("\t", "", "\n", "", "\r", "", `\`, "/")

// isCratesIo folds at least what Cargo's url crate and CanonicalUrl fold, and says whether a source is crates.io or, through IDNA, may be.
func isCratesIo(source string) (is, maybe bool) {
	kind, raw, _ := strings.Cut(source, "+")
	want, ok := cratesIoIndex[kind]
	if !ok {
		return false, false
	}
	scheme, rest, ok := strings.Cut(crateURLCleaner.Replace(trimC0(raw)), ":")
	// A file URL has no host, so its first path segment is never crates.io's.
	if !ok || strings.EqualFold(scheme, "file") {
		return false, false
	}
	rest = strings.TrimLeft(rest, "/")
	authority, p := rest, ""
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority, p = rest[:i], rest[i:]
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	// Userinfo, query and fragment cannot move the index off crates.io's host.
	host, port, _ := strings.Cut(authority[strings.LastIndex(authority, "@")+1:], ":")
	if port != "" {
		// Cargo keeps any other port, and CanonicalUrl re-parses a github.com index as https.
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n != defaultPort[strings.ToLower(scheme)] && (kind != "registry" || n != 443) {
			return false, false
		}
	}
	host, err := url.PathUnescape(host)
	if err != nil {
		return false, false
	}
	// Cargo's parser keeps an escaped slash in the path, so the index it names is another one.
	if strings.Contains(strings.ToLower(p), "%2f") {
		return false, false
	}
	if p, err = url.PathUnescape(p); err != nil {
		return false, false
	}
	// Cargo maps no path, and ToLower maps 'İ' to 'i', so non-ASCII is tested before case folding.
	if strings.ContainsFunc(p, nonASCII) {
		return false, false
	}
	if strings.TrimSuffix(path.Clean("/"+strings.ToLower(p)), ".git") != want[1] {
		return false, false
	}
	// Cargo's IDNA step maps some non-ASCII registry hosts to github.com and others elsewhere.
	if strings.ContainsFunc(host, nonASCII) {
		return false, kind == "registry"
	}
	return strings.ToLower(host) == want[0], false
}

func nonASCII(r rune) bool { return r > unicode.MaxASCII }

// gitCommit is the locked commit Cargo writes after '#' in a git source.
var gitCommit = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// maxSourceQualifier keeps the percent-encoded value inside the API's 2048-byte purl limit.
const maxSourceQualifier = 512

const unsendableSource = "its source is not a git or registry URL"

// sourceKey is the purl qualifier that marks each Cargo.lock source kind.
var sourceKey = map[string]string{"git": "vcs_url", "registry": "repository_url", "sparse": "repository_url"}

// bare is the qualifier set of a package sent unmarked.
var bare = []map[string]string{nil}

// cargoSourceMarks lists the qualifier sets a package goes out with; a non-empty why drops it.
func cargoSourceMarks(p pkg.Package) (marks []map[string]string, why string) {
	m, ok := p.Metadata.(pkg.RustCargoLockEntry)
	if !ok {
		return bare, ""
	}
	source := strings.TrimSpace(m.Source)
	is, maybe := isCratesIo(source)
	if source == "" || is {
		return bare, ""
	}
	q, why := cargoSourceQualifiers(source)
	if why == "" {
		marks = append(marks, q)
	}
	if maybe {
		marks = append(marks, nil)
	}
	if len(marks) == 0 {
		return nil, why
	}
	return marks, ""
}

// cargoSourceQualifiers marks a git or non-crates.io registry source, falling back to its origin, then its scheme, rather than drop a crate Cargo builds.
func cargoSourceQualifiers(source string) (map[string]string, string) {
	kind, raw, _ := strings.Cut(source, "+")
	key := sourceKey[kind]
	if key == "" {
		// Cargo refuses a lock with any other source kind.
		return nil, unsendableSource
	}
	clean := crateURLCleaner.Replace(trimC0(raw))
	u, err := url.Parse(clean)
	if err != nil || u.Scheme == "" || atPastSlash(clean) {
		// Cargo's parser accepts more than Go's, and a password may sit past a '/', so keep the scheme alone.
		scheme, _, ok := strings.Cut(clean, ":")
		if u, err = url.Parse(scheme + ":/"); !ok || err != nil {
			return nil, unsendableSource
		}
	}
	prefix, p, rawPath, commit := "", "/", "", ""
	if kind == "git" {
		prefix = "git+"
		// With no parsed host Go leaves any userinfo in the path, so only a file URL keeps its path.
		if u.Host != "" || u.Scheme == "file" {
			p, rawPath = u.Path, u.RawPath
		}
		if _, frag, _ := strings.Cut(clean, "#"); gitCommit.MatchString(frag) {
			commit = "@" + frag
		}
	}
	// Userinfo, query and fragment are never copied, nor a registry's path: any of them can hold a token.
	for _, v := range []url.URL{{Scheme: u.Scheme, Host: u.Host, Path: p, RawPath: rawPath}, {Scheme: u.Scheme, Host: u.Host, Path: "/"}, {Scheme: u.Scheme, Path: "/"}} {
		if value := prefix + v.String() + commit; len(value) <= maxSourceQualifier {
			return map[string]string{key: value}, ""
		}
	}
	return nil, "its source is over the API's length limit"
}

// cargoRegistryOf returns the index URL of a registry or sparse source for the trust policy, or "" for git, crates.io or a spelling Go and Cargo may read apart.
func cargoRegistryOf(m pkg.RustCargoLockEntry) string {
	kind, raw, _ := strings.Cut(m.Source, "+")
	// Any byte Go and Cargo may read apart keeps the crate checked, before anything is trimmed or cleaned.
	if strings.ContainsFunc(raw, unplainURLByte) {
		return ""
	}
	if is, _ := isCratesIo(m.Source); is || kind != "registry" && kind != "sparse" {
		return ""
	}
	if _, err := url.Parse(raw); err != nil || atPastSlash(raw) || dotOrEmptySegment(raw) {
		return ""
	}
	return raw
}

// unplainURLByte reports whitespace, a control, non-ASCII, '\' or '%', any of which Go and Cargo may read apart.
func unplainURLByte(r rune) bool { return r < '!' || r > '~' || r == '\\' || r == '%' }

// dotOrEmptySegment reports an empty, "." or ".." path segment, where Cargo's URL parser and the trust policy's path.Clean may land apart.
func dotOrEmptySegment(clean string) bool {
	_, rest, _ := strings.Cut(clean, ":")
	rest = strings.TrimLeft(rest, "/")
	i := strings.IndexAny(rest, "/?#")
	if i < 0 {
		return false
	}
	p := rest[i:]
	if j := strings.IndexAny(p, "?#"); j >= 0 {
		p = p[:j]
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for k, s := range segs {
		// Only the last segment may be empty, as a trailing '/'.
		if s == "." || s == ".." || s == "" && k < len(segs)-1 {
			return true
		}
	}
	return false
}

const (
	sourceReplaced = "a source replacement is configured"
	configIncluded = "a cargo config includes another file"
	configUnread   = "a cargo config could not be read"
	aliasConfig    = "a cargo alias passes --config"
	configLinked   = "a symlink in the scan could point cargo at another config"
)

// cargoReplacement says why no crate is trusted by registry: a symlink in the scan, or a cargo config cargo may read for root that replaces a source, includes a file, has an alias passing --config or cannot be read.
func cargoReplacement(ctx context.Context, r file.Resolver, root string) string {
	root = resolvedRoot(root)
	inScan, why := cargoConfigsInScan(ctx, r, root)
	if why != "" {
		return why
	}
	// A manifest above the root names no source, so only configs decide trust.
	_, above, ok := cargoFilesAbove(root, false, true)
	if !ok {
		return configUnread
	}
	for _, c := range slices.Concat(above, inScan) {
		// Cargo 1.94 merges an included file, which may set replace-with, so any include counts.
		if c.doc["include"] != nil {
			return configIncluded
		}
		sources, _ := c.doc["source"].(map[string]any)
		for _, s := range sources {
			if tomlLookup(s, "replace-with") != nil {
				return sourceReplaced
			}
		}
		// An alias's --config sets a value or names a file the scan never reads.
		for _, args := range cargoAliasArgs(c.doc) {
			if slices.ContainsFunc(args, isConfigArg) {
				return aliasConfig
			}
		}
		if aliasIndeterminate(c.doc) {
			return aliasConfig
		}
	}
	return ""
}

// aliasIndeterminate reports an alias holding a quote or backslash, or a string one starting with '!', which a whitespace split may read apart from cargo or a shell.
func aliasIndeterminate(doc map[string]any) bool {
	aliases, _ := doc["alias"].(map[string]any)
	for _, a := range aliases {
		switch a := a.(type) {
		case string:
			if strings.HasPrefix(strings.TrimSpace(a), "!") || strings.ContainsAny(a, `'"\`) {
				return true
			}
		case []any:
			for _, s := range a {
				if s, ok := s.(string); ok && strings.ContainsAny(s, `'"\`) {
					return true
				}
			}
		}
	}
	return false
}

// cargoConfigsInScan reads every .cargo directory the index holds, or says why not.
func cargoConfigsInScan(ctx context.Context, r file.Resolver, root string) ([]cargoFile, string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	rootSlash := filepath.ToSlash(root)
	var dirs []string
	for l := range r.AllLocations(ctx) {
		m, err := r.FileMetadataByLocation(l)
		if err != nil || m.FileInfo == nil {
			return nil, configUnread
		}
		// cargo walks up from its physical cwd, which a link can move per process, so any link ends trust.
		if m.Mode()&fs.ModeSymlink != 0 {
			return nil, configLinked
		}
		if rel := rootRel(l.RealPath, rootSlash+"/"); m.IsDir() && strings.ToLower(path.Base(rel)) == ".cargo" {
			dirs = append(dirs, placeRef(rootSlash, rel))
		}
	}
	// A cancelled scan closes the walk early, so the links and configs it never reached may still be there.
	if ctx.Err() != nil {
		return nil, configUnread
	}
	var configs []cargoFile
	for _, d := range dirs {
		cs, ok := cargoConfigsIn(filepath.FromSlash(d), filepath.FromSlash(path.Dir(d)), false, true)
		if !ok {
			return nil, configUnread
		}
		configs = append(configs, cs...)
	}
	return configs, ""
}

// atPastSlash reports an '@' after a '/' in the authority or path, where Go reads a password's tail as host or path.
func atPastSlash(clean string) bool {
	_, rest, _ := strings.Cut(clean, ":")
	rest = strings.TrimLeft(rest, "/")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	at := strings.LastIndex(rest, "@")
	return at > 0 && strings.Contains(rest[:at], "/")
}

// qualifierKey spells qualifiers in key order, for keys that must tell sources apart.
func qualifierKey(qualifiers map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(qualifiers)) {
		b.WriteString("?" + k + "=" + qualifiers[k])
	}
	return b.String()
}
