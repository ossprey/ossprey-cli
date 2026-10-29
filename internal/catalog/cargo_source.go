package catalog

import (
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

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
	if !ok {
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
	if err != nil || u.Scheme == "" {
		// Cargo's parser accepts more than Go's, so keep the scheme alone.
		scheme, _, ok := strings.Cut(clean, ":")
		if u, err = url.Parse(scheme + ":/"); !ok || err != nil {
			return nil, unsendableSource
		}
	}
	prefix, p, commit := "", "/", ""
	if kind == "git" {
		prefix, p = "git+", u.Path
		if _, frag, _ := strings.Cut(clean, "#"); gitCommit.MatchString(frag) {
			commit = "@" + frag
		}
	}
	// Userinfo, query and fragment are never copied, nor a registry's path: any of them can hold a token.
	for _, v := range []url.URL{{Scheme: u.Scheme, Host: u.Host, Path: p}, {Scheme: u.Scheme, Host: u.Host, Path: "/"}, {Scheme: u.Scheme, Path: "/"}} {
		if value := prefix + v.String() + commit; len(value) <= maxSourceQualifier {
			return map[string]string{key: value}, ""
		}
	}
	return nil, "its source is over the API's length limit"
}

// qualifierKey spells qualifiers in key order, for keys that must tell sources apart.
func qualifierKey(qualifiers map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(qualifiers)) {
		b.WriteString("?" + k + "=" + qualifiers[k])
	}
	return b.String()
}
