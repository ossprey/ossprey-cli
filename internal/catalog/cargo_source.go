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

// isCratesIo folds at least what Cargo's url crate and CanonicalUrl fold before comparing a source with crates.io.
func isCratesIo(source string) bool {
	kind, raw, _ := strings.Cut(source, "+")
	want, ok := cratesIoIndex[kind]
	if !ok {
		return false
	}
	scheme, rest, ok := strings.Cut(crateURLCleaner.Replace(trimC0(raw)), ":")
	if !ok {
		return false
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
			return false
		}
	}
	host, err := url.PathUnescape(host)
	if err != nil {
		return false
	}
	if p, err = url.PathUnescape(p); err != nil {
		return false
	}
	// Non-ASCII stays foreign before any case folding: IDNA sends a github.com homograph elsewhere, and ToLower maps 'İ' to 'i'.
	if strings.ContainsFunc(host+p, func(r rune) bool { return r > unicode.MaxASCII }) {
		return false
	}
	p = strings.TrimSuffix(path.Clean("/"+strings.ToLower(p)), ".git")
	return p == want[1] && strings.ToLower(host) == want[0]
}

// gitCommit is the locked commit Cargo writes after '#' in a git source.
var gitCommit = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// maxSourceQualifier keeps the percent-encoded value inside the API's 2048-byte purl limit.
const maxSourceQualifier = 512

const unsendableSource = "its Cargo.lock source is not a git or registry URL"

// cargoSourceQualifiers marks a Cargo.lock crate from git or a non-crates.io registry; a non-empty why drops it.
func cargoSourceQualifiers(p pkg.Package) (qualifiers map[string]string, why string) {
	m, ok := p.Metadata.(pkg.RustCargoLockEntry)
	if !ok {
		return nil, ""
	}
	source := strings.TrimSpace(m.Source)
	if source == "" || isCratesIo(source) {
		return nil, ""
	}
	kind, raw, _ := strings.Cut(source, "+")
	u, err := url.Parse(trimC0(raw))
	if err != nil || u.Host == "" {
		return nil, unsendableSource
	}
	// Userinfo, query and fragment are never copied: any of them can hold a token.
	var key, value string
	switch kind {
	case "git":
		key = "vcs_url"
		value = "git+" + (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String()
		if gitCommit.MatchString(u.Fragment) {
			value += "@" + u.Fragment
		}
	case "registry", "sparse":
		// Only the origin: some registries put an access token in the path.
		key = "repository_url"
		value = (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}).String()
	default:
		return nil, unsendableSource
	}
	if len(value) > maxSourceQualifier {
		return nil, "its Cargo.lock source is over the API's length limit"
	}
	return map[string]string{key: value}, ""
}

// qualifierKey spells qualifiers in key order, for keys that must tell sources apart.
func qualifierKey(qualifiers map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(qualifiers)) {
		b.WriteString("?" + k + "=" + qualifiers[k])
	}
	return b.String()
}
