package catalog

import (
	"maps"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/anchore/syft/syft/pkg"
)

// cratesIoIndex is crates.io's index host and path for each Cargo.lock source kind.
var cratesIoIndex = map[string][2]string{
	"registry": {"github.com", "/rust-lang/crates.io-index"},
	"sparse":   {"index.crates.io", "/"},
}

// crateURLCleaner applies the WHATWG URL parser's tab and newline removal and its reading of '\' as '/'.
var crateURLCleaner = strings.NewReplacer("\t", "", "\n", "", "\r", "", `\`, "/")

// isCratesIo folds at least what Cargo's url crate and CanonicalUrl fold before comparing a source with crates.io.
func isCratesIo(source string) bool {
	kind, raw, _ := strings.Cut(source, "+")
	want, ok := cratesIoIndex[kind]
	if !ok {
		return false
	}
	_, rest, ok := strings.Cut(crateURLCleaner.Replace(raw), ":")
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
	// Userinfo, port, query and fragment cannot move the index off crates.io's host.
	host, _, _ := strings.Cut(authority[strings.LastIndex(authority, "@")+1:], ":")
	host, err := url.PathUnescape(host)
	if err != nil {
		return false
	}
	if p, err = url.PathUnescape(p); err != nil {
		return false
	}
	p = strings.TrimSuffix(path.Clean("/"+strings.ToLower(p)), ".git")
	// Cargo maps a non-ASCII registry+ host through IDNA, so it may be github.com; a sparse+ host is opaque to it.
	return p == want[1] && (strings.ToLower(host) == want[0] || kind == "registry" && !isASCII(host))
}

func isASCII(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r >= utf8.RuneSelf }) < 0
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
	u, err := url.Parse(raw)
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

// cargoWorkspaces maps a location to the directory of the nearest Cargo.lock at or above it, "" when none.
func cargoWorkspaces(pkgs []Package) func(loc string) string {
	locks := map[string]bool{}
	for _, p := range pkgs {
		for _, l := range p.Locations {
			if l = filepath.ToSlash(l); path.Base(l) == "Cargo.lock" {
				locks[path.Dir(l)] = true
			}
		}
	}
	return func(loc string) string {
		for d := path.Dir(filepath.ToSlash(loc)); ; d = path.Dir(d) {
			if locks[d] {
				return d
			}
			if d == path.Dir(d) {
				return ""
			}
		}
	}
}
