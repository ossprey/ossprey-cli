package catalog

import (
	"maps"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// cratesIoIndex is crates.io's index host and path for each Cargo.lock source kind.
var cratesIoIndex = map[string][2]string{
	"registry": {"github.com", "/rust-lang/crates.io-index"},
	"sparse":   {"index.crates.io", "/"},
}

// defaultPort is the port the WHATWG URL parser drops for each special scheme.
var defaultPort = map[string]uint64{"ftp": 21, "http": 80, "https": 443, "ws": 80, "wss": 443}

// crateURLCleaner applies the WHATWG URL parser's tab and newline removal and its reading of '\' as '/'.
var crateURLCleaner = strings.NewReplacer("\t", "", "\n", "", "\r", "", `\`, "/")

// isCratesIo folds at least what Cargo's url crate and CanonicalUrl fold before comparing a source with crates.io.
func isCratesIo(source string) bool {
	kind, raw, _ := strings.Cut(source, "+")
	want, ok := cratesIoIndex[kind]
	if !ok {
		return false
	}
	scheme, rest, ok := strings.Cut(crateURLCleaner.Replace(raw), ":")
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
	p = strings.TrimSuffix(path.Clean("/"+strings.ToLower(p)), ".git")
	// A non-ASCII host stays foreign: IDNA maps a homograph of github.com to another domain.
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

// cargoOwns reports whether p's Cargo.toml sighting at loc means marked crate m: that workspace locks m, at p's pin if any, and not p from crates.io.
func cargoOwns(pkgs []Package) func(m, p Package, loc string) bool {
	locks := map[string]bool{}
	for _, p := range pkgs {
		for _, l := range p.sightings {
			if l = filepath.ToSlash(l); path.Base(l) == "Cargo.lock" {
				locks[path.Dir(l)] = true
			}
		}
	}
	// workspace is the directory of the nearest Cargo.lock at or above loc, "" when none.
	workspace := func(loc string) string {
		for d := path.Dir(filepath.ToSlash(loc)); ; d = path.Dir(d) {
			if locks[d] {
				return d
			}
			if d == path.Dir(d) {
				return ""
			}
		}
	}
	return func(m, p Package, loc string) bool {
		ws := workspace(loc)
		inWorkspace := func(l string) bool { return workspace(l) == ws }
		cratesIoLock := func(l string) bool { return path.Base(filepath.ToSlash(l)) == "Cargo.lock" && inWorkspace(l) }
		return ws != "" && path.Base(filepath.ToSlash(loc)) == "Cargo.toml" && (p.Version == "" || p.Version == m.Version) &&
			slices.ContainsFunc(m.sightings, inWorkspace) && !slices.ContainsFunc(p.sightings, cratesIoLock)
	}
}
