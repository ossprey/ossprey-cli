package catalog

import (
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// cratesIoSources are the spellings Cargo's SourceId::is_crates_io accepts; a default dependency locks as the first.
var cratesIoSources = map[string]bool{
	"registry+https://github.com/rust-lang/crates.io-index": true,
	"sparse+https://index.crates.io/":                       true,
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
	if source == "" || cratesIoSources[source] {
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
