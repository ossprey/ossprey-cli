package catalog

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

// requirementPins re-derives the version a requirements file pins for a package
// and corrects the one syft reported for it.
//
// Syft's requirements.txt parser captures the constraint with the character
// class [0-9a-zA-Z.*], which silently truncates every PEP 440 separator outside
// it. "==1.0.0-beta.1" is reported as "1.0.0", "==1.2.3+local1" as "1.2.3" and
// "==1!2.0.0" as "1" — versions that look real but name a different release
// than the project installs (or none at all, so the purl 404s and the scan
// errors). PEP 440's arbitrary-equality operator fares no better: syft's
// parseVersion strips only "==", so "===0.1.138.0" is reported as "=0.1.138.0"
// (OSS-1869).
//
// Only requirements that pin exactly one release are corrected. A range, a
// wildcard or a multi-constraint spec is left to syft's own guess — those never
// name a single version to carry through in the first place.
//
// This corrects; it does not catalog. Shapes syft drops outright rather than
// mangles — a bare ">2.0", or a PEP 440 epoch like "==1!2.0.0", where its guess
// yields no version at all — stay missing. That is a coverage gap in syft, not
// a wrong version, and the resolver-backed catalogers (uv) are what close it.
//
// Files are parsed at most once per Catalog run (cache keyed by path). Not safe
// for concurrent use — Catalog consumes cataloger output serially.
type requirementPins struct {
	root  string
	cache map[string]map[string][]string // requirements file abs path -> canonical name -> versions
}

// newRequirementPins returns a corrector for the requirements files under root.
func newRequirementPins(root string) *requirementPins {
	return &requirementPins{root: root, cache: map[string]map[string][]string{}}
}

// versionFor returns the version p's requirements file pins for it, and whether
// it pins one at all. Packages syft parsed from anything other than a
// requirements file are left alone.
func (r *requirementPins) versionFor(p pkg.Package) (string, bool) {
	if _, ok := p.Metadata.(pkg.PythonRequirementsEntry); !ok {
		return "", false
	}
	name := canonicalPackageName(p.Name)
	for _, l := range p.Locations.ToSlice() {
		if v, ok := matchPin(r.pins(hostPath(r.root, l.RealPath))[name], p.Version); ok {
			return v, true
		}
	}
	return "", false
}

// matchPin picks the pin that reported is a truncation of. One name can be
// pinned more than once in a file — most often under mutually exclusive
// environment markers ("foo==1.0.0-beta.1 ; python_version < '3.9'" and
// "foo==2.0.0-beta.1 ; python_version >= '3.9'"), which syft emits as two
// packages. Keying pins by name alone applied the last one to both, so
// deduplication then collapsed them into a single component and the other
// version vanished from the SBOM entirely — unscanned, which is worse than a
// truncated version.
//
// Since the defect is truncation, syft's version is a prefix of the pin it came
// from (a leading "=" first, from the "===" operator it fails to strip). That
// identifies the pin without having to reconcile marker text, which syft's own
// capture does not preserve faithfully. Correct only on a unique match: zero
// leaves a version we cannot attribute, and more than one (two pins truncating
// alike, e.g. 1.0.0-beta.1 and 1.0.0-beta.2) would be a guess, so both keep
// syft's value.
func matchPin(pins []string, reported string) (string, bool) {
	reported = strings.TrimPrefix(reported, "=")
	var match string
	var n int
	for _, pin := range pins {
		if strings.HasPrefix(pin, reported) {
			match, n = pin, n+1
		}
	}
	if n != 1 {
		return "", false
	}
	return match, true
}

// pins returns every exact pin in the requirements file at path, grouped by
// canonical name. Each file is read and parsed once per Catalog run; an
// unreadable one caches an empty result so every package from it keeps syft's
// version rather than re-reading per package.
func (r *requirementPins) pins(path string) map[string][]string {
	if pins, ok := r.cache[path]; ok {
		return pins
	}
	data, err := os.ReadFile(path)
	if err != nil {
		r.cache[path] = nil // unreadable: keep syft's version, don't retry
		return nil
	}
	pins := pinnedRequirements(data)
	r.cache[path] = pins
	return pins
}

// pinnedRequirement matches a requirement pinning exactly one release, once the
// line has been stripped of comments, environment markers, pip options and
// whitespace: a name, optional extras, "==" or PEP 440's arbitrary-equality
// "===", then the version. The version class excludes every comparator and
// separator that would mean more than one release (",", "*", "<", ">", "!",
// "~", "="), so ranges, wildcards and multi-constraint specs never match.
var pinnedRequirement = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:===|==)([^,*<>!~=\s]+)$`)

// pinnedRequirements maps the PEP 503 canonical name of every exactly-pinned
// requirement in one requirements file to the versions it pins — plural,
// because environment markers let one name be pinned several times.
func pinnedRequirements(data []byte) map[string][]string {
	pins := map[string][]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var continued string
	for sc.Scan() {
		line := stripRequirementComment(strings.TrimRight(sc.Text(), "\r"))
		// A trailing backslash continues the requirement on the next line.
		if before, ok := strings.CutSuffix(strings.TrimRight(line, " \t"), `\`); ok {
			continued += before + " "
			continue
		}
		line, continued = continued+line, ""
		if name, version, ok := parsePinnedRequirement(line); ok {
			pins[name] = append(pins[name], version)
		}
	}
	return pins
}

// parsePinnedRequirement extracts the canonical name and version from one
// logical requirements line, and reports whether the line pins exactly one
// release at all. Comments, environment markers and pip options are stripped
// first; option lines, editables and URL requirements pin nothing.
func parsePinnedRequirement(line string) (name, version string, ok bool) {
	spec := strings.TrimSpace(line)
	// Blank, or a pip option / "-r" include / "-e" editable rather than a
	// requirement.
	if spec == "" || strings.HasPrefix(spec, "-") {
		return "", "", false
	}
	if i := strings.IndexByte(spec, ';'); i >= 0 {
		spec = spec[:i] // PEP 508 environment marker
	}
	// Drop per-requirement pip options ("--hash=sha256:...", "--global-option").
	fields := strings.Fields(spec)
	for i, f := range fields {
		if strings.HasPrefix(f, "--") {
			fields = fields[:i]
			break
		}
	}
	// A PEP 440 name, extras list and version all forbid whitespace, so joining
	// the fields normalises "pkg [extra] == 1.0" without altering any of them.
	m := pinnedRequirement.FindStringSubmatch(strings.Join(fields, ""))
	if m == nil {
		return "", "", false
	}
	return canonicalPackageName(m[1]), m[2], true
}

// stripRequirementComment removes a trailing "#" comment. pip only treats "#"
// as a comment at the start of a line or after whitespace, so a "#egg=" URL
// fragment survives — unlike a naive cut at the first "#".
func stripRequirementComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] != '#' {
			continue
		}
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			return line[:i]
		}
	}
	return line
}
