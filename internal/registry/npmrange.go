package registry

import (
	"regexp"
	"strconv"
	"strings"
)

// A port of the parts of node-semver (classes/range.js, functions/compare.js)
// that npm uses to pick a release for a range: enough to answer "which version
// would `npm install name@<range>` fetch". TestNpmRangeMatchesNodeSemver diffs
// it against the semver npm bundles.

type semver struct {
	major, minor, patch int
	pre                 []string
}

// semverRe is node-semver's LOOSE version: "v"/"=" prefix, optional "-" before
// the prerelease, build metadata ignored.
var semverRe = regexp.MustCompile(`^[v=\s]*(\d+)\.(\d+)\.(\d+)(?:-?([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func parseSemver(s string) (semver, bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	var v semver
	var err error
	if v.major, err = strconv.Atoi(m[1]); err != nil {
		return semver{}, false
	}
	if v.minor, err = strconv.Atoi(m[2]); err != nil {
		return semver{}, false
	}
	if v.patch, err = strconv.Atoi(m[3]); err != nil {
		return semver{}, false
	}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
	}
	return v, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (a semver) compare(b semver) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	// A release sorts above any of its prereleases.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; ; i++ {
		switch {
		case i >= len(a.pre) && i >= len(b.pre):
			return 0
		case i >= len(a.pre):
			return -1
		case i >= len(b.pre):
			return 1
		}
		x, y := a.pre[i], b.pre[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		var c int
		switch {
		case xerr == nil && yerr == nil:
			c = cmpInt(xn, yn)
		case xerr == nil:
			c = -1 // numeric identifiers sort below alphanumeric ones
		case yerr == nil:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
}

type comparator struct {
	op  string // "", "<", "<=", ">", ">="; "" with any=true matches everything
	v   semver
	any bool
}

func (c comparator) test(v semver) bool {
	if c.any {
		return true
	}
	r := v.compare(c.v)
	switch c.op {
	case "<":
		return r < 0
	case "<=":
		return r <= 0
	case ">":
		return r > 0
	case ">=":
		return r >= 0
	}
	return r == 0
}

// npmRange is a parsed range: the version must satisfy every comparator of at
// least one set.
type npmRange [][]comparator

var (
	partialRe = `[v=\s]*(\d+|[xX*])(?:\.(\d+|[xX*])(?:\.(\d+|[xX*])(?:-?([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)?)?`
	hyphenRe  = regexp.MustCompile(`^\s*(` + partialRe + `)\s+-\s+(` + partialRe + `)\s*$`)
	compRe    = regexp.MustCompile(`^(~>?|\^|<=|>=|<|>|=)?` + partialRe + `$`)
	// node-semver's comparatorTrim/tildeTrim/caretTrim: "> 1.2" is ">1.2".
	opSpaceRe = regexp.MustCompile(`(~>?|\^|<=|>=|<|>|=)\s+`)
)

func isX(s string) bool { return s == "" || s == "x" || s == "X" || s == "*" }

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func ver(major, minor, patch int, pre ...string) semver {
	return semver{major, minor, patch, pre}
}

func preOf(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

var (
	anyComp  = comparator{any: true}
	zeroPre  = "0"
	nothingC = comparator{op: "<", v: ver(0, 0, 0, zeroPre)}
)

// parseNpmRange parses a range, or reports false for a string that is not one
// (which npm then treats as a dist-tag).
func parseNpmRange(r string) (npmRange, bool) {
	var out npmRange
	for _, set := range strings.Split(r, "||") {
		cs, ok := parseCompSet(strings.TrimSpace(set))
		if !ok {
			return nil, false
		}
		out = append(out, cs)
	}
	return out, true
}

func parseCompSet(set string) ([]comparator, bool) {
	if m := hyphenRe.FindStringSubmatch(set); m != nil {
		return hyphen(m[2:6], m[7:11]), true
	}
	set = opSpaceRe.ReplaceAllString(set, "$1")
	fields := strings.Fields(set)
	if len(fields) == 0 {
		return []comparator{anyComp}, true
	}
	var out []comparator
	for _, f := range fields {
		m := compRe.FindStringSubmatch(f)
		if m == nil {
			return nil, false
		}
		out = append(out, desugar(m[1], m[2], m[3], m[4], m[5])...)
	}
	return out, true
}

func hyphen(from, to []string) []comparator {
	var out []comparator
	switch {
	case isX(from[0]):
	case isX(from[1]):
		out = append(out, comparator{op: ">=", v: ver(atoi(from[0]), 0, 0)})
	case isX(from[2]):
		out = append(out, comparator{op: ">=", v: ver(atoi(from[0]), atoi(from[1]), 0)})
	default:
		out = append(out, comparator{op: ">=", v: ver(atoi(from[0]), atoi(from[1]), atoi(from[2]), preOf(from[3])...)})
	}
	switch {
	case isX(to[0]):
	case isX(to[1]):
		out = append(out, comparator{op: "<", v: ver(atoi(to[0])+1, 0, 0, zeroPre)})
	case isX(to[2]):
		out = append(out, comparator{op: "<", v: ver(atoi(to[0]), atoi(to[1])+1, 0, zeroPre)})
	default:
		out = append(out, comparator{op: "<=", v: ver(atoi(to[0]), atoi(to[1]), atoi(to[2]), preOf(to[3])...)})
	}
	if len(out) == 0 {
		out = append(out, anyComp)
	}
	return out
}

// desugar expands one comparator (tilde, caret, x-range or primitive) into
// primitive comparators, as node-semver's replaceTilde/replaceCaret/
// replaceXRange do.
func desugar(op, M, m, p, pr string) []comparator {
	xM, xm, xp := isX(M), isX(M) || isX(m), isX(M) || isX(m) || isX(p)
	maj, min, pat := atoi(M), atoi(m), atoi(p)
	ge := func(v semver) comparator { return comparator{op: ">=", v: v} }
	lt := func(v semver) comparator { return comparator{op: "<", v: v} }
	switch op {
	case "~", "~>":
		switch {
		case xM:
			return []comparator{anyComp}
		case xm:
			return []comparator{ge(ver(maj, 0, 0)), lt(ver(maj+1, 0, 0, zeroPre))}
		case xp:
			return []comparator{ge(ver(maj, min, 0)), lt(ver(maj, min+1, 0, zeroPre))}
		}
		return []comparator{ge(ver(maj, min, pat, preOf(pr)...)), lt(ver(maj, min+1, 0, zeroPre))}
	case "^":
		switch {
		case xM:
			return []comparator{anyComp}
		case xm:
			return []comparator{ge(ver(maj, 0, 0)), lt(ver(maj+1, 0, 0, zeroPre))}
		case xp:
			if maj == 0 {
				return []comparator{ge(ver(maj, min, 0)), lt(ver(maj, min+1, 0, zeroPre))}
			}
			return []comparator{ge(ver(maj, min, 0)), lt(ver(maj+1, 0, 0, zeroPre))}
		}
		from := ge(ver(maj, min, pat, preOf(pr)...))
		switch {
		case maj == 0 && min == 0:
			return []comparator{from, lt(ver(0, 0, pat+1, zeroPre))}
		case maj == 0:
			return []comparator{from, lt(ver(0, min+1, 0, zeroPre))}
		}
		return []comparator{from, lt(ver(maj+1, 0, 0, zeroPre))}
	}

	// x-ranges and primitives.
	if op == "=" && xp {
		op = ""
	}
	switch {
	case xM:
		if op == ">" || op == "<" {
			return []comparator{nothingC}
		}
		return []comparator{anyComp}
	case op != "" && xp:
		if xm {
			min = 0
		}
		pat = 0
		var pre []string
		switch op {
		case ">":
			op = ">="
			if xm {
				maj, min = maj+1, 0
			} else {
				min++
			}
		case "<=":
			op = "<"
			if xm {
				maj++
			} else {
				min++
			}
		}
		if op == "<" {
			pre = []string{zeroPre}
		}
		return []comparator{{op: op, v: ver(maj, min, pat, pre...)}}
	case xm:
		return []comparator{ge(ver(maj, 0, 0)), lt(ver(maj+1, 0, 0, zeroPre))}
	case xp:
		return []comparator{ge(ver(maj, min, 0)), lt(ver(maj, min+1, 0, zeroPre))}
	}
	if op == "=" {
		op = ""
	}
	return []comparator{{op: op, v: ver(maj, min, pat, preOf(pr)...)}}
}

// satisfies is node-semver's Range.test without includePrerelease: a
// prerelease only matches a set that names a prerelease of the same release.
func (r npmRange) satisfies(v semver) bool {
	for _, set := range r {
		if testSet(set, v) {
			return true
		}
	}
	return false
}

func testSet(set []comparator, v semver) bool {
	for _, c := range set {
		if !c.test(v) {
			return false
		}
	}
	if len(v.pre) == 0 {
		return true
	}
	for _, c := range set {
		if !c.any && len(c.v.pre) > 0 &&
			c.v.major == v.major && c.v.minor == v.minor && c.v.patch == v.patch {
			return true
		}
	}
	return false
}

// pickNpmVersion is npm-pick-manifest's choice for a range: the `latest` tag
// when it satisfies the range and is not deprecated, else the highest
// non-deprecated version that does, else the highest deprecated one. Engine
// compatibility, which npm also ranks on, is not modelled. ok is false when
// spec is not a range (it is a dist-tag) or nothing satisfies it.
func pickNpmVersion(spec, latest string, versions []string, deprecated map[string]bool) (string, bool) {
	r, ok := parseNpmRange(spec)
	if !ok {
		return "", false
	}
	if lv, ok := parseSemver(latest); ok && r.satisfies(lv) && !deprecated[latest] {
		return latest, true
	}
	best, bestV, bestDep := "", semver{}, false
	for _, s := range versions {
		v, ok := parseSemver(s)
		if !ok || !r.satisfies(v) {
			continue
		}
		dep := deprecated[s]
		if best == "" || (bestDep && !dep) || (dep == bestDep && v.compare(bestV) > 0) {
			best, bestV, bestDep = s, v, dep
		}
	}
	return best, best != ""
}
