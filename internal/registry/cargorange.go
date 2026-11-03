package registry

import "strings"

// CargoSatisfies reports whether version meets a Cargo requirement via the npm port; ok is false if unreadable.
func CargoSatisfies(req, version string) (match, ok bool) {
	v, ok := parseSemver(version)
	if !ok || strings.ContainsAny(req, "|") {
		return false, false
	}
	var parts []string
	for _, c := range strings.Split(req, ",") {
		c = opSpaceRe.ReplaceAllString(strings.TrimSpace(c), "$1")
		if c == "" || strings.ContainsAny(c, " \t") {
			return false, false
		}
		// A wildcard in the release core is an x-range in both grammars, so only a plain bare version gains the caret.
		if core, _, _ := strings.Cut(strings.SplitN(c, "+", 2)[0], "-"); c[0] >= '0' && c[0] <= '9' && !strings.ContainsAny(core, "*xX") {
			c = "^" + c
		}
		parts = append(parts, c)
	}
	r, ok := parseNpmRange(strings.Join(parts, " "))
	if !ok {
		return false, false
	}
	return r.satisfies(v), true
}
