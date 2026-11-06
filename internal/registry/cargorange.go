package registry

import (
	"regexp"
	"strconv"
	"strings"
)

// cargoRelease matches a concrete crates.io release, which is always full three-component semver with no leading zero or empty identifier, so "=1.0" is a range rather than a pin.
var cargoRelease = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// IsCargoRelease reports whether s is a release cargo's semver parser accepts, whose core numbers fit in a u64.
func IsCargoRelease(s string) bool {
	if !cargoRelease.MatchString(s) {
		return false
	}
	core, _, _ := strings.Cut(strings.SplitN(s, "+", 2)[0], "-")
	for _, n := range strings.Split(core, ".") {
		if _, err := strconv.ParseUint(n, 10, 64); err != nil {
			return false
		}
	}
	return true
}

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
