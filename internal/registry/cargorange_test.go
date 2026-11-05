package registry

import "testing"

// TestCargoSatisfies pins Cargo's requirement semantics from the Cargo book's "Specifying dependencies" page.
func TestCargoSatisfies(t *testing.T) {
	for _, c := range []struct {
		req, version string
		match, ok    bool
	}{
		{"1.2.3", "1.9.0", true, true},
		{"1.2.3", "2.0.0", false, true},
		{"1.2", "1.2.0", true, true},
		{"1", "1.9.9", true, true},
		{"0.2.3", "0.2.9", true, true},
		{"0.2.3", "0.3.0", false, true},
		{"0.0.3", "0.0.4", false, true},
		{"0.0", "0.0.9", true, true},
		{"0", "0.9.0", true, true},
		{"^1.2.3", "1.2.2", false, true},
		{"~1.2.3", "1.2.9", true, true},
		{"~1.2.3", "1.3.0", false, true},
		{"~1", "1.9.0", true, true},
		{"=1.0.0", "1.0.0", true, true},
		{"=1.0.0", "2.0.0", false, true},
		{"=1.2", "1.2.7", true, true},
		{"*", "3.0.0", true, true},
		{"1.*", "1.4.0", true, true},
		{"1.2.*", "1.3.0", false, true},
		{">= 1.2, < 1.5", "1.4.9", true, true},
		{">= 1.2, < 1.5", "1.5.0", false, true},
		{">1.2", "1.2.5", false, true},
		{"<=1.2", "1.2.9", true, true},
		// A prerelease only matches a requirement naming one of the same release, and build metadata is ignored.
		{"1.0.0", "1.1.0-alpha.1", false, true},
		{"1.1.0-alpha.0", "1.1.0-alpha.1", true, true},
		{"0.9", "0.9.12+spec-1.1.0", true, true},
		{"1.2.3-alpha.x", "1.4.0", true, true},
		{"1.2.3+build.x", "1.4.0", true, true},
		// Numeric prerelease identifiers compare by length then lexically, as Cargo's semver crate does, however long they are.
		{">=1.0.0-100000000000000000000", "1.0.0-99999999999999999999", false, true},
		{"<1.0.0-100000000000000000000", "1.0.0-99999999999999999999", true, true},
		{">=1.0.0-99999999999999999999", "1.0.0-100000000000000000000", true, true},
		{"=1.0.0-18446744073709551616", "1.0.0-18446744073709551616", true, true},
		{">=1.0.0-alpha.10", "1.0.0-alpha.9", false, true},
		{">=1.0.0-99999999999999999999", "1.0.0-alpha", true, true},
		{">=1.0.0-alpha", "1.0.0-99999999999999999999", false, true},
		// Core numbers are u64 as in Cargo's semver crate, nothing lies past u64::MAX, and a larger number is refused.
		{">=18446744073709551615.0.0", "9223372036854775807.0.0", false, true},
		{">=18446744073709551615.0.0", "18446744073709551615.0.0", true, true},
		{"<18446744073709551615.0.0", "9223372036854775807.0.0", true, true},
		{"=18446744073709551615.18446744073709551615.18446744073709551615", "18446744073709551615.18446744073709551615.18446744073709551615", true, true},
		{"18446744073709551615", "18446744073709551615.1.0", true, true},
		{"18446744073709551615.*", "18446744073709551615.3.0", true, true},
		{"~0.18446744073709551615", "0.18446744073709551615.7", true, true},
		{"~0.18446744073709551615", "1.0.0", false, true},
		{"^0.0.18446744073709551615", "0.0.18446744073709551615", true, true},
		{"^0.0.18446744073709551615", "0.1.0", false, true},
		{">18446744073709551615", "18446744073709551615.1.0", false, true},
		{">18446744073709551615", "1.0.0", false, true},
		{">5.18446744073709551615", "6.0.0", true, true},
		{"<=18446744073709551615", "18446744073709551615.9.9", true, true},
		{"18446744073709551616.0.0", "1.0.0", false, false},
		{">=1.0, <1.18446744073709551616", "1.0.0", false, false},
		{"1.0.0", "18446744073709551616.0.0", false, false},
		// Not Cargo's grammar.
		{"1.0 || 2.0", "1.0.0", false, false},
		{"1.0 - 2.0", "1.0.0", false, false},
		{"", "1.0.0", false, false},
		{"1.0", "not-a-version", false, false},
	} {
		match, ok := CargoSatisfies(c.req, c.version)
		if match != c.match || ok != c.ok {
			t.Errorf("CargoSatisfies(%q, %q) = %v, %v; want %v, %v", c.req, c.version, match, ok, c.match, c.ok)
		}
	}
}
