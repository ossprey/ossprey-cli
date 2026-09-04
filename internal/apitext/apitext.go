// Package apitext makes API-supplied free text safe to print to a terminal.
//
// Finding justifications and threat descriptions are free text that reaches us
// over the wire and gets written straight to a developer's stderr. Control
// characters in that text can forge output: a newline invents an extra report
// line, a carriage return overwrites the one already printed, and an ESC starts
// an ANSI sequence that can recolour or reposition anything around it. None of
// that is hypothetical for a field whose whole job is to describe hostile code.
package apitext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxLen bounds one line of API text. Long enough for a real justification,
// short enough that a runaway field cannot bury the verdict above it.
const maxLen = 500

// OneLine returns s as a single printable line: control and formatting
// characters become spaces, runs of whitespace collapse, and the result is
// trimmed and truncated. Safe to interpolate into a message written to a
// terminal.
func OneLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			// Already-invalid input; drop it rather than re-encode the noise.
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			// Cf covers the bidirectional overrides, which reorder rendered
			// text without being control characters.
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if utf8.RuneCountInString(out) > maxLen {
		// Cut on a rune boundary so truncation cannot emit a partial sequence.
		runes := []rune(out)
		out = string(runes[:maxLen]) + "..."
	}
	return out
}
