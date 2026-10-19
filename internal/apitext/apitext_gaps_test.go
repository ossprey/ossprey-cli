package apitext

import (
	"strings"
	"testing"
	"unicode"
)

// Every rune that can move the cursor, reorder text, hide text or start an
// escape sequence must be gone from the output, whatever category it sits in.
func TestOneLineNeutralisesHostileRunes(t *testing.T) {
	hostile := map[string]string{
		"C1 CSI":                "\u009b31m",
		"C1 OSC":                "\u009d0;title\u009c",
		"NEL":                   "\u0085",
		"line separator":        "\u2028",
		"paragraph separator":   "\u2029",
		"LRO":                   "\u202d",
		"RLO":                   "\u202e",
		"PDF":                   "\u202c",
		"LRI":                   "\u2066",
		"RLI":                   "\u2067",
		"FSI":                   "\u2068",
		"PDI":                   "\u2069",
		"arabic letter mark":    "\u061c",
		"LRM":                   "\u200e",
		"RLM":                   "\u200f",
		"zero width joiner":     "\u200d",
		"zero width non-joiner": "\u200c",
		"word joiner":           "\u2060",
		"BOM":                   "\ufeff",
		"soft hyphen":           "\u00ad",
		"tag character":         "\U000e0041",
		"OSC 8 hyperlink":       "\x1b]8;;https://evil.example\x07click\x1b]8;;\x07",
		"BEL":                   "\x07",
		"backspace":             "\x08",
		"DEL":                   "\x7f",
		"invalid byte":          "\x9b",
		"invalid ESC lookalike": "\xc0\x9b",
	}
	for name, seq := range hostile {
		got := OneLine("before" + seq + "after")
		for _, r := range got {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' || r == unicode.ReplacementChar {
				t.Errorf("%s: output %q still holds %U", name, got, r)
			}
		}
		if !strings.HasPrefix(got, "before") || !strings.HasSuffix(got, "after") {
			t.Errorf("%s: surrounding text lost: %q", name, got)
		}
	}
}

// Ordinary non-ASCII text is a real justification and passes through intact.
func TestOneLineKeepsPrintableUnicode(t *testing.T) {
	for _, in := range []string{"café naïve", "日本語のパッケージ", "Ελληνικά", "emoji 🐍 ok"} {
		if got := OneLine(in); got != in {
			t.Errorf("OneLine(%q) = %q, want it unchanged", in, got)
		}
	}
}
