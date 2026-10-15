package alert

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ossprey/ossprey-cli/internal/ansi"
)

// Multi-byte names, at and past the column width, keep every line the box
// width and never split a rune.
func TestMalwareMultibyteFieldsKeepTheBoxWidth(t *testing.T) {
	f := []Finding{
		{Name: strings.Repeat("é", nameCol), Version: strings.Repeat("ü", versionCol), Ecosystem: "pypi"},
		{Name: strings.Repeat("ß", nameCol+40), Version: strings.Repeat("ø", versionCol+3), Ecosystem: strings.Repeat("ñ", 80)},
		{Name: "", Version: "", Ecosystem: ""},
	}
	for _, p := range []ansi.Profile{ansi.None, ansi.TrueColor} {
		out := ansi.Strip(Malware(f, "Git command blocked.", p))
		if !utf8.ValidString(out) {
			t.Fatalf("%v: invalid UTF-8 in banner", p)
		}
		for _, l := range lines(out) {
			if n := utf8.RuneCountInString(l); n != Width {
				t.Errorf("%v: line is %d runes, want %d: %q", p, n, Width, l)
			}
		}
		if !strings.Contains(out, strings.Repeat("é", nameCol)+" ") {
			t.Errorf("%v: a name exactly the column width was truncated", p)
		}
		if !strings.Contains(out, strings.Repeat("ß", nameCol-1)+"…") {
			t.Errorf("%v: an over-long multibyte name was not truncated with an ellipsis", p)
		}
	}
}

// One over the row cap folds into the overflow line, and every caller's
// outcome text fits the headline at the largest realistic count.
func TestMalwareOverflowAndOutcomes(t *testing.T) {
	var nine []Finding
	for i := 0; i < maxRows+1; i++ {
		nine = append(nine, Finding{Name: "pkg" + string(rune('a'+i)), Version: "1", Ecosystem: "npm"})
	}
	out := Malware(nine, "Installation blocked.", ansi.None)
	if !strings.Contains(out, "and 3 more, listed below") {
		t.Errorf("missing overflow line:\n%s", out)
	}

	many := make([]Finding, 9999)
	for _, outcome := range []string{"", "Installation blocked.", "Git command blocked."} {
		out := Malware(many, outcome, ansi.None)
		for _, l := range lines(out) {
			if n := utf8.RuneCountInString(l); n != Width {
				t.Errorf("outcome %q: line is %d runes, want %d: %q", outcome, n, Width, l)
			}
		}
	}
}

// An outcome too long for one headline row wraps inside the box instead of
// panicking on a negative pad; an unbroken run is hard-split.
func TestMalwareLongOutcomeWraps(t *testing.T) {
	f := []Finding{{Name: "evil", Version: "1.0.0", Ecosystem: "npm"}}
	for _, outcome := range []string{
		"Installation blocked because this package was flagged by the Ossprey platform as malicious.",
		strings.Repeat("x", 3*Width),
	} {
		out := ansi.Strip(Malware(f, outcome, ansi.TrueColor))
		for _, l := range lines(out) {
			if n := utf8.RuneCountInString(l); n != Width {
				t.Errorf("line is %d runes, want %d: %q", n, Width, l)
			}
		}
		if got := strings.Count(out, "x"); outcome[0] == 'x' && got != 3*Width {
			t.Errorf("hard-split lost text: %d x's, want %d", got, 3*Width)
		}
	}
	if out := Malware(f, "Installation blocked because this package was flagged.", ansi.None); !strings.Contains(out, "flagged.") {
		t.Errorf("wrapped outcome lost its tail:\n%s", out)
	}
}
