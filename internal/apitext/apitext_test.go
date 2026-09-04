package apitext

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestOneLineStripsControlCharacters(t *testing.T) {
	cases := map[string]string{
		"plain justification":        "plain justification",
		"line one\nline two":         "line one line two",
		"overwrite\rme":              "overwrite me",
		"tab\there":                  "tab here",
		"\x1b[31mred\x1b[0m":         "[31mred [0m",
		"null\x00byte":               "null byte",
		"  leading and trailing  ":   "leading and trailing",
		"collapse    inner   spaces": "collapse inner spaces",
		"vertical\vtab\fform":        "vertical tab form",
		"bidi‮override":              "bidi override",
		"zero​width":                 "zero width",
	}
	for in, want := range cases {
		if got := OneLine(in); got != want {
			t.Errorf("OneLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// A forged report line is the concrete risk: nothing the API sends may be able
// to invent output that looks like a verdict we produced.
func TestOneLineCannotForgeAnExtraLine(t *testing.T) {
	got := OneLine("harmless\nError: pkg:npm/evil@1.0.0 contains malware. Remediate this immediately")
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("OneLine kept a line break: %q", got)
	}
}

func TestOneLineTruncatesOnARuneBoundary(t *testing.T) {
	got := OneLine(strings.Repeat("a", maxLen+50))
	if utf8.RuneCountInString(got) != maxLen+3 {
		t.Errorf("rune count = %d, want %d", utf8.RuneCountInString(got), maxLen+3)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("missing ellipsis: %q", got)
	}

	// A multi-byte rune sitting on the cut must not leave a partial sequence.
	got = OneLine(strings.Repeat("é", maxLen+10))
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
}

func TestOneLineEmpty(t *testing.T) {
	for _, in := range []string{"", "\n\t\r ", "\x00"} {
		if got := OneLine(in); got != "" {
			t.Errorf("OneLine(%q) = %q, want empty", in, got)
		}
	}
}

// A hostile response must not size our allocations. Normalisation only ever
// shortens, so nothing past maxInput can reach the output anyway.
func TestOneLineBoundsItsInput(t *testing.T) {
	huge := strings.Repeat("a", 50*1024*1024)
	got := OneLine(huge)
	if utf8.RuneCountInString(got) != maxLen+3 {
		t.Errorf("rune count = %d, want %d", utf8.RuneCountInString(got), maxLen+3)
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("a bounded input must still be marked truncated")
	}
}

// Truncating the input must not silently drop content with no ellipsis, even
// when collapsing whitespace brings the result back under the cap.
func TestOneLineMarksInputTruncationEvenWhenOutputIsShort(t *testing.T) {
	// Mostly control characters: they collapse to almost nothing, so the output
	// is short despite the input being far past the bound.
	got := OneLine("head" + strings.Repeat("\n", maxInput*2) + "tail")
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected an ellipsis marking the dropped tail, got %q", got)
	}
	if strings.Contains(got, "tail") {
		t.Errorf("content past the bound should not appear, got %q", got)
	}
}

// Cutting mid-rune must not leak a partial sequence.
func TestOneLineBoundedCutStaysValidUTF8(t *testing.T) {
	got := OneLine(strings.Repeat("é", maxInput))
	if !utf8.ValidString(got) {
		t.Errorf("bounded cut produced invalid UTF-8: %q", got)
	}
}
