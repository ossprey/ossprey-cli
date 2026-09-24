package monitor

import (
	"strings"
	"testing"
)

func TestRedactKeepsAPrefixAndDropsTheRest(t *testing.T) {
	full := Prefix + strings.Repeat("a", 64)

	got := Redact(full)

	if strings.Contains(got, strings.Repeat("a", 64)) {
		t.Error("the full monitor id reached a log line")
	}
	if !strings.HasPrefix(got, Prefix) || !strings.HasSuffix(got, "...") {
		t.Errorf("Redact(%q) = %q, want a recognisable prefix", full, got)
	}
}

// A value too short to redact by truncation is a value somebody typed wrong --
// or pasted from the wrong secret. Returning it unchanged printed it in full.
func TestRedactMasksAValueTooShortToTruncate(t *testing.T) {
	for _, in := range []string{"", "ospi_TYPO", Prefix + "abcd"} {
		got := Redact(in)
		if strings.Contains(got, "TYPO") || strings.Contains(got, "abcd") {
			t.Errorf("Redact(%q) = %q, want the value masked", in, got)
		}
		if len(got) != len(in) {
			t.Errorf("Redact(%q) = %q, want the same length", in, got)
		}
	}
}
