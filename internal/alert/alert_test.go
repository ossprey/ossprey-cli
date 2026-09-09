package alert

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ossprey/ossprey-cli/internal/ansi"
)

var two = []Finding{
	{Name: "requests", Version: "2.31.0", Ecosystem: "pypi"},
	{Name: "left-pad", Version: "1.3.0", Ecosystem: "npm"},
}

func lines(s string) []string {
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

func TestMalwareEveryLineIsBoxWidth(t *testing.T) {
	for _, l := range lines(Malware(two, "Installation blocked.", ansi.None)) {
		if n := utf8.RuneCountInString(l); n != Width {
			t.Errorf("line is %d runes, want %d: %q", n, Width, l)
		}
		if !strings.HasPrefix(l, "│") && !strings.HasPrefix(l, "┌") && !strings.HasPrefix(l, "└") {
			t.Errorf("line does not start with a box edge: %q", l)
		}
	}
}

func TestMalwareNamesLetters(t *testing.T) {
	out := Malware(two, "Installation blocked.", ansi.None)
	if !strings.Contains(out, "███╗   ███╗ █████╗ ██╗     ██╗    ██╗ █████╗ ██████╗ ███████╗") {
		t.Fatalf("missing MALWARE lettering:\n%s", out)
	}
}

func TestMalwareListsEachFinding(t *testing.T) {
	out := Malware(two, "Installation blocked.", ansi.None)
	for _, want := range []string{
		"Ossprey found 2 malicious packages. Installation blocked.",
		"PACKAGE", "VERSION", "ECOSYSTEM",
		"requests                   2.31.0       pypi",
		"left-pad                   1.3.0        npm",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	for _, gone := range []string{"dashboard.ossprey.com", "ADVISORY", "Remediate this immediately"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q should be gone:\n%s", gone, out)
		}
	}
}

func TestMalwareSingularWording(t *testing.T) {
	out := Malware(two[:1], "", ansi.None)
	for _, want := range []string{
		"Ossprey found 1 malicious package.  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestMalwareTruncatesLongFields(t *testing.T) {
	f := []Finding{{
		Name:      "@some-organisation/an-extremely-long-package-name",
		Version:   "1.0.0-beta.12345678+build.999",
		Ecosystem: "npm",
	}}
	out := Malware(f, "Installation blocked.", ansi.None)
	if !strings.Contains(out, "@some-organisation/an-ext…") {
		t.Errorf("name not truncated with ellipsis:\n%s", out)
	}
	if !strings.Contains(out, "1.0.0-beta.…") {
		t.Errorf("version not truncated with ellipsis:\n%s", out)
	}
	for _, l := range lines(out) {
		if n := utf8.RuneCountInString(l); n != Width {
			t.Errorf("line is %d runes, want %d: %q", n, Width, l)
		}
	}
}

func TestMalwareCapsLongTables(t *testing.T) {
	var many []Finding
	for i := 0; i < 12; i++ {
		many = append(many, Finding{Name: "pkg" + string(rune('a'+i)), Version: "1.0.0", Ecosystem: "npm"})
	}
	out := Malware(many, "Installation blocked.", ansi.None)
	if !strings.Contains(out, "pkgf ") {
		t.Errorf("sixth finding missing:\n%s", out)
	}
	if strings.Contains(out, "pkgg ") {
		t.Errorf("seventh finding should be folded into the overflow line:\n%s", out)
	}
	if !strings.Contains(out, "and 6 more, listed below") {
		t.Errorf("missing overflow line:\n%s", out)
	}
	if !strings.Contains(out, "found 12 malicious packages") {
		t.Errorf("headline should count all findings:\n%s", out)
	}
}

func TestMalwareEightFindingsAreNotCapped(t *testing.T) {
	var eight []Finding
	for i := 0; i < 8; i++ {
		eight = append(eight, Finding{Name: "pkg" + string(rune('a'+i)), Version: "1.0.0", Ecosystem: "npm"})
	}
	out := Malware(eight, "Installation blocked.", ansi.None)
	if strings.Contains(out, "more, listed below") {
		t.Errorf("eight findings should all be listed:\n%s", out)
	}
}

func TestMalwareColourStripsToPlain(t *testing.T) {
	plain := Malware(two, "Installation blocked.", ansi.None)
	if strings.Contains(plain, "\x1b") {
		t.Fatalf("None profile emitted escapes")
	}
	for _, p := range []ansi.Profile{ansi.Basic, ansi.ANSI256, ansi.TrueColor} {
		coloured := Malware(two, "Installation blocked.", p)
		if !strings.Contains(coloured, "\x1b[") {
			t.Errorf("%v: no escapes emitted", p)
		}
		if got := ansi.Strip(coloured); got != plain {
			t.Errorf("%v: stripped output differs from plain\n--- got\n%s\n--- want\n%s", p, got, plain)
		}
	}
}

func TestMalwareTrueColorGradient(t *testing.T) {
	out := Malware(two, "Installation blocked.", ansi.TrueColor)
	if strings.Count(out, "\x1b[1;38;2;") < 6 {
		t.Errorf("expected a distinct truecolor code per letter row:\n%q", out)
	}
}

func TestMalwareEmptyOutcomeLeavesNoTrailingSpace(t *testing.T) {
	out := Malware(two, "", ansi.None)
	if !strings.Contains(out, "Ossprey found 2 malicious packages.  ") || strings.Contains(out, "packages. \n") {
		t.Errorf("headline should end at the full stop:\n%s", out)
	}
	if strings.Contains(out, "Scan failed") {
		t.Errorf("no outcome text expected:\n%s", out)
	}
}

func TestMalwareEmptyIsEmpty(t *testing.T) {
	if got := Malware(nil, "Installation blocked.", ansi.None); got != "" {
		t.Fatalf("no findings should render nothing, got:\n%s", got)
	}
}
