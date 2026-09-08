package severity

import "testing"

func TestParseIsCaseInsensitive(t *testing.T) {
	for _, in := range []string{"Info", "info", "INFO", " Info ", "iNfO"} {
		if got := Parse(in); got != Info {
			t.Errorf("Parse(%q) = %v, want Info", in, got)
		}
	}
	if got := Parse("CRITICAL"); got != Critical {
		t.Errorf("Parse(CRITICAL) = %v, want Critical", got)
	}
}

// Anything we cannot grade must fail. The API omits severity on findings
// recorded before it was captured and on OSV-sourced findings, and an older
// server omits it entirely.
func TestUnrecognisedIsUnknownAndFails(t *testing.T) {
	for _, in := range []string{"", "   ", "bogus", "severe", "informational", "Info!"} {
		lvl := Parse(in)
		if lvl != Unknown {
			t.Errorf("Parse(%q) = %v, want Unknown", in, lvl)
		}
		if !lvl.Fails() {
			t.Errorf("Parse(%q).Fails() = false, want true", in)
		}
	}
}

func TestOnlyInfoPasses(t *testing.T) {
	cases := map[Level]bool{
		Unknown:  true,
		Info:     false,
		Low:      true,
		Medium:   true,
		High:     true,
		Critical: true,
	}
	for lvl, wantFails := range cases {
		if got := lvl.Fails(); got != wantFails {
			t.Errorf("%v.Fails() = %v, want %v", lvl, got, wantFails)
		}
	}
}

func TestScaleIsOrdered(t *testing.T) {
	if !(Info < Low && Low < Medium && Medium < High && High < Critical) {
		t.Error("levels are not ordered Info < Low < Medium < High < Critical")
	}
	if FailingFloor != Low {
		t.Errorf("FailingFloor = %v, want Low", FailingFloor)
	}
}

func TestString(t *testing.T) {
	for in, want := range map[string]string{
		"info":     "Info",
		"CRITICAL": "Critical",
		"bogus":    "Unknown",
		"":         "Unknown",
	} {
		if got := Parse(in).String(); got != want {
			t.Errorf("Parse(%q).String() = %q, want %q", in, got, want)
		}
	}
	if got := Level(99).String(); got != "Unknown" {
		t.Errorf("Level(99).String() = %q, want Unknown", got)
	}
}

// A caller may opt into a stricter floor; it must never be able to loosen past
// the point where something we could not grade would pass.
func TestFailsAt(t *testing.T) {
	if !Info.FailsAt(Info) {
		t.Error("Info.FailsAt(Info) = false, want true")
	}
	if Info.FailsAt(Low) {
		t.Error("Info.FailsAt(Low) = true, want false")
	}
	for _, floor := range []Level{Unknown, Info, Low, Medium, High, Critical} {
		if !Unknown.FailsAt(floor) {
			t.Errorf("Unknown.FailsAt(%v) = false, want true", floor)
		}
		if !Critical.FailsAt(floor) {
			t.Errorf("Critical.FailsAt(%v) = false, want true", floor)
		}
	}
	// An unset floor falls back to the default rather than passing everything.
	if Info.FailsAt(Unknown) {
		t.Error("Info.FailsAt(Unknown) = true, want false (falls back to FailingFloor)")
	}
	if !Low.FailsAt(Unknown) {
		t.Error("Low.FailsAt(Unknown) = false, want true")
	}
}
