package ansi

import (
	"bytes"
	"os"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE", "TERM", "COLORTERM", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE", "CI"} {
		t.Setenv(k, "")
	}
}

func TestDetectPipeIsNone(t *testing.T) {
	clearEnv(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("COLORTERM", "truecolor")
	if got := Detect(&bytes.Buffer{}); got != None {
		t.Fatalf("pipe: got %v, want None", got)
	}
}

func TestDetectForceColor(t *testing.T) {
	clearEnv(t)
	t.Setenv("FORCE_COLOR", "1")
	if got := Detect(&bytes.Buffer{}); got != Basic {
		t.Fatalf("FORCE_COLOR=1: got %v, want Basic", got)
	}
	t.Setenv("COLORTERM", "truecolor")
	if got := Detect(&bytes.Buffer{}); got != TrueColor {
		t.Fatalf("FORCE_COLOR + COLORTERM=truecolor: got %v, want TrueColor", got)
	}
	t.Setenv("COLORTERM", "")
	t.Setenv("TERM", "screen-256color")
	if got := Detect(&bytes.Buffer{}); got != ANSI256 {
		t.Fatalf("FORCE_COLOR + 256color TERM: got %v, want ANSI256", got)
	}
}

func TestDetectForceColorZeroDisables(t *testing.T) {
	clearEnv(t)
	t.Setenv("FORCE_COLOR", "0")
	t.Setenv("GITHUB_ACTIONS", "true")
	if got := Detect(&bytes.Buffer{}); got != None {
		t.Fatalf("FORCE_COLOR=0: got %v, want None", got)
	}
}

func TestDetectNoColorWins(t *testing.T) {
	clearEnv(t)
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "1")
	if got := Detect(&bytes.Buffer{}); got != None {
		t.Fatalf("NO_COLOR: got %v, want None", got)
	}
}

func TestDetectDumbTermWins(t *testing.T) {
	clearEnv(t)
	t.Setenv("TERM", "dumb")
	t.Setenv("GITHUB_ACTIONS", "true")
	if got := Detect(&bytes.Buffer{}); got != None {
		t.Fatalf("TERM=dumb: got %v, want None", got)
	}
}

func TestDetectCILogViewers(t *testing.T) {
	for _, k := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "BUILDKITE"} {
		t.Run(k, func(t *testing.T) {
			clearEnv(t)
			t.Setenv(k, "true")
			if got := Detect(&bytes.Buffer{}); got != Basic {
				t.Fatalf("%s: got %v, want Basic", k, got)
			}
		})
	}
	clearEnv(t)
	t.Setenv("CI", "true")
	if got := Detect(&bytes.Buffer{}); got != None {
		t.Fatalf("bare CI=true: got %v, want None", got)
	}
}

func TestStylesNoneAreIdentity(t *testing.T) {
	for name, f := range map[string]func(string) string{
		"Bold": None.Bold, "Dim": None.Dim, "Red": None.Red,
		"RGB": func(s string) string { return None.RGB(255, 140, 0, s) },
	} {
		if got := f("x"); got != "x" {
			t.Errorf("None.%s: got %q, want %q", name, got, "x")
		}
	}
}

func TestStylesBasic(t *testing.T) {
	if got, want := Basic.Bold("x"), "\x1b[1mx\x1b[0m"; got != want {
		t.Errorf("Bold: got %q, want %q", got, want)
	}
	if got, want := Basic.Dim("x"), "\x1b[2mx\x1b[0m"; got != want {
		t.Errorf("Dim: got %q, want %q", got, want)
	}
	if got, want := Basic.Red("x"), "\x1b[1;31mx\x1b[0m"; got != want {
		t.Errorf("Red: got %q, want %q", got, want)
	}
	if got, want := Basic.RGB(255, 140, 0, "x"), Basic.Red("x"); got != want {
		t.Errorf("Basic.RGB falls back to Red: got %q, want %q", got, want)
	}
}

func TestStylesRGB(t *testing.T) {
	if got, want := ANSI256.Red("x"), "\x1b[1;38;5;196mx\x1b[0m"; got != want {
		t.Errorf("ANSI256.Red: got %q, want %q", got, want)
	}
	if got, want := ANSI256.RGB(255, 140, 0, "x"), ANSI256.Red("x"); got != want {
		t.Errorf("ANSI256.RGB falls back to Red: got %q, want %q", got, want)
	}
	if got, want := TrueColor.RGB(255, 140, 0, "x"), "\x1b[1;38;2;255;140;0mx\x1b[0m"; got != want {
		t.Errorf("TrueColor.RGB: got %q, want %q", got, want)
	}
}

func TestStripRemovesEscapes(t *testing.T) {
	in := TrueColor.RGB(1, 2, 3, "a") + Basic.Bold("b") + "c"
	if got := Strip(in); got != "abc" {
		t.Fatalf("Strip: got %q, want %q", got, "abc")
	}
}

func TestEnableIsSafeOnAnyWriter(t *testing.T) {
	Enable(&bytes.Buffer{})
	Enable(os.Stdout)
}
