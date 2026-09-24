package catalog

import (
	"errors"
	"strings"
	"testing"
)

// The customer report in OSS-2001: uv's own "error:" reached the terminal and
// read as ossprey's. The summary keeps one actionable line; the rest is detail.
func TestToolErrorSummarySkipsToolWarnings(t *testing.T) {
	stderr := `warning: Setting ` + "`exclude-newer`" + ` on configured indexes is experimental and may change without warning.
error: The build backend returned an error
  Caused by: Call to ` + "`setuptools.build_meta:__legacy__.build_wheel`" + ` failed (exit status: 1)`

	e := newToolError("uv", "/repo", stderr)
	if got, want := e.summary, "the build backend returned an error"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
	if len(e.detail) != 3 {
		t.Errorf("detail = %d lines, want all 3 kept for verbose", len(e.detail))
	}
}

func TestToolErrorFallsBackToTheFirstLine(t *testing.T) {
	e := newToolError("npm", "/repo", "npm error code E404\nnpm error 404 Not Found")
	if got, want := e.summary, "npm error code E404"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

func TestToolErrorWithNoOutputStillReads(t *testing.T) {
	e := newToolError("uv", "/repo", "   \n\n")
	if e.summary == "" {
		t.Error("summary is empty; a failure with no output must still say something")
	}
	if len(e.detail) != 0 {
		t.Errorf("detail = %v, want none", e.detail)
	}
}

// Error() keeps the whole output so nothing is lost for callers that log it.
func TestToolErrorErrorStringCarriesEverything(t *testing.T) {
	e := newToolError("uv", "/repo", "error: boom\n  Caused by: bang")
	msg := e.Error()
	for _, want := range []string{"uv", "/repo", "boom", "bang"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}
}

func TestToolErrorIsDiscoverableByErrorsAs(t *testing.T) {
	var wrapped error = newToolError("uv", "/repo", "error: boom")
	var te *toolError
	if !errors.As(wrapped, &te) {
		t.Fatal("errors.As did not find *toolError")
	}
}

// A malformed manifest line can be arbitrarily long — a minified blob on one
// line, say. Quoting it whole into the headline would recreate the wall of text
// this work exists to remove, so the summary is capped and the full text stays
// in detail for a verbose run.
func TestToolErrorSummaryIsCapped(t *testing.T) {
	long := strings.Repeat("x", 4000)
	e := newToolError("uv", "/repo", "error: could not parse `"+long+"`")

	if n := len([]rune(e.summary)); n > maxSummary {
		t.Errorf("summary is %d runes, want at most %d", n, maxSummary)
	}
	if !strings.HasSuffix(e.summary, "…") {
		t.Errorf("summary = %q, want it to show it was truncated", e.summary)
	}
	if !strings.Contains(strings.Join(e.detail, "\n"), long) {
		t.Error("the full text must survive in detail for a verbose run")
	}
}

func TestToolErrorShortSummaryIsNotTouched(t *testing.T) {
	e := newToolError("uv", "/repo", "error: boom")
	if e.summary != "boom" {
		t.Errorf("summary = %q, want %q", e.summary, "boom")
	}
}
