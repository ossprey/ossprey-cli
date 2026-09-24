package catalog

import (
	"fmt"
	"strings"
	"unicode"
)

// toolError is a resolver subprocess's failure, split into the one line worth
// printing by default and the full output, which only a verbose run wants.
//
// The split exists because uv and npm write their own "error:" lines to stderr.
// Inlining that text into our error message put a foreign "error:" in a
// customer's CI log where it read as ossprey failing (OSS-2001).
type toolError struct {
	tool    string
	dir     string
	summary string
	detail  []string
}

func newToolError(tool, dir, output string) *toolError {
	e := &toolError{tool: tool, dir: dir}
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e.detail = append(e.detail, strings.TrimRight(line, " \t\r"))
	}
	e.summary = summarize(e.detail)
	return e
}

func (e *toolError) Error() string {
	if len(e.detail) == 0 {
		return fmt.Sprintf("%s %s: %s", e.tool, e.dir, e.summary)
	}
	return fmt.Sprintf("%s %s: %s", e.tool, e.dir, strings.Join(e.detail, "\n"))
}

// maxSummary caps the headline. A manifest line can be arbitrarily long — a
// minified blob on one line — and quoting it whole would recreate the wall of
// text this work removes. The full text stays in detail for a verbose run.
const maxSummary = 160

// summarize picks the line a developer needs. A tool's own advisory warnings
// come first in its output but never explain the failure, so they are skipped
// in favour of the first real complaint.
func summarize(lines []string) string {
	const fallback = "no output"
	if len(lines) == 0 {
		return fallback
	}
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(l), "warning:") {
			continue
		}
		if rest, ok := cutPrefixFold(l, "error:"); ok {
			l = strings.TrimSpace(rest)
		}
		if l == "" {
			continue
		}
		return truncate(lowerFirst(l))
	}
	// Every line was a warning: say the first one rather than nothing.
	return truncate(strings.TrimSpace(lines[0]))
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// lowerFirst downcases a leading capital so the line reads inside our sentence.
// It leaves acronyms and identifiers alone (E404, PyPI, __legacy__).
func lowerFirst(s string) string {
	r := []rune(s)
	if len(r) < 2 || !unicode.IsUpper(r[0]) || !unicode.IsLower(r[1]) {
		return s
	}
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

func truncate(s string) string {
	r := []rune(s)
	if len(r) <= maxSummary {
		return s
	}
	return string(r[:maxSummary-1]) + "…"
}
