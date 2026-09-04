// Package severity models the Ossprey finding severity scale and the floor at
// or above which a finding fails a scan.
//
// The scale is ordered Info < Low < Medium < High < Critical. Info is
// informational: the finding is reported to the user with its justification but
// does not fail the scan, and being below the floor is the one and only thing
// that makes Info special.
//
// Parsing is fail-closed. The API omits severity on findings recorded before it
// was captured and on findings sourced from the OSV advisory tables, and an
// older server does not send the field at all, so anything this package cannot
// recognise is Unknown and Unknown fails at every floor. A client must never
// pass a real detection because it could not grade it.
package severity

import "strings"

// Level is a point on the severity scale. Higher is more severe; Unknown sorts
// above every named level so it always fails.
type Level int

const (
	// Unknown is a missing or unrecognised severity. It fails at every floor.
	Unknown Level = iota
	Info
	Low
	Medium
	High
	Critical
)

// FailingFloor is the lowest level that fails a scan. Info is the only named
// level below it.
const FailingFloor = Low

var byName = map[string]Level{
	"info":     Info,
	"low":      Low,
	"medium":   Medium,
	"high":     High,
	"critical": Critical,
}

var names = map[Level]string{
	Unknown:  "Unknown",
	Info:     "Info",
	Low:      "Low",
	Medium:   "Medium",
	High:     "High",
	Critical: "Critical",
}

// Parse reads a severity from the wire. The API canonicalises to title case,
// but the store has held other spellings, so matching is case-insensitive.
// Anything unrecognised, including the empty string, is Unknown.
func Parse(s string) Level {
	if lvl, ok := byName[strings.ToLower(strings.TrimSpace(s))]; ok {
		return lvl
	}
	return Unknown
}

// String is the canonical title-case name.
func (l Level) String() string {
	if name, ok := names[l]; ok {
		return name
	}
	return "Unknown"
}

// Fails reports whether a finding at this level fails a scan at the default
// floor. Unknown always fails, whatever the floor.
func (l Level) Fails() bool {
	return l.FailsAt(FailingFloor)
}

// FailsAt reports whether a finding at this level fails a scan at the given
// floor, so a caller can opt into a stricter one (`--fail-on-informational`
// lowers it to Info). Unknown fails at every floor: a finding we could not
// grade must never pass because of it.
func (l Level) FailsAt(floor Level) bool {
	if l == Unknown {
		return true
	}
	if floor == Unknown {
		floor = FailingFloor
	}
	return l >= floor
}
