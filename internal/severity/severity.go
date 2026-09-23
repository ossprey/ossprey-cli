// Package severity models the Ossprey finding severity scale and the floor at
// or above which a finding fails a scan.
//
// The scale is ordered Info < Low < Medium < High < Critical. No level is
// special: a finding fails when it is at or above the configured floor, so Info
// fails a scan graded at Info exactly as Critical fails one graded at Critical.
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

// FailingFloor is the floor a run grades at when nothing else says otherwise:
// no account floor served and no per-run override. It is a default, not a cap;
// an account may sit anywhere on the scale.
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

// ParseFloor reads a floor rather than a grade, so an unrecognised value falls
// back to FailingFloor instead of Unknown. The two directions are opposite on
// purpose: an unreadable grade must fail, an unreadable floor must not fail
// everything.
func ParseFloor(s string) Level {
	if lvl := Parse(s); lvl != Unknown {
		return lvl
	}
	return FailingFloor
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
// floor, which is the account's setting or a per-run override. Unknown fails at
// every floor: a finding we could not grade must never pass because of it.
func (l Level) FailsAt(floor Level) bool {
	if l == Unknown {
		return true
	}
	if floor == Unknown {
		floor = FailingFloor
	}
	return l >= floor
}
