package scan

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/severity"
)

func reportJSON(t *testing.T, r Report) map[string]any {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A verdict served from the local cache says so in the report, with the age
// of the entry, so CI can tell a reused result from a fresh one.
func TestReportMarksACachedVerdict(t *testing.T) {
	r := NewReport(ossbom.New(ossbom.Environment{}), severity.FailingFloor)
	r.MarkCached(90*time.Second + 600*time.Millisecond)

	m := reportJSON(t, r)
	if m["cached"] != true {
		t.Errorf("cached = %v, want true", m["cached"])
	}
	if m["cached_age_seconds"] != float64(90) {
		t.Errorf("cached_age_seconds = %v, want 90", m["cached_age_seconds"])
	}
}

// A live verdict carries neither key, so a consumer that predates the cache
// sees no change.
func TestReportOmitsCacheFieldsWhenLive(t *testing.T) {
	m := reportJSON(t, NewReport(ossbom.New(ossbom.Environment{}), severity.FailingFloor))
	for _, key := range []string{"cached", "cached_age_seconds"} {
		if _, present := m[key]; present {
			t.Errorf("live report carries %q", key)
		}
	}
}

// An entry written and read within the same second has age 0, and that still
// has to be reported as a number rather than vanishing under omitempty.
func TestReportKeepsAZeroCachedAge(t *testing.T) {
	r := NewReport(ossbom.New(ossbom.Environment{}), severity.FailingFloor)
	r.MarkCached(0)
	if m := reportJSON(t, r); m["cached_age_seconds"] != float64(0) {
		t.Errorf("cached_age_seconds = %v, want 0", m["cached_age_seconds"])
	}
}
