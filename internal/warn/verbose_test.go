package warn

import (
	"context"
	"testing"
)

// Verbose lets a package decide whether to record a diagnostic at all, not
// just how much of it to show: a cache that cannot be read is worth a line
// to someone debugging and nothing to anyone else.
func TestVerboseReportsTheCollectorSetting(t *testing.T) {
	t.Setenv("OSSPREY_VERBOSE", "")
	if Verbose(context.Background()) {
		t.Error("no collector and no env: want false")
	}
	ctx := NewContext(context.Background(), false)
	if Verbose(ctx) {
		t.Error("quiet collector: want false")
	}
	SetVerbose(ctx)
	if !Verbose(ctx) {
		t.Error("after SetVerbose: want true")
	}
	if !Verbose(NewContext(context.Background(), true)) {
		t.Error("collector built verbose: want true")
	}
	t.Setenv("OSSPREY_VERBOSE", "1")
	if !Verbose(context.Background()) {
		t.Error("no collector but OSSPREY_VERBOSE=1: want true")
	}
}
