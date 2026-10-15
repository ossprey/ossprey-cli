package warn

import (
	"context"
	"strings"
	"testing"
)

// Classes render in first-occurrence order however their adds interleave, so
// output from concurrent catalogers is stable run to run.
func TestDrainKeepsFirstOccurrenceOrder(t *testing.T) {
	t.Setenv("OSSPREY_VERBOSE", "")
	ctx := NewContext(context.Background(), false)
	add := func(class string) {
		Add(ctx, Entry{Class: class, One: class + " once", Many: class + " x%d"})
	}
	add("b")
	add("a")
	add("b")
	add("c")
	add("a")
	got := Drain(ctx)
	want := "ossprey: b x2\nossprey: a x2\nossprey: c once\n"
	if got != want {
		t.Errorf("Drain() =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(Drain(ctx), "ossprey") {
		t.Error("second drain repeated warnings")
	}
}
