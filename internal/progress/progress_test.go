package progress

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

// A non-terminal writer must get one plain line, not a redrawn one: CI logs and
// piped output are where a carriage-returned spinner turns into noise.
func TestStartNonTerminalPrintsOnce(t *testing.T) {
	var buf bytes.Buffer
	stop := Start(&buf, "ossprey: scan in progress")
	stop()
	stop() // idempotent

	got := buf.String()
	if got != "ossprey: scan in progress...\n" {
		t.Fatalf("output = %q", got)
	}
	if strings.Contains(got, "\r") {
		t.Errorf("non-terminal output should not redraw: %q", got)
	}
}

// /dev/null is a character device but not a terminal — the naive ModeCharDevice
// check treats it as one and animates into it.
func TestStartDevNullIsNotATerminal(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Errorf("isTerminal(%s) = true", os.DevNull)
	}
}

// Everything the animated path writes must land before stop returns, so the
// caller's next line can't be overwritten by a trailing redraw.
func TestStartTerminalDrawsAndErases(t *testing.T) {
	var w bytes.Buffer
	stop := animate(&w, "ossprey: scan in progress")
	stop()

	got := w.String()
	if !strings.HasPrefix(got, "\rossprey: scan in progress... ") {
		t.Fatalf("expected an in-place first draw, got %q", got)
	}
	if !strings.HasSuffix(got, "\r") {
		t.Errorf("expected the line to be erased on stop, got %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("the indicator should not leave a line behind: %q", got)
	}
}

// The point of the animation is that it keeps moving: a line drawn once and
// then frozen is indistinguishable from the hang it exists to rule out.
func TestAnimateKeepsRedrawing(t *testing.T) {
	old := Tick
	Tick = time.Millisecond
	t.Cleanup(func() { Tick = old })

	w := &drawSignaller{draws: make(chan struct{}, 64)}
	stop := animate(w, "ossprey: scan in progress")
	defer stop()

	for i := 0; i < 3; i++ {
		select {
		case <-w.draws:
		case <-time.After(5 * time.Second):
			t.Fatalf("redraw %d never arrived", i+1)
		}
	}
}

// drawSignaller reports each write on a buffered channel; writes never block,
// so the indicator goroutine is not paced by the test.
type drawSignaller struct{ draws chan struct{} }

func (d *drawSignaller) Write(p []byte) (int, error) {
	select {
	case d.draws <- struct{}{}:
	default:
	}
	return len(p), nil
}

// The count is the whole reason Scan exists as its own constructor: "scan in
// progress" alone reads the same whether one package is being checked or four
// hundred, and the pluralisation is the kind of thing that rots silently.
func TestScanWordsTheCount(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{
		{1, "ossprey: scan in progress, checking 1 package...\n"},
		{2, "ossprey: scan in progress, checking 2 packages...\n"},
		// No count at all rather than "checking 0 packages".
		{0, "ossprey: scan in progress...\n"},
	} {
		var buf bytes.Buffer
		Scan(&buf, tc.n)()
		if got := buf.String(); got != tc.want {
			t.Errorf("Scan(w, %d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

// Submit must not borrow Scan's "checking" wording: passive mode posts the SBOM
// and returns, so a message promising a check would describe a verdict nobody
// waits for.
func TestSubmitDoesNotClaimToCheck(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{
		{1, "ossprey: submitting scan of 1 package...\n"},
		{3, "ossprey: submitting scan of 3 packages...\n"},
		{0, "ossprey: submitting scan...\n"},
	} {
		var buf bytes.Buffer
		Submit(&buf, tc.n)()
		if got := buf.String(); got != tc.want {
			t.Errorf("Submit(w, %d) = %q, want %q", tc.n, got, tc.want)
		}
		if strings.Contains(buf.String(), "checking") {
			t.Errorf("Submit(w, %d) claims to check: %q", tc.n, buf.String())
		}
	}
}
