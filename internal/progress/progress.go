// Package progress prints a "still working" indicator for the slow part of a
// command — cataloging a project and waiting on the API scan — so that a user
// watching an install does not read a silent pause as a hang.
package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// Tick is how often the animated line is redrawn. Overridable in tests.
var Tick = 200 * time.Millisecond

// ASCII frames deliberately: the spinner is written to a Windows console as
// often as to a UTF-8 terminal, and a mojibake spinner is worse than none.
var frames = [...]byte{'|', '/', '-', '\\'}

// Start announces msg on w and returns a function that ends the announcement.
//
// On an interactive terminal the line is redrawn in place with a spinner and an
// elapsed-second counter, then erased by stop — so a scan that finishes quickly
// leaves the output of the command exactly as it was. Everywhere else (a pipe,
// a CI log, a file) the message is printed once with a newline instead: a
// redrawn line is unreadable in a log, and all that matters there is the record
// that the time went to the scan.
//
// stop is idempotent and returns only after the final redraw has been written,
// so callers can print immediately afterwards without racing the animation.
func Start(w io.Writer, msg string) (stop func()) {
	if !isTerminal(w) {
		fmt.Fprintln(w, msg+"...")
		return func() {}
	}
	return animate(w, msg)
}

// animate is the terminal half of Start, split out so tests can exercise the
// redraw without owning a real terminal.
func animate(w io.Writer, msg string) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		started := time.Now()
		t := time.NewTicker(Tick)
		defer t.Stop()
		for i := 0; ; i++ {
			line := fmt.Sprintf("%s... %c %ds", msg, frames[i%len(frames)],
				int(time.Since(started).Seconds()))
			fmt.Fprintf(w, "\r%s", line)
			select {
			case <-done:
				// Blank the line rather than emitting a newline: the scan is a
				// step on the way to the install, not output of its own.
				fmt.Fprintf(w, "\r%s\r", strings.Repeat(" ", len(line)))
				return
			case <-t.C:
			}
		}
	}()

	var once sync.Once
	return func() { once.Do(func() { close(done); wg.Wait() }) }
}

// isTerminal reports whether w is a file attached to an interactive terminal.
// term.IsTerminal, not a ModeCharDevice check: /dev/null is a character device
// too, and animating into it (or into a pipe) is what this guards against.
func isTerminal(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	return ok && term.IsTerminal(int(f.Fd()))
}
