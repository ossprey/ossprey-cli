// Package warn collects the non-fatal diagnostics a scan produces and renders
// them as a few counted lines instead of one line per occurrence.
//
// The problem it solves is a real customer scan (OSS-2001) whose useful output
// — a malware verdict — sat under twenty-five lines of a subprocess's raw
// stderr and four repetitions of an expected condition. Nothing there was
// wrong, but nothing was readable either.
//
// Three rules hold it together:
//
//   - Warnings group by Class, never by message. A private package and a
//     registry outage both leave a component unversioned, but one is expected
//     and the other means the scan checked almost nothing, so they must never
//     share a count.
//   - A subprocess's output never reaches the terminal at the default level,
//     and never without our prefix and a gutter. uv's own "error:" read as
//     ossprey's in the report that prompted this.
//   - A warning is never lost. Add outside a collector context falls back to
//     stderr rather than dropping the line.
//
// The collector rides on a context because the catalogers it serves sit behind
// syft's Catalog(ctx, resolver) signature, which has nowhere to return one.
package warn

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/ossprey/ossprey-cli/internal/env"
)

// prefix marks every line as ours, the gutter included.
const prefix = "ossprey: "

// MaxLine caps a rendered headline. A cataloger failure names a directory and a
// cause, either of which can be long in a real monorepo; an unbounded headline
// would recreate the wall of text this package removes. Detail, which only a
// verbose run prints, is never truncated.
const MaxLine = 200

// fallback receives warnings added outside a collector context. A var so tests
// can capture it.
var fallback io.Writer = os.Stderr

// Entry is one occurrence of one warning.
//
// One and Many are the headline for the whole class: One renders when the class
// has a single entry (so it can name that entry's subject — "uv: could not
// resolve /repo"), Many takes the count. The first entry of a class supplies
// both, so every Add for a class should carry the same Many.
type Entry struct {
	// Class groups occurrences. Distinct causes need distinct classes even
	// when the consequence matches, since the fix differs.
	Class string
	// One is the whole headline when this is the class's only entry.
	One string
	// Many is the headline format when the class has more than one entry.
	// It takes exactly one %d, the count.
	Many string
	// Item is the per-occurrence line shown only when verbose.
	Item string
	// Detail is a subprocess's output, shown only when verbose, behind a
	// gutter. Nil for warnings that have none.
	Detail []string
	// DetailLabel names the subprocess in the closing marker.
	DetailLabel string
}

type collector struct {
	mu      sync.Mutex
	verbose bool
	order   []string
	byClass map[string][]Entry
}

type ctxKey struct{}

// NewContext returns a context carrying a fresh collector. verbose is OR'd with
// OSSPREY_VERBOSE, so CI can turn detail on for every path at once — the
// forwarders parse no flags of their own and have no other way to ask.
func NewContext(ctx context.Context, verbose bool) context.Context {
	return context.WithValue(ctx, ctxKey{}, &collector{
		verbose: verbose || env.Verbose(),
		byClass: map[string][]Entry{},
	})
}

// Add records one occurrence. Safe for concurrent use: the catalogers that call
// it run under an errgroup.
func Add(ctx context.Context, e Entry) {
	c, ok := ctx.Value(ctxKey{}).(*collector)
	if !ok {
		// No collector wired up. Print rather than drop it.
		fmt.Fprint(fallback, prefix+e.One+"\n")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.byClass[e.Class]; !seen {
		c.order = append(c.order, e.Class)
	}
	c.byClass[e.Class] = append(c.byClass[e.Class], e)
}

// Drain renders everything collected so far and empties the collector, so a
// caller that drains twice does not print twice. Returns "" when there is
// nothing to say — no header, no blank line.
func Drain(ctx context.Context) string {
	c, ok := ctx.Value(ctxKey{}).(*collector)
	if !ok {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	var b strings.Builder
	// Classes render in first-occurrence order, so the output is stable even
	// though the catalogers that filled it ran concurrently.
	for _, class := range c.order {
		entries := c.byClass[class]
		if len(entries) == 0 {
			continue
		}
		headline := entries[0].One
		if len(entries) > 1 {
			headline = fmt.Sprintf(entries[0].Many, len(entries))
		}
		b.WriteString(prefix + truncate(headline) + "\n")
		if !c.verbose {
			continue
		}
		for _, e := range entries {
			// Skip an item the headline already spelled out — a single
			// cataloger failure names its own directory. A counted headline
			// ("4 packages not on the public registry") names none of them, so
			// there the items are the whole point.
			if e.Item != "" && !strings.Contains(headline, e.Item) {
				b.WriteString(prefix + "  " + e.Item + "\n")
			}
			for _, line := range e.Detail {
				b.WriteString(prefix + "| " + line + "\n")
			}
			if len(e.Detail) > 0 {
				b.WriteString(prefix + "(end of " + detailLabel(e) + " output)\n")
			}
		}
	}
	c.order = nil
	c.byClass = map[string][]Entry{}
	return b.String()
}

func detailLabel(e Entry) string {
	if e.DetailLabel == "" {
		return "command"
	}
	return e.DetailLabel
}

// SetVerbose raises an existing collector to verbose. The collector is built
// before cobra parses -v, and it only ever goes up: nothing here can quiet a
// warning someone asked to see.
func SetVerbose(ctx context.Context) {
	c, ok := ctx.Value(ctxKey{}).(*collector)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verbose = true
}

// truncate caps a headline. len(prefix) is a byte count compared against a rune
// count, which is only correct because prefix is pure ASCII — keep it that way.
func truncate(s string) string {
	r := []rune(s)
	if len(r)+len(prefix) <= MaxLine {
		return s
	}
	return string(r[:MaxLine-len(prefix)-1]) + "…"
}
