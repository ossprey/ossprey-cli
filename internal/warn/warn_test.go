package warn

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
)

func reg404(item string) Entry {
	return Entry{
		Class: "registry-404",
		One:   "1 package not on the public registry; left unversioned",
		Many:  "%d packages not on the public registry; left unversioned",
		Item:  item,
	}
}

func TestDrainWithoutEntriesIsEmpty(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	if got := Drain(ctx); got != "" {
		t.Errorf("Drain() = %q, want empty", got)
	}
}

func TestSingleEntryUsesSingularHeadline(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	Add(ctx, reg404("npm/@wayflyer/flyui (404)"))

	want := "ossprey: 1 package not on the public registry; left unversioned\n"
	if got := Drain(ctx); got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

func TestMultipleEntriesCollapseToACount(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	for _, n := range []string{"a", "b", "c", "d"} {
		Add(ctx, reg404("npm/"+n+" (404)"))
	}

	want := "ossprey: 4 packages not on the public registry; left unversioned\n"
	if got := Drain(ctx); got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

// A registry outage and a private package have different fixes, so they must
// never share a count — that is the whole reason Class exists.
func TestClassesAreCountedSeparately(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	Add(ctx, reg404("npm/a (404)"))
	Add(ctx, Entry{
		Class: "registry-down",
		One:   "1 package could not be resolved (registry unreachable); left unversioned",
		Many:  "%d packages could not be resolved (registry unreachable); left unversioned",
		Item:  "npm/b (dial tcp: timeout)",
	})
	Add(ctx, reg404("npm/c (404)"))

	got := Drain(ctx)
	want := "ossprey: 2 packages not on the public registry; left unversioned\n" +
		"ossprey: 1 package could not be resolved (registry unreachable); left unversioned\n"
	if got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

func TestQuietOmitsItemsAndDetail(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	Add(ctx, Entry{
		Class:       "cataloger:uv",
		One:         "uv: could not resolve /repo (the build backend returned an error)",
		Many:        "uv: could not resolve %d manifests",
		Item:        "/repo (the build backend returned an error)",
		Detail:      []string{"error: The build backend returned an error"},
		DetailLabel: "uv",
	})

	got := Drain(ctx)
	if strings.Contains(got, "|") || strings.Contains(got, "end of") {
		t.Errorf("Drain() leaked detail at the default level: %q", got)
	}
	want := "ossprey: uv: could not resolve /repo (the build backend returned an error)\n"
	if got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

func TestVerboseListsItems(t *testing.T) {
	ctx := NewContext(context.Background(), true)
	Add(ctx, reg404("npm/a (404)"))
	Add(ctx, reg404("npm/b (404)"))

	want := "ossprey: 2 packages not on the public registry; left unversioned\n" +
		"ossprey:   npm/a (404)\n" +
		"ossprey:   npm/b (404)\n"
	if got := Drain(ctx); got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

// Every line of a subprocess's output carries our prefix and a gutter, so its
// own "error:" can never be read as ossprey's.
func TestVerboseGuttersSubprocessDetail(t *testing.T) {
	ctx := NewContext(context.Background(), true)
	Add(ctx, Entry{
		Class:       "cataloger:uv",
		One:         "uv: could not resolve /repo (the build backend returned an error)",
		Many:        "uv: could not resolve %d manifests",
		Item:        "/repo (the build backend returned an error)",
		Detail:      []string{"error: The build backend returned an error", "  Caused by: boom"},
		DetailLabel: "uv",
	})

	want := "ossprey: uv: could not resolve /repo (the build backend returned an error)\n" +
		"ossprey: | error: The build backend returned an error\n" +
		"ossprey: |   Caused by: boom\n" +
		"ossprey: (end of uv output)\n"
	if got := Drain(ctx); got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

func TestVerboseViaEnv(t *testing.T) {
	t.Setenv("OSSPREY_VERBOSE", "1")
	ctx := NewContext(context.Background(), false)
	Add(ctx, reg404("npm/a (404)"))

	if got := Drain(ctx); !strings.Contains(got, "npm/a (404)") {
		t.Errorf("Drain() = %q, want the item listed under OSSPREY_VERBOSE=1", got)
	}
}

func TestDrainClears(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	Add(ctx, reg404("npm/a (404)"))
	_ = Drain(ctx)

	if got := Drain(ctx); got != "" {
		t.Errorf("second Drain() = %q, want empty", got)
	}
}

// Catalogers run under an errgroup, so Add is called concurrently.
func TestAddIsConcurrencySafe(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Add(ctx, reg404("npm/x (404)"))
		}()
	}
	wg.Wait()

	want := "ossprey: 50 packages not on the public registry; left unversioned\n"
	if got := Drain(ctx); got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

// A caller that forgot to wire a collector must still see its warning: losing
// one silently is the failure mode this whole package exists to avoid.
func TestUncollectedWarningFallsBackToStderr(t *testing.T) {
	var buf bytes.Buffer
	old := fallback
	fallback = &buf
	defer func() { fallback = old }()

	Add(context.Background(), reg404("npm/a (404)"))

	want := "ossprey: 1 package not on the public registry; left unversioned\n"
	if got := buf.String(); got != want {
		t.Errorf("fallback = %q, want %q", got, want)
	}
}

// scan and check own a -v flag; the collector is built before cobra has parsed
// it, so verbosity has to be raisable after the fact.
func TestSetVerboseAfterTheFact(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	Add(ctx, reg404("npm/a (404)"))
	SetVerbose(ctx)

	if got := Drain(ctx); !strings.Contains(got, "npm/a (404)") {
		t.Errorf("Drain() = %q, want the item listed after SetVerbose", got)
	}
}

// Verbosity only ever goes up: nothing may quiet a warning that was asked for.
func TestSetVerboseOnAnUnwiredContextDoesNotPanic(t *testing.T) {
	SetVerbose(context.Background())
}

// With one entry the headline already names it, so repeating it as an item is
// noise — and noise is what this package exists to remove.
func TestVerboseSkipsTheItemWhenTheHeadlineAlreadyNamesIt(t *testing.T) {
	ctx := NewContext(context.Background(), true)
	Add(ctx, Entry{
		Class:       "cataloger:uv",
		One:         "uv: could not resolve /repo (boom)",
		Many:        "uv: could not resolve %d manifests",
		Item:        "/repo (boom)",
		Detail:      []string{"error: boom"},
		DetailLabel: "uv",
	})

	want := "ossprey: uv: could not resolve /repo (boom)\n" +
		"ossprey: | error: boom\n" +
		"ossprey: (end of uv output)\n"
	if got := Drain(ctx); got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}

// The whole point is a few readable lines. A headline built from a long path
// and a long cause must not become the wall of text it replaced; the full text
// is still there under verbose.
func TestHeadlineIsCapped(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	Add(ctx, Entry{
		Class: "cataloger:uv",
		One:   "uv: could not resolve /" + strings.Repeat("deep/", 80) + " (boom)",
		Many:  "uv: could not resolve %d manifests",
	})

	got := strings.TrimRight(Drain(ctx), "\n")
	if n := len([]rune(got)); n > MaxLine {
		t.Errorf("headline is %d runes, want at most %d", n, MaxLine)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("headline = %q, want it to show it was truncated", got)
	}
}

func TestShortHeadlineIsUntouched(t *testing.T) {
	ctx := NewContext(context.Background(), false)
	Add(ctx, reg404("npm/a (404)"))

	if got, want := Drain(ctx), "ossprey: 1 package not on the public registry; left unversioned\n"; got != want {
		t.Errorf("Drain() = %q, want %q", got, want)
	}
}
