package scancache

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// lookupCtx isolates the cache in a temp dir with the default TTL and a quiet
// collector, and returns that dir's scans/ path for assertions.
func lookupCtx(t *testing.T) (context.Context, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv(DirEnv, root)
	t.Setenv(TTLEnv, "")
	return warn.NewContext(context.Background(), false), filepath.Join(root, "scans")
}

func TestLookupPutThenGetHits(t *testing.T) {
	ctx, _ := lookupCtx(t)
	in := baseInput(t)

	l := New(ctx, in)
	if _, _, ok := l.Get(); ok {
		t.Fatal("hit before anything was put")
	}
	l.Put(json.RawMessage(cleanResponse))

	raw, age, ok := New(ctx, in).Get()
	if !ok {
		t.Fatal("miss after put")
	}
	if string(raw) != cleanResponse {
		t.Errorf("response = %s, want %s", raw, cleanResponse)
	}
	if age < 0 || age > time.Minute {
		t.Errorf("age = %v, want a just-written age", age)
	}
}

// No identity, no cache: a login with no email or subject has nothing to key
// on, and caching under the hash of nothing would share verdicts between
// everyone in that state.
func TestLookupWithoutIdentityNeverTouchesDisk(t *testing.T) {
	ctx, dir := lookupCtx(t)
	in := baseInput(t)
	in.Identity = ""

	l := New(ctx, in)
	l.Put(json.RawMessage(cleanResponse))
	if _, _, ok := l.Get(); ok {
		t.Error("a lookup with no identity hit")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cache dir was created for an uncacheable lookup (stat err %v)", err)
	}
}

func TestLookupDisabledByTTL(t *testing.T) {
	for _, ttl := range []string{"0", "off"} {
		t.Run(ttl, func(t *testing.T) {
			ctx, dir := lookupCtx(t)
			t.Setenv(TTLEnv, ttl)
			in := baseInput(t)

			l := New(ctx, in)
			l.Put(json.RawMessage(cleanResponse))
			if _, _, ok := l.Get(); ok {
				t.Error("hit with the cache disabled")
			}
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("cache dir was created with the cache disabled (stat err %v)", err)
			}
		})
	}
}

// --no-cache skips the read and still writes, so the next ordinary run reuses
// the fresh result rather than the one the user just chose not to trust.
func TestBypassSkipsTheReadButStillWrites(t *testing.T) {
	ctx, _ := lookupCtx(t)
	in := baseInput(t)
	New(ctx, in).Put(json.RawMessage(cleanResponse))

	if Bypassed(ctx) {
		t.Fatal("a plain context reads as bypassed")
	}
	bctx := WithBypass(ctx)
	if !Bypassed(bctx) {
		t.Fatal("WithBypass did not mark the context")
	}

	b := New(bctx, in)
	if _, _, ok := b.Get(); ok {
		t.Fatal("a bypassed lookup served a hit")
	}
	const rewritten = `{"vulnerabilities":[],"rewritten":true}`
	b.Put(json.RawMessage(rewritten))

	raw, _, ok := New(ctx, in).Get()
	if !ok {
		t.Fatal("miss after a bypassed put")
	}
	if string(raw) != rewritten {
		t.Errorf("the bypassed run did not rewrite the entry: %s", raw)
	}
}

func TestHitRecordsTheOutcomeAndSaysSo(t *testing.T) {
	base, _ := lookupCtx(t)

	ctx, out := Observe(base)
	New(ctx, baseInput(t)).Hit(5 * time.Minute)
	if !out.Hit || out.Age != 5*time.Minute {
		t.Errorf("outcome = %+v, want a 5m hit", *out)
	}
	if got, want := warn.Drain(ctx), "ossprey: clean result reused from a scan 5m ago (--no-cache or OSSPREY_SCAN_CACHE_TTL=0 to rescan)\n"; got != want {
		t.Errorf("verdict hit line:\n got %q\nwant %q", got, want)
	}

	in := baseInput(t)
	in.Kind = Posted
	ctx, out = Observe(base)
	New(ctx, in).Hit(90 * time.Second)
	if !out.Hit || out.Age != 90*time.Second {
		t.Errorf("outcome = %+v, want a 90s hit", *out)
	}
	if got, want := warn.Drain(ctx), "ossprey: identical scan already sent 1m ago; not sent again\n"; got != want {
		t.Errorf("posted hit line:\n got %q\nwant %q", got, want)
	}
}

func TestHitWithoutAnObserverStillSaysSo(t *testing.T) {
	ctx, _ := lookupCtx(t)
	New(ctx, baseInput(t)).Hit(time.Second)
	if out := warn.Drain(ctx); !strings.Contains(out, "clean result reused") {
		t.Errorf("no hit line without an observer: %q", out)
	}
}

func TestObserveStartsUnhit(t *testing.T) {
	_, out := Observe(context.Background())
	if out.Hit || out.Age != 0 {
		t.Errorf("fresh outcome = %+v", *out)
	}
}

// A cache that cannot be written or read is nobody's problem but a debugger's:
// quiet runs print nothing about it, verbose runs get one line.
func TestCacheErrorsAreReportedOnlyWhenVerbose(t *testing.T) {
	root := t.TempDir()
	t.Setenv(DirEnv, root)
	t.Setenv(TTLEnv, "")
	// A file where the directory should be: every write and read fails.
	if err := os.WriteFile(filepath.Join(root, "scans"), []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := baseInput(t)

	quiet := warn.NewContext(context.Background(), false)
	l := New(quiet, in)
	l.Put(json.RawMessage(cleanResponse))
	if _, _, ok := l.Get(); ok {
		t.Fatal("hit from an unusable cache")
	}
	if out := warn.Drain(quiet); out != "" {
		t.Errorf("quiet run reported a cache problem: %q", out)
	}

	verbose := warn.NewContext(context.Background(), true)
	l = New(verbose, in)
	l.Put(json.RawMessage(cleanResponse))
	l.Get()
	if out := warn.Drain(verbose); !strings.Contains(out, "scan cache") {
		t.Errorf("verbose run did not explain the cache problem: %q", out)
	}
}

func TestCorruptEntryIsReportedOnlyWhenVerbose(t *testing.T) {
	ctx, dir := lookupCtx(t)
	in := baseInput(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile((&Store{Dir: dir}).path(Key(in), Verdict), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, ok := New(ctx, in).Get(); ok {
		t.Fatal("a corrupt entry hit")
	}
	if out := warn.Drain(ctx); out != "" {
		t.Errorf("quiet run reported the corrupt entry: %q", out)
	}

	verbose := warn.NewContext(context.Background(), true)
	if _, _, ok := New(verbose, in).Get(); ok {
		t.Fatal("a corrupt entry hit")
	}
	if out := warn.Drain(verbose); !strings.Contains(out, "scan cache") {
		t.Errorf("verbose run did not mention the corrupt entry: %q", out)
	}
}
