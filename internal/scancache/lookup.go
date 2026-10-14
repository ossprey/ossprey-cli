package scancache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Lookup is one cache slot resolved for one submission: the key for this
// (kind, SBOM, API URL, identity), the TTL in force and the store. It is what
// submit.Validate and submit.Post talk to, and it folds every "is the cache
// usable?" question into itself so the two seams stay three lines each.
//
// A Lookup that cannot work — no identity, TTL off, no cache directory — is
// not an error. Get misses, Put does nothing, and the scan proceeds exactly
// as it would have before the cache existed.
type Lookup struct {
	ctx      context.Context
	kind     Kind
	key      string
	ttl      time.Duration
	store    *Store
	enabled  bool
	readable bool
}

// New resolves the lookup for in on ctx. The context carries the warning
// collector (for the hit line and verbose diagnostics), the bypass flag set
// by --no-cache and the Outcome an observing caller asked for.
func New(ctx context.Context, in KeyInput) *Lookup {
	l := &Lookup{ctx: ctx, kind: in.Kind}
	if in.Identity == "" {
		return l
	}
	l.ttl = TTL(ctx)
	if l.ttl <= 0 {
		return l
	}
	store, err := Open()
	if err != nil {
		l.debug(err)
		return l
	}
	l.store = store
	l.key = Key(in)
	l.enabled = true
	l.readable = !Bypassed(ctx)
	return l
}

// Get returns the stored response (nil for a posted entry), its age and
// whether there was a fresh entry at all. Every failure is a miss.
func (l *Lookup) Get() (raw json.RawMessage, age time.Duration, ok bool) {
	if !l.enabled || !l.readable {
		return nil, 0, false
	}
	hit, err := l.store.Get(l.key, l.kind, l.ttl)
	if err != nil {
		l.debug(err)
		return nil, 0, false
	}
	if hit == nil {
		return nil, 0, false
	}
	// A verdict entry was only ever written for a clean response, so the
	// same test is applied on the way out. Anything else — a hand edit, a
	// truncated write, a schema that drifted — is a miss, never a pass; the
	// live run that follows overwrites it.
	if l.kind == Verdict && !Clean(hit.Response) {
		l.debug(fmt.Errorf("stored verdict for %s is not a clean response; ignoring it", l.key[:12]))
		return nil, 0, false
	}
	return hit.Response, hit.Age, true
}

// Hit records that this submission was served from the cache: it fills the
// Outcome of an observing caller and queues the one line the user sees. The
// line goes through the collector rather than straight to stderr so that it
// prints where warnings print — before the verdict in scan and check, and
// only under OSSPREY_VERBOSE in the forwarders, which are silent by default.
func (l *Lookup) Hit(age time.Duration) {
	if o, ok := l.ctx.Value(outcomeKey{}).(*Outcome); ok {
		o.Hit = true
		o.Age = age
	}
	warn.Add(l.ctx, hitEntry(l.kind, age))
}

// Put stores raw under this lookup's key. Best-effort: a failure is reported
// only to a verbose run and never to the caller.
func (l *Lookup) Put(raw json.RawMessage) {
	if !l.enabled {
		return
	}
	if err := l.store.Put(l.key, l.kind, raw); err != nil {
		l.debug(err)
	}
}

// debug records a cache problem for a verbose run only. At the default level
// the cache is invisible when it works and invisible when it does not: a
// scan's output must not change because a directory was unwritable.
func (l *Lookup) debug(err error) {
	if err == nil || !warn.Verbose(l.ctx) {
		return
	}
	warn.Add(l.ctx, warn.Entry{
		Class: "scan-cache-error",
		One:   "scan cache: " + err.Error() + " (the scan ran as if there were no cache)",
		Many:  "scan cache: %d problems (listed below); the scan ran as if there were no cache",
		Item:  err.Error(),
	})
}

func hitEntry(kind Kind, age time.Duration) warn.Entry {
	if kind == Posted {
		return warn.Entry{
			Class: "scan-cache-hit-posted",
			One:   fmt.Sprintf("identical scan already sent %s ago; not sent again", formatAge(age)),
			Many:  "%d identical scans already sent; not sent again",
		}
	}
	return warn.Entry{
		Class: "scan-cache-hit-verdict",
		One: fmt.Sprintf("clean result reused from a scan %s ago (--no-cache or %s=0 to rescan)",
			formatAge(age), TTLEnv),
		Many: "%d clean results reused from the scan cache (--no-cache or " + TTLEnv + "=0 to rescan)",
	}
}

type bypassKey struct{}

// WithBypass marks ctx so lookups skip the read and still write: the user
// asked for a fresh result (--no-cache), and the next run should reuse it.
func WithBypass(ctx context.Context) context.Context {
	return context.WithValue(ctx, bypassKey{}, true)
}

// Bypassed reports whether WithBypass marked ctx.
func Bypassed(ctx context.Context) bool {
	b, _ := ctx.Value(bypassKey{}).(bool)
	return b
}

// Outcome is what a caller learns after a submission went through a Lookup:
// whether it was served from the cache and how old the entry was. The report
// writer and the passive "Scan submitted" line read it.
type Outcome struct {
	Hit bool
	Age time.Duration
}

type outcomeKey struct{}

// Observe attaches a fresh Outcome to ctx and returns it. The caller passes
// the returned context down to submit and reads the Outcome afterwards; the
// submit signatures do not change.
func Observe(ctx context.Context) (context.Context, *Outcome) {
	o := &Outcome{}
	return context.WithValue(ctx, outcomeKey{}, o), o
}
