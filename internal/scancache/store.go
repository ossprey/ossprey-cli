package scancache

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// now is the store's clock, swapped by tests so expiry is checked without
// sleeping.
var now = time.Now

// maxAge is how long any entry survives on disk, whatever the TTL asked for
// at read time. It equals MaxTTL, the longest anything could ever be reused.
const maxAge = MaxTTL

// maxEntries caps the directory so a machine that scans thousands of distinct
// projects does not grow it without bound. A var so a test can lower it.
var maxEntries = 1000

// tempPrefix marks a writer's in-flight file. It starts with a dot so a
// crashed writer's leftover never matches entryName and is pruned by age
// rather than mistaken for an entry.
const tempPrefix = ".tmp-"

// entryName is the only shape prune will delete: our two kinds, a 64-hex
// key, .json. Anything else in the directory belongs to somebody else.
var entryName = regexp.MustCompile(`^(` + string(Verdict) + `|` + string(Posted) + `)-[0-9a-f]{64}\.json$`)

// Store is the on-disk cache: one small JSON file per entry under Dir.
type Store struct {
	Dir string
}

// Open resolves the store's directory without creating it. A machine that
// never writes an entry never gets a cache directory.
func Open() (*Store, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// Hit is a fresh entry: the raw API response a verdict entry stored (nil for
// a posted entry) and how long ago it was written.
type Hit struct {
	Response json.RawMessage
	Age      time.Duration
}

// entry is the file format. Response is omitted for a posted entry.
type entry struct {
	Kind     Kind            `json:"kind"`
	StoredAt time.Time       `json:"stored_at"`
	Response json.RawMessage `json:"response,omitempty"`
}

func (s *Store) path(key string, kind Kind) string {
	return filepath.Join(s.Dir, string(kind)+"-"+key+".json")
}

// Get returns the entry under key if one exists, is of the asked kind and is
// younger than ttl. A missing or expired entry is (nil, nil). Anything else
// that stops the entry being used — an unreadable file, one that does not
// parse, one whose kind disagrees with its name — is (nil, err), so a verbose
// run can say why the cache did not help; callers treat it as a miss.
func (s *Store) Get(key string, kind Kind, ttl time.Duration) (*Hit, error) {
	if ttl <= 0 {
		return nil, nil
	}
	p := s.path(key, kind)
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read cache entry: %w", err)
	}
	var e entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("parse cache entry %s: %w", filepath.Base(p), err)
	}
	if e.Kind != kind {
		return nil, fmt.Errorf("cache entry %s is a %q entry, not %q", filepath.Base(p), e.Kind, kind)
	}
	age := now().Sub(e.StoredAt)
	// A negative age means the clock went backwards since the entry was
	// written. Serving it would keep it alive until the clock caught up, so it
	// is treated exactly like an expired one.
	if age < 0 || age > ttl {
		_ = os.Remove(p)
		return nil, nil
	}
	return &Hit{Response: e.Response, Age: age}, nil
}

// Put writes an entry, replacing any existing one, then prunes the directory.
//
// The write goes to a temp file in the same directory and is renamed into
// place, so two CLI processes finishing the same scan at once cannot leave a
// torn file: a reader sees one writer's whole entry or the other's. The
// directory is 0700 and the file 0600, like credentials.json.
func (s *Store) Put(key string, kind Kind, raw json.RawMessage) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	data, err := json.Marshal(entry{Kind: kind, StoredAt: now().UTC(), Response: raw})
	if err != nil {
		return fmt.Errorf("encode cache entry: %w", err)
	}
	tmp, err := os.CreateTemp(s.Dir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("write cache entry: %w", err)
	}
	// CreateTemp already uses 0600; said explicitly so a changed umask or a
	// future refactor cannot loosen it in silence.
	if err := writeAndClose(tmp, data); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write cache entry: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path(key, kind)); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write cache entry: %w", err)
	}
	s.prune()
	return nil
}

func writeAndClose(f *os.File, data []byte) error {
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// prune deletes entries and abandoned temp files older than maxAge, then
// trims the entries to maxEntries, oldest first. It only ever touches files
// matching our own naming, because OSSPREY_CACHE_DIR may be pointed at a
// directory other things use. Best-effort throughout: an error here is not
// worth failing a write over.
func (s *Store) prune() {
	dirents, err := os.ReadDir(s.Dir)
	if err != nil {
		return
	}
	type aged struct {
		path string
		mod  time.Time
	}
	var entries []aged
	cutoff := now().Add(-maxAge)
	for _, d := range dirents {
		if d.IsDir() {
			continue
		}
		name := d.Name()
		isTemp := strings.HasPrefix(name, tempPrefix)
		if !isTemp && !entryName.MatchString(name) {
			continue
		}
		info, err := d.Info()
		if err != nil {
			continue
		}
		p := filepath.Join(s.Dir, name)
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(p)
			continue
		}
		if isTemp {
			// A live writer's file: leave it to finish.
			continue
		}
		entries = append(entries, aged{path: p, mod: info.ModTime()})
	}
	if len(entries) <= maxEntries {
		return
	}
	slices.SortFunc(entries, func(a, b aged) int { return a.mod.Compare(b.mod) })
	for _, e := range entries[:len(entries)-maxEntries] {
		_ = os.Remove(e.path)
	}
}
