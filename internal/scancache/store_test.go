package scancache

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	keyA = strings.Repeat("a", 64)
	keyB = strings.Repeat("b", 64)
)

const cleanResponse = `{"vulnerabilities":[],"findings":[{"purl":"pkg:npm/x@1","type":"NOT_FOUND"}]}`

func newStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Dir: filepath.Join(t.TempDir(), "scans")}
}

// fixNow pins the store's clock and restores it afterwards.
func fixNow(t *testing.T, at time.Time) {
	t.Helper()
	old := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = old })
}

func mustPut(t *testing.T, s *Store, key string, kind Kind, raw string) {
	t.Helper()
	var msg json.RawMessage
	if raw != "" {
		msg = json.RawMessage(raw)
	}
	if err := s.Put(key, kind, msg); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func entryFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestPutThenGetReturnsTheResponse(t *testing.T) {
	s := newStore(t)
	mustPut(t, s, keyA, Verdict, cleanResponse)

	hit, err := s.Get(keyA, Verdict, time.Hour)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if hit == nil {
		t.Fatal("Get missed an entry that was just written")
	}
	if string(hit.Response) != cleanResponse {
		t.Errorf("response round-trip changed it:\n got %s\nwant %s", hit.Response, cleanResponse)
	}
	if hit.Age < 0 || hit.Age > time.Minute {
		t.Errorf("age %v is not a just-written age", hit.Age)
	}
}

func TestGetOfAnAbsentKeyIsAMiss(t *testing.T) {
	s := newStore(t)
	mustPut(t, s, keyA, Verdict, cleanResponse)

	hit, err := s.Get(keyB, Verdict, time.Hour)
	if err != nil || hit != nil {
		t.Fatalf("Get(absent) = %v, %v; want nil, nil", hit, err)
	}
}

// A posted entry holds no verdict, so it must never answer a verdict lookup,
// and a verdict entry must not stand in for a post that was never made.
func TestKindsNeverCross(t *testing.T) {
	s := newStore(t)
	mustPut(t, s, keyA, Posted, "")
	if hit, _ := s.Get(keyA, Verdict, time.Hour); hit != nil {
		t.Error("a posted entry satisfied a verdict lookup")
	}

	s = newStore(t)
	mustPut(t, s, keyA, Verdict, cleanResponse)
	if hit, _ := s.Get(keyA, Posted, time.Hour); hit != nil {
		t.Error("a verdict entry satisfied a posted lookup")
	}
}

// The filename says verdict but the entry inside says posted: a hand edit or
// a bug. Trust neither; it is a miss.
func TestKindMismatchInsideTheFileIsAMiss(t *testing.T) {
	s := newStore(t)
	mustPut(t, s, keyA, Posted, "")
	posted, err := os.ReadFile(s.path(keyA, Posted))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path(keyA, Verdict), posted, 0o600); err != nil {
		t.Fatal(err)
	}

	hit, err := s.Get(keyA, Verdict, time.Hour)
	if hit != nil {
		t.Fatal("a mislabelled entry was served")
	}
	if err == nil {
		t.Error("a mislabelled entry should be reported, so verbose runs can see it")
	}
}

func TestExpiredEntryIsAMissAndIsRemoved(t *testing.T) {
	s := newStore(t)
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	fixNow(t, base)
	mustPut(t, s, keyA, Verdict, cleanResponse)

	fixNow(t, base.Add(61*time.Minute))
	hit, err := s.Get(keyA, Verdict, time.Hour)
	if err != nil || hit != nil {
		t.Fatalf("Get(expired) = %v, %v; want nil, nil", hit, err)
	}
	if _, err := os.Stat(s.path(keyA, Verdict)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expired entry still on disk (stat err %v)", err)
	}
}

func TestEntryWithinTTLIsAHit(t *testing.T) {
	s := newStore(t)
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	fixNow(t, base)
	mustPut(t, s, keyA, Verdict, cleanResponse)

	fixNow(t, base.Add(59*time.Minute))
	hit, err := s.Get(keyA, Verdict, time.Hour)
	if err != nil || hit == nil {
		t.Fatalf("Get(59m old, 1h ttl) = %v, %v; want a hit", hit, err)
	}
	if hit.Age != 59*time.Minute {
		t.Errorf("age = %v, want 59m", hit.Age)
	}
}

// A stored_at in the future means the clock went backwards. Treating it as
// fresh would keep the entry alive until the clock caught up, which could be
// never; it is a miss.
func TestEntryFromTheFutureIsAMiss(t *testing.T) {
	s := newStore(t)
	base := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	fixNow(t, base)
	mustPut(t, s, keyA, Verdict, cleanResponse)

	fixNow(t, base.Add(-10*time.Minute))
	if hit, _ := s.Get(keyA, Verdict, time.Hour); hit != nil {
		t.Fatal("an entry stored in the future was served")
	}
}

func TestZeroTTLNeverReads(t *testing.T) {
	s := newStore(t)
	mustPut(t, s, keyA, Verdict, cleanResponse)
	if hit, err := s.Get(keyA, Verdict, 0); hit != nil || err != nil {
		t.Fatalf("Get with ttl 0 = %v, %v; want nil, nil", hit, err)
	}
}

func TestCorruptEntryIsAMissWithAnError(t *testing.T) {
	for _, body := range []string{"not json", "[]", `{"kind":"verdict","stored_at":"yesterday"}`} {
		s := newStore(t)
		if err := os.MkdirAll(s.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.path(keyA, Verdict), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		hit, err := s.Get(keyA, Verdict, time.Hour)
		if hit != nil {
			t.Errorf("%q: a corrupt entry was served", body)
		}
		if err == nil {
			t.Errorf("%q: a corrupt entry was not reported", body)
		}
	}
}

// The cache directory is a regular file: nothing can be read or written, and
// both say so instead of panicking.
func TestUnusableDirIsAnError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "scans")
	if err := os.WriteFile(file, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: file}
	if err := s.Put(keyA, Verdict, json.RawMessage(cleanResponse)); err == nil {
		t.Error("Put into a file succeeded")
	}
	if hit, err := s.Get(keyA, Verdict, time.Hour); hit != nil || err == nil {
		t.Errorf("Get from a file = %v, %v; want nil and an error", hit, err)
	}
}

func TestReadOnlyDirFailsPutButNotGet(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("permission bits are not enforced here")
	}
	s := newStore(t)
	mustPut(t, s, keyA, Verdict, cleanResponse)
	if err := os.Chmod(s.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(s.Dir, 0o700) })

	if err := s.Put(keyB, Verdict, json.RawMessage(cleanResponse)); err == nil {
		t.Error("Put into a read-only dir succeeded")
	}
	if hit, err := s.Get(keyA, Verdict, time.Hour); hit == nil || err != nil {
		t.Errorf("Get from a read-only dir = %v, %v; want the entry", hit, err)
	}
}

func TestDirAndFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX modes on windows")
	}
	s := newStore(t)
	mustPut(t, s, keyA, Verdict, cleanResponse)

	dir, err := os.Stat(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dir.Mode().Perm(); got != 0o700 {
		t.Errorf("dir mode %o, want 700", got)
	}
	file, err := os.Stat(s.path(keyA, Verdict))
	if err != nil {
		t.Fatal(err)
	}
	if got := file.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode %o, want 600", got)
	}
}

// Two CLI processes finishing the same scan at once must not leave a torn
// file behind: the entry is either one writer's whole response or the other's.
func TestConcurrentPutsLeaveOneValidEntry(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw := json.RawMessage(strings.Replace(cleanResponse, `"findings"`, `"writer":`+strings.Repeat("9", i+1)+`,"findings"`, 1))
			_ = s.Put(keyA, Verdict, raw)
		}(i)
	}
	wg.Wait()

	hit, err := s.Get(keyA, Verdict, time.Hour)
	if err != nil || hit == nil {
		t.Fatalf("Get after concurrent puts = %v, %v", hit, err)
	}
	if !json.Valid(hit.Response) {
		t.Errorf("stored response is not valid JSON: %s", hit.Response)
	}
	if names := entryFiles(t, s.Dir); len(names) != 1 {
		t.Errorf("want exactly one file after concurrent puts, got %v", names)
	}
}

// Nothing a user typed may land in the cache directory, in a filename or in
// a file. The key is a hash and the entry holds only the API's response.
func TestNoSecretReachesDisk(t *testing.T) {
	const apiKey = "ospy_THIS-IS-A-SECRET-KEY"
	const monitorID = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	s := newStore(t)
	in := baseInput(t)
	in.Identity = FingerprintAPIKey(apiKey)
	mustPut(t, s, Key(in), Verdict, cleanResponse)
	in.Kind, in.Identity = Posted, FingerprintMonitor(monitorID)
	mustPut(t, s, Key(in), Posted, "")

	for _, name := range entryFiles(t, s.Dir) {
		data, err := os.ReadFile(filepath.Join(s.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{apiKey, monitorID, "THIS-IS-A-SECRET"} {
			if strings.Contains(name, secret) || strings.Contains(string(data), secret) {
				t.Errorf("%s leaks %q", name, secret)
			}
		}
	}
}

func touch(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"kind":"verdict","stored_at":"2026-10-08T00:00:00Z","response":{"vulnerabilities":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// Prune deletes our own stale entries and abandoned temp files, and nothing
// else: OSSPREY_CACHE_DIR may be pointed at a directory other things use.
func TestPutPrunesStaleEntriesAndTempFilesOnly(t *testing.T) {
	s := newStore(t)
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-25 * time.Hour)
	fresh := time.Now().Add(-time.Hour)
	touch(t, s.path(keyB, Verdict), stale)
	touch(t, s.path(strings.Repeat("c", 64), Posted), fresh)
	touch(t, filepath.Join(s.Dir, ".tmp-abandoned"), stale)
	touch(t, filepath.Join(s.Dir, ".tmp-live"), fresh)
	touch(t, filepath.Join(s.Dir, "notes.txt"), stale)
	touch(t, filepath.Join(s.Dir, "other.json"), stale)
	touch(t, filepath.Join(s.Dir, "verdict-notahash.json"), stale)

	mustPut(t, s, keyA, Verdict, cleanResponse)

	got := entryFiles(t, s.Dir)
	want := map[string]bool{
		filepath.Base(s.path(keyA, Verdict)):                   true,
		filepath.Base(s.path(strings.Repeat("c", 64), Posted)): true,
		".tmp-live":                          true,
		"notes.txt":                          true,
		"other.json":                         true,
		"verdict-notahash.json":              true,
		filepath.Base(s.path(keyB, Verdict)): false,
		".tmp-abandoned":                     false,
	}
	for name, keep := range want {
		present := false
		for _, g := range got {
			if g == name {
				present = true
			}
		}
		if present != keep {
			t.Errorf("%s: present=%v, want %v (dir: %v)", name, present, keep, got)
		}
	}
}

func TestPutCapsTheEntryCountOldestFirst(t *testing.T) {
	old := maxEntries
	maxEntries = 3
	t.Cleanup(func() { maxEntries = old })

	s := newStore(t)
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		touch(t, s.path(strings.Repeat(string(rune('a'+i)), 64), Verdict), base.Add(time.Duration(i)*time.Minute))
	}

	mustPut(t, s, strings.Repeat("f", 64), Verdict, cleanResponse)

	got := entryFiles(t, s.Dir)
	if len(got) != 3 {
		t.Fatalf("want 3 entries after the cap, got %d: %v", len(got), got)
	}
	for _, survivor := range []string{"d", "e", "f"} {
		name := filepath.Base(s.path(strings.Repeat(survivor, 64), Verdict))
		found := false
		for _, g := range got {
			if g == name {
				found = true
			}
		}
		if !found {
			t.Errorf("newest entry %s was pruned; survivors: %v", survivor, got)
		}
	}
}

func TestOpenUsesDir(t *testing.T) {
	root := t.TempDir()
	t.Setenv(DirEnv, root)
	s, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "scans"); s.Dir != want {
		t.Errorf("Open().Dir = %q, want %q", s.Dir, want)
	}
	if _, err := os.Stat(s.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open created the directory before anything was written (stat err %v)", err)
	}
}
