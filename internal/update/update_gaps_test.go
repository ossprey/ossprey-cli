package update

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func redirectTo(t *testing.T, tag string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Redirect(w, r, "/tag/"+tag, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestNoticeVersionComparison(t *testing.T) {
	cases := []struct {
		current, latest string
		notice          bool
	}{
		{"v1.0.0", "v1.0.0", false},
		{"v1.0.0", "v1.0.1", true},
		{"1.0.0-rc.1", "v1.0.0", true}, // a prerelease is older than its release
		{"1.1.0-rc.1", "v1.0.0", false},
		{"1.9.0", "v1.10.0", true}, // numeric, not lexical
	}
	for _, c := range cases {
		srv, _ := redirectTo(t, c.latest)
		var out bytes.Buffer
		err := Notice(context.Background(), NoticeOptions{
			Current: c.current, BaseURL: srv.URL, CachePath: filepath.Join(t.TempDir(), "c.json"), Out: &out,
		})
		if err != nil {
			t.Fatalf("%s vs %s: %v", c.current, c.latest, err)
		}
		if got := out.Len() > 0; got != c.notice {
			t.Errorf("%s vs %s: notice=%v (%q), want %v", c.current, c.latest, got, out.String(), c.notice)
		}
	}
}

// An unversioned build cannot be compared, so it asks nothing.
func TestNoticeUnparseableCurrentMakesNoRequest(t *testing.T) {
	srv, n := redirectTo(t, "v1.0.0")
	err := Notice(context.Background(), NoticeOptions{
		Current: "dev", BaseURL: srv.URL, CachePath: filepath.Join(t.TempDir(), "c.json"),
	})
	if err == nil || n.Load() != 0 {
		t.Fatalf("err=%v requests=%d; want an error and no request", err, n.Load())
	}
}

// A corrupt cache (or one holding a non-version) is refetched and rewritten.
func TestNoticeRecoversFromACorruptCache(t *testing.T) {
	for _, body := range []string{"{not json", `{"latest":"garbage","checked_at":"2099-01-01T00:00:00Z"}`} {
		cachePath := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(cachePath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		srv, n := redirectTo(t, "v2.0.0")
		var out bytes.Buffer
		now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
		err := Notice(context.Background(), NoticeOptions{
			Current: "1.0.0", BaseURL: srv.URL, CachePath: cachePath, Out: &out, Now: func() time.Time { return now },
		})
		if err != nil || n.Load() != 1 || !strings.Contains(out.String(), "1.0.0 -> 2.0.0") {
			t.Fatalf("cache %q: err=%v requests=%d out=%q", body, err, n.Load(), out.String())
		}
		var c noticeCache
		data, _ := os.ReadFile(cachePath)
		if json.Unmarshal(data, &c) != nil || c.Latest != "v2.0.0" {
			t.Fatalf("cache not rewritten: %s", data)
		}
	}
}

// A failed release lookup prints nothing and caches nothing, so the next run
// tries again.
func TestNoticeLookupFailureIsQuietAndUncached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	cachePath := filepath.Join(t.TempDir(), "c.json")
	var out bytes.Buffer
	if err := Notice(context.Background(), NoticeOptions{Current: "1.0.0", BaseURL: srv.URL, CachePath: cachePath, Out: &out}); err == nil {
		t.Fatal("want an error the caller can ignore")
	}
	if out.Len() != 0 {
		t.Fatalf("printed %q", out.String())
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Fatal("a failed lookup was cached")
	}
}

// Failing to write the cache still shows the notice.
func TestNoticeCacheWriteFailureStillNotifies(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, _ := redirectTo(t, "v2.0.0")
	var out bytes.Buffer
	err := Notice(context.Background(), NoticeOptions{
		Current: "1.0.0", BaseURL: srv.URL, CachePath: filepath.Join(blocker, "sub", "c.json"), Out: &out,
	})
	if err == nil {
		t.Fatal("want the cache error reported")
	}
	if !strings.Contains(out.String(), "1.0.0 -> 2.0.0") {
		t.Fatalf("notice lost on cache failure: %q", out.String())
	}
}

func TestRunVPrefixedCurrentIsUpToDate(t *testing.T) {
	srv, downloads := newReleaseServer(t, "v1.2.3", []byte("bin"), true)
	var out bytes.Buffer
	if err := Run(context.Background(), Options{Current: "v1.2.3", BaseURL: srv.URL, ExePath: fakeExe(t), Out: &out}); err != nil {
		t.Fatal(err)
	}
	if downloads.Load() != 0 || !strings.Contains(out.String(), "already the latest version") {
		t.Fatalf("downloads=%d out=%q", downloads.Load(), out.String())
	}
}

// A sidecar that exists but cannot be fetched is not "missing": verification
// must fail closed rather than install an unverified binary.
func TestRunChecksumServerErrorFailsClosed(t *testing.T) {
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	mux := http.NewServeMux()
	mux.HandleFunc("/download/v2.0.0/"+asset, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("new")) })
	mux.HandleFunc("/download/v2.0.0/"+asset+".sha256", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "oops", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	exe := fakeExe(t)
	err := Run(context.Background(), Options{Current: "1.0.0", Target: "v2.0.0", BaseURL: srv.URL, ExePath: exe})
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err = %v, want a checksum download error", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatalf("binary replaced without verification: %q", got)
	}
}

func TestRunAssetServerErrorLeavesBinary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "oops", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	exe := fakeExe(t)
	if err := Run(context.Background(), Options{Current: "1.0.0", Target: "v2.0.0", BaseURL: srv.URL, ExePath: exe}); err == nil {
		t.Fatal("want an error")
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Fatalf("binary modified: %q", got)
	}
}

// The swap keeps the binary executable and leaves no temp file behind.
func TestReplaceExecutableKeepsModeAndCleansUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	exe := fakeExe(t)
	if err := os.Chmod(exe, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutable(exe, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o750 != 0o750 || perm&0o006 != 0 {
		t.Fatalf("mode = %v; want the original 0750 bits kept and no other read/write", perm)
	}
	assertNoUpdateTemps(t, filepath.Dir(exe))
}

// When the swap cannot happen the old binary stays and the temp file goes.
func TestReplaceExecutableFailureLeavesNoTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rename-onto-directory semantics differ")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "ossprey")
	if err := os.Mkdir(target, 0o755); err != nil { // rename onto a directory fails
		t.Fatal(err)
	}
	if err := replaceExecutable(target, []byte("new")); err == nil {
		t.Fatal("want an error")
	}
	assertNoUpdateTemps(t, dir)

	if err := replaceExecutable(filepath.Join(dir, "missing", "ossprey"), []byte("new")); err == nil {
		t.Fatal("want an error for a missing directory")
	}
}

func assertNoUpdateTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ossprey-update-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestLatestTagParsesTheRedirect(t *testing.T) {
	for loc, want := range map[string]string{
		"/ossprey/ossprey-cli/releases/tag/v1.2.3":    "v1.2.3",
		"https://github.com/o/r/releases/tag/v1.2.3/": "v1.2.3",
		"/releases/latest":                            "",
		"":                                            "",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if loc != "" {
				w.Header().Set("Location", loc)
			}
			w.WriteHeader(http.StatusFound)
		}))
		got, err := latestTag(context.Background(), srv.URL)
		srv.Close()
		if want == "" {
			if err == nil {
				t.Errorf("Location %q: got %q, want an error", loc, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("Location %q: got %q, %v; want %q", loc, got, err, want)
		}
	}
}

// A build newer than the latest release (a release candidate, a fresh tag the
// redirect has not caught up with) is never "updated" backwards, by --check or
// by a plain update. Only --force or an explicit --version may downgrade.
func TestRunNeverDowngradesToLatest(t *testing.T) {
	for _, current := range []string{"1.1.0", "v1.10.0"} {
		srv, downloads := newReleaseServer(t, "v1.0.0", []byte("old release"), true)
		for _, check := range []bool{true, false} {
			exe := fakeExe(t)
			var out bytes.Buffer
			err := Run(context.Background(), Options{Current: current, CheckOnly: check, BaseURL: srv.URL, ExePath: exe, Out: &out})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "update available") || downloads.Load() != 0 {
				t.Fatalf("current %s check=%v: out=%q downloads=%d", current, check, out.String(), downloads.Load())
			}
			if got, _ := os.ReadFile(exe); string(got) != "old binary" {
				t.Fatalf("current %s: binary replaced: %q", current, got)
			}
		}
	}

	srv, downloads := newReleaseServer(t, "v1.0.0", []byte("old release"), true)
	if err := Run(context.Background(), Options{Current: "1.1.0", Force: true, BaseURL: srv.URL, ExePath: fakeExe(t)}); err != nil || downloads.Load() != 1 {
		t.Fatalf("--force: err=%v downloads=%d; want the downgrade installed", err, downloads.Load())
	}
}

// Comparison is numeric, and a dev build (no comparable version) can still
// update rather than being stuck.
func TestRunComparesAsSemver(t *testing.T) {
	for _, current := range []string{"1.9.0", "dev", "1.10.0-rc.1"} {
		srv, downloads := newReleaseServer(t, "v1.10.0", []byte("new"), true)
		if err := Run(context.Background(), Options{Current: current, BaseURL: srv.URL, ExePath: fakeExe(t)}); err != nil || downloads.Load() != 1 {
			t.Errorf("current %s: err=%v downloads=%d; want an update", current, err, downloads.Load())
		}
	}
}
