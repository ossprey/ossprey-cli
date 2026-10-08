package submit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/scancache"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

const (
	cleanBody   = `{"vulnerabilities":[],"findings":[{"purl":"pkg:pypi/requests@2.31.0","type":"NOT_FOUND"}]}`
	malwareBody = `{"vulnerabilities":[{"id":"V1","purl":"pkg:pypi/requests@2.31.0","type":"Malware","reference":"x"}]}`
	infoBody    = `{"vulnerabilities":[{"id":"V1","purl":"pkg:pypi/requests@2.31.0","type":"Malware","reference":"x","severity":"Info"}]}`
	accepted    = `{"sbom_id":"sb1","scan_id":"sc1"}`
	monitorID   = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// cacheEnv isolates the cache, the config dir and the credential env, and
// returns a quiet collector context plus the cache's scans/ directory.
func cacheEnv(t *testing.T) (context.Context, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("OSSPREY_CACHE_DIR", root)
	t.Setenv("OSSPREY_SCAN_CACHE_TTL", "")
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	t.Setenv("OSSPREY_API_KEY", "")
	t.Setenv("API_KEY", "")
	return warn.NewContext(context.Background(), false), filepath.Join(root, "scans")
}

// api is a scans endpoint that counts submissions and answers every POST the
// same way; a status poll, when one happens, gets statusBody.
type api struct {
	*httptest.Server
	posts      atomic.Int32
	status     int
	body       string
	statusBody string
}

func newAPI(t *testing.T, status int, body string) *api {
	t.Helper()
	a := &api{status: status, body: body}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/scans/status") {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, a.statusBody)
			return
		}
		a.posts.Add(1)
		w.WriteHeader(a.status)
		io.WriteString(w, a.body)
	}))
	t.Cleanup(a.Close)
	return a
}

func cacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestValidate_SecondIdenticalScanIsServedFromCache(t *testing.T) {
	base, dir := cacheEnv(t)
	srv := newAPI(t, http.StatusOK, cleanBody)

	ctx1, out1 := scancache.Observe(base)
	if err := Validate(ctx1, newSBOM(), srv.URL, "test-key"); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	if out1.Hit {
		t.Error("first scan reported a cache hit")
	}
	if n := len(cacheFiles(t, dir)); n != 1 {
		t.Fatalf("want one verdict entry after a clean scan, got %d", n)
	}

	ctx2, out2 := scancache.Observe(base)
	sbom := newSBOM()
	if err := Validate(ctx2, sbom, srv.URL, "test-key"); err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if got := srv.posts.Load(); got != 1 {
		t.Errorf("the second identical scan reached the API (%d posts)", got)
	}
	if !out2.Hit {
		t.Error("second scan did not report a cache hit")
	}
	if len(sbom.Vulnerabilities) != 0 || len(sbom.Findings) != 1 || sbom.Unscanned() != 1 {
		t.Errorf("replayed response was not applied like the live one: vulns=%d findings=%d unscanned=%d",
			len(sbom.Vulnerabilities), len(sbom.Findings), sbom.Unscanned())
	}
	if out := warn.Drain(ctx2); !strings.Contains(out, "clean result reused from a scan") {
		t.Errorf("no hit line in the drain: %q", out)
	}
}

// The key is built from the URL the client actually uses, so a trailing slash
// does not make a second copy of the same server.
func TestValidate_TrailingSlashSharesTheEntry(t *testing.T) {
	ctx, _ := cacheEnv(t)
	srv := newAPI(t, http.StatusOK, cleanBody)

	if err := Validate(ctx, newSBOM(), srv.URL, "test-key"); err != nil {
		t.Fatal(err)
	}
	if err := Validate(ctx, newSBOM(), srv.URL+"/", "test-key"); err != nil {
		t.Fatal(err)
	}
	if got := srv.posts.Load(); got != 1 {
		t.Errorf("trailing slash was a different key (%d posts)", got)
	}
}

// Only a clean verdict is ever stored. Everything else — malware at any
// severity, an error, a quota skip, a failed scan, a cancelled wait — leaves
// the cache exactly as it was.
func TestValidate_StoresOnlyCleanVerdicts(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		statusBody string
		cancel     bool
	}{
		{name: "malware", status: http.StatusOK, body: malwareBody},
		{name: "informational", status: http.StatusOK, body: infoBody},
		{name: "server error", status: http.StatusInternalServerError, body: `{"message":"boom"}`},
		{name: "quota skipped", status: http.StatusAccepted, body: accepted, statusBody: `{"status":"SKIPPED","message":"quota"}`},
		{name: "failed", status: http.StatusAccepted, body: accepted, statusBody: `{"status":"FAILED","message":"nope"}`},
		{name: "cancelled while polling", status: http.StatusAccepted, body: accepted, cancel: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, dir := cacheEnv(t)
			srv := newAPI(t, c.status, c.body)
			srv.statusBody = c.statusBody
			if c.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			sbom := newSBOM()
			err := Validate(ctx, sbom, srv.URL, "test-key")
			switch c.name {
			case "malware", "informational":
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				if len(sbom.Vulnerabilities) != 1 {
					t.Fatalf("live verdict not applied: %d vulnerabilities", len(sbom.Vulnerabilities))
				}
			default:
				if err == nil {
					t.Fatal("expected an error")
				}
			}
			if files := cacheFiles(t, dir); len(files) != 0 {
				t.Errorf("a non-clean outcome was cached: %v", files)
			}
		})
	}
}

func TestPost_SecondIdenticalPostIsNotSent(t *testing.T) {
	base, dir := cacheEnv(t)
	srv := newAPI(t, http.StatusAccepted, accepted)

	if err := Post(base, newSBOM(), srv.URL, "test-key", ""); err != nil {
		t.Fatalf("first Post: %v", err)
	}
	if n := len(cacheFiles(t, dir)); n != 1 {
		t.Fatalf("want one posted entry, got %d", n)
	}

	ctx, out := scancache.Observe(base)
	if err := Post(ctx, newSBOM(), srv.URL, "test-key", ""); err != nil {
		t.Fatalf("second Post: %v", err)
	}
	if got := srv.posts.Load(); got != 1 {
		t.Errorf("the second identical post reached the API (%d posts)", got)
	}
	if !out.Hit {
		t.Error("second post did not report a hit")
	}
	if drain := warn.Drain(ctx); !strings.Contains(drain, "identical scan already sent") {
		t.Errorf("no dedupe line in the drain: %q", drain)
	}
}

func TestPost_FailedPostIsNotCached(t *testing.T) {
	ctx, dir := cacheEnv(t)
	srv := newAPI(t, http.StatusInternalServerError, "")

	for i := 0; i < 2; i++ {
		if err := Post(ctx, newSBOM(), srv.URL, "test-key", ""); err == nil {
			t.Fatal("expected an error from a 500")
		}
	}
	if got := srv.posts.Load(); got != 2 {
		t.Errorf("a failed post was deduplicated (%d posts)", got)
	}
	if files := cacheFiles(t, dir); len(files) != 0 {
		t.Errorf("a failed post was cached: %v", files)
	}
}

// A posted entry carries no verdict, so it must never let a blocking scan
// pass; and a clean verdict is not evidence that a passive post was made.
func TestPostedAndVerdictEntriesNeverCross(t *testing.T) {
	t.Run("posted does not satisfy Validate", func(t *testing.T) {
		ctx, _ := cacheEnv(t)
		srv := newAPI(t, http.StatusOK, cleanBody)
		if err := Post(ctx, newSBOM(), srv.URL, "test-key", ""); err != nil {
			t.Fatal(err)
		}
		if err := Validate(ctx, newSBOM(), srv.URL, "test-key"); err != nil {
			t.Fatal(err)
		}
		if got := srv.posts.Load(); got != 2 {
			t.Errorf("Validate was answered by a posted entry (%d posts)", got)
		}
	})
	t.Run("verdict does not satisfy Post", func(t *testing.T) {
		ctx, _ := cacheEnv(t)
		srv := newAPI(t, http.StatusOK, cleanBody)
		if err := Validate(ctx, newSBOM(), srv.URL, "test-key"); err != nil {
			t.Fatal(err)
		}
		if err := Post(ctx, newSBOM(), srv.URL, "test-key", ""); err != nil {
			t.Fatal(err)
		}
		if got := srv.posts.Load(); got != 2 {
			t.Errorf("Post was answered by a verdict entry (%d posts)", got)
		}
	})
}

// idToken builds an unsigned JWT whose payload carries email, which is all
// Credentials.Identity reads.
func idToken(email string) string {
	payload, _ := json.Marshal(map[string]string{"email": email, "sub": "auth0|1"})
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + ".sig"
}

func TestValidate_StoredLoginIsCachedByIdentityOnly(t *testing.T) {
	t.Run("no identity, no cache", func(t *testing.T) {
		ctx, dir := cacheEnv(t)
		srv := newAPI(t, http.StatusOK, cleanBody)
		if err := auth.Save(&auth.Credentials{AccessToken: "at", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := Validate(ctx, newSBOM(), srv.URL, ""); err != nil {
				t.Fatal(err)
			}
		}
		if got := srv.posts.Load(); got != 2 {
			t.Errorf("a login with no identity was cached (%d posts)", got)
		}
		if files := cacheFiles(t, dir); len(files) != 0 {
			t.Errorf("a login with no identity wrote %v", files)
		}
	})
	t.Run("identity present", func(t *testing.T) {
		ctx, dir := cacheEnv(t)
		srv := newAPI(t, http.StatusOK, cleanBody)
		const token = "at-SECRET-ACCESS-TOKEN"
		if err := auth.Save(&auth.Credentials{
			AccessToken: token, IDToken: idToken("dev@ossprey.com"), ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := Validate(ctx, newSBOM(), srv.URL, ""); err != nil {
				t.Fatal(err)
			}
		}
		if got := srv.posts.Load(); got != 1 {
			t.Errorf("a login with an identity was not cached (%d posts)", got)
		}
		for _, name := range cacheFiles(t, dir) {
			data, _ := os.ReadFile(filepath.Join(dir, name))
			for _, secret := range []string{"dev@ossprey.com", token} {
				if strings.Contains(name, secret) || strings.Contains(string(data), secret) {
					t.Errorf("%s leaks %q", name, secret)
				}
			}
		}
	})
}

func TestValidate_CorruptEntryGoesLive(t *testing.T) {
	ctx, dir := cacheEnv(t)
	srv := newAPI(t, http.StatusOK, cleanBody)
	if err := Validate(ctx, newSBOM(), srv.URL, "test-key"); err != nil {
		t.Fatal(err)
	}
	files := cacheFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("want one entry, got %v", files)
	}
	if err := os.WriteFile(filepath.Join(dir, files[0]), []byte(`{"kind":"verdict","stored_at":"2026-10-08T00:00:00Z","response":"not an object"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	sbom := newSBOM()
	if err := Validate(ctx, sbom, srv.URL, "test-key"); err != nil {
		t.Fatalf("Validate after corrupting the entry: %v", err)
	}
	if got := srv.posts.Load(); got != 2 {
		t.Errorf("a corrupt entry was served instead of going live (%d posts)", got)
	}
	if len(sbom.Findings) != 1 {
		t.Errorf("live response not applied after a corrupt entry: %d findings", len(sbom.Findings))
	}
}

func TestValidate_BypassRequestsAndRewrites(t *testing.T) {
	base, _ := cacheEnv(t)
	srv := newAPI(t, http.StatusOK, cleanBody)
	if err := Validate(base, newSBOM(), srv.URL, "test-key"); err != nil {
		t.Fatal(err)
	}

	ctx, out := scancache.Observe(scancache.WithBypass(base))
	if err := Validate(ctx, newSBOM(), srv.URL, "test-key"); err != nil {
		t.Fatal(err)
	}
	if got := srv.posts.Load(); got != 2 {
		t.Errorf("--no-cache did not reach the API (%d posts)", got)
	}
	if out.Hit {
		t.Error("a bypassed scan reported a hit")
	}

	ctx, out = scancache.Observe(base)
	if err := Validate(ctx, newSBOM(), srv.URL, "test-key"); err != nil {
		t.Fatal(err)
	}
	if got := srv.posts.Load(); got != 2 || !out.Hit {
		t.Errorf("the bypassed run did not refresh the entry (%d posts, hit=%v)", got, out.Hit)
	}
}

func TestPost_MonitorIDIsDeduplicatedAndNeverWritten(t *testing.T) {
	ctx, dir := cacheEnv(t)
	srv := newAPI(t, http.StatusAccepted, accepted)
	for i := 0; i < 2; i++ {
		if err := Post(ctx, newSBOM(), srv.URL, "", monitorID); err != nil {
			t.Fatal(err)
		}
	}
	if got := srv.posts.Load(); got != 1 {
		t.Errorf("a monitor post was not deduplicated (%d posts)", got)
	}
	files := cacheFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("want one posted entry, got %v", files)
	}
	data, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(files[0], monitorID[5:]) || strings.Contains(string(data), monitorID[5:]) {
		t.Error("the monitor id reached the cache directory")
	}
}

// A different monitor id is a different account: no sharing.
func TestPost_DifferentMonitorIsADifferentEntry(t *testing.T) {
	ctx, _ := cacheEnv(t)
	srv := newAPI(t, http.StatusAccepted, accepted)
	other := "ospi_" + strings.Repeat("f", 64)
	if err := Post(ctx, newSBOM(), srv.URL, "", monitorID); err != nil {
		t.Fatal(err)
	}
	if err := Post(ctx, newSBOM(), srv.URL, "", other); err != nil {
		t.Fatal(err)
	}
	if got := srv.posts.Load(); got != 2 {
		t.Errorf("two monitors shared an entry (%d posts)", got)
	}
}
