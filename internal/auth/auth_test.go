package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testConfig points a Config at the given httptest server with fast polling.
func testConfig(srv *httptest.Server) Config {
	return Config{
		Domain:       "auth.test",
		ClientID:     "cid",
		Audience:     "https://api.test",
		BaseURL:      srv.URL,
		PollInterval: time.Millisecond,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fakeIDToken builds an unsigned JWT-shaped token with the given claims.
func fakeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(payload) + ".sig"
}

func TestDeviceFlow_HappyPath(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		switch r.URL.Path {
		case "/oauth/device/code":
			if form.Get("client_id") != "cid" {
				t.Errorf("device code client_id: got %q", form.Get("client_id"))
			}
			if form.Get("audience") != "https://api.test" {
				t.Errorf("device code audience: got %q", form.Get("audience"))
			}
			if !strings.Contains(form.Get("scope"), "offline_access") {
				t.Errorf("scope missing offline_access: %q", form.Get("scope"))
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"device_code": "dev-1", "user_code": "ABCD-EFGH",
				"verification_uri":          "https://auth.test/activate",
				"verification_uri_complete": "https://auth.test/activate?user_code=ABCD-EFGH",
				"expires_in":                900, "interval": 5,
			})
		case "/oauth/token":
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
				t.Errorf("grant_type: got %q", form.Get("grant_type"))
			}
			if form.Get("device_code") != "dev-1" {
				t.Errorf("device_code: got %q", form.Get("device_code"))
			}
			if polls.Add(1) < 3 {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "authorization_pending"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "at-1", "refresh_token": "rt-1",
				"id_token":   fakeIDToken(t, map[string]any{"email": "dev@ossprey.com", "sub": "auth0|1"}),
				"expires_in": 86400,
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := testConfig(srv)
	dc, err := cfg.RequestDeviceCode(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("RequestDeviceCode: %v", err)
	}
	if dc.UserCode != "ABCD-EFGH" {
		t.Errorf("UserCode: got %q", dc.UserCode)
	}

	creds, err := cfg.PollToken(context.Background(), srv.Client(), dc)
	if err != nil {
		t.Fatalf("PollToken: %v", err)
	}
	if creds.AccessToken != "at-1" || creds.RefreshToken != "rt-1" {
		t.Errorf("tokens: got %+v", creds)
	}
	if !creds.Valid() {
		t.Error("fresh credentials should be valid")
	}
	if got := creds.Identity(); got != "dev@ossprey.com" {
		t.Errorf("Identity: got %q, want dev@ossprey.com", got)
	}
	if creds.Domain != "auth.test" || creds.Audience != "https://api.test" {
		t.Errorf("tenant not stored on credentials: %+v", creds)
	}
	if got := polls.Load(); got < 3 {
		t.Errorf("expected >=3 polls, got %d", got)
	}
}

func TestPollToken_Denied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "access_denied"})
	}))
	defer srv.Close()

	cfg := testConfig(srv)
	_, err := cfg.PollToken(context.Background(), srv.Client(), &DeviceCode{DeviceCode: "d", ExpiresIn: 900})
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("expected declined error, got %v", err)
	}
}

func TestPollToken_Expired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "expired_token"})
	}))
	defer srv.Close()

	cfg := testConfig(srv)
	_, err := cfg.PollToken(context.Background(), srv.Client(), &DeviceCode{DeviceCode: "d", ExpiresIn: 900})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestPollToken_SlowDownThenSuccess(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) == 1 {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "slow_down"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at", "expires_in": 60})
	}))
	defer srv.Close()

	cfg := testConfig(srv)
	creds, err := cfg.PollToken(context.Background(), srv.Client(), &DeviceCode{DeviceCode: "d", ExpiresIn: 900})
	if err != nil {
		t.Fatalf("PollToken: %v", err)
	}
	if creds.AccessToken != "at" {
		t.Errorf("AccessToken: got %q", creds.AccessToken)
	}
}

func TestRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-old" {
			t.Errorf("unexpected form: %v", form)
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at-new", "expires_in": 86400})
	}))
	defer srv.Close()

	cfg := testConfig(srv)
	old := &Credentials{RefreshToken: "rt-old", IDToken: "id-old"}
	next, err := cfg.Refresh(context.Background(), srv.Client(), old)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if next.AccessToken != "at-new" {
		t.Errorf("AccessToken: got %q", next.AccessToken)
	}
	// Auth0 without rotation returns no new refresh/ID token; keep the old ones.
	if next.RefreshToken != "rt-old" || next.IDToken != "id-old" {
		t.Errorf("old tokens not carried over: %+v", next)
	}
}

func TestRefresh_NoRefreshToken(t *testing.T) {
	cfg := Config{Domain: "auth.test", ClientID: "cid"}
	_, err := cfg.Refresh(context.Background(), nil, &Credentials{})
	if err == nil || !strings.Contains(err.Error(), "ossprey login") {
		t.Fatalf("expected re-login hint, got %v", err)
	}
}

func TestStore_RoundTrip(t *testing.T) {
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())

	if _, err := Load(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("Load on empty store: got %v, want ErrNotLoggedIn", err)
	}

	creds := &Credentials{
		Domain: "auth.test", ClientID: "cid", Audience: "https://api.test",
		AccessToken: "at", RefreshToken: "rt",
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	if err := Save(creds); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if runtime.GOOS != "windows" {
		path, _ := Path()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat credentials: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("credentials file mode: got %o, want 600", perm)
		}
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.AccessToken != "at" || got.Domain != "auth.test" {
		t.Errorf("Load: got %+v", got)
	}

	if err := Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := Load(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("Load after Remove: got %v, want ErrNotLoggedIn", err)
	}
	// Removing again is not an error.
	if err := Remove(); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}

func TestAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "at-refreshed", "refresh_token": "rt-rotated", "expires_in": 86400,
		})
	}))
	defer srv.Close()

	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())

	if _, err := AccessToken(context.Background(), srv.Client()); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("AccessToken without login: got %v, want ErrNotLoggedIn", err)
	}

	// Fresh token: returned as-is, no network call needed.
	if err := Save(&Credentials{AccessToken: "at-fresh", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	tok, err := AccessToken(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("AccessToken (fresh): %v", err)
	}
	if tok != "at-fresh" {
		t.Errorf("token: got %q, want at-fresh", tok)
	}

	// Expired token: refreshed against the stored tenant and re-saved. The
	// injected client rewrites https://auth.test to the test server.
	if err := Save(&Credentials{
		Domain: "auth.test", ClientID: "cid",
		AccessToken: "at-stale", RefreshToken: "rt-old",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	tok, err = AccessToken(context.Background(), newRewriteClient(srv))
	if err != nil {
		t.Fatalf("AccessToken (refresh): %v", err)
	}
	if tok != "at-refreshed" {
		t.Errorf("token: got %q, want at-refreshed", tok)
	}

	// The refreshed (rotated) credentials were persisted.
	saved, err := Load()
	if err != nil {
		t.Fatalf("Load after refresh: %v", err)
	}
	if saved.AccessToken != "at-refreshed" || saved.RefreshToken != "rt-rotated" {
		t.Errorf("refreshed credentials not saved: %+v", saved)
	}
}

// newRewriteClient returns an *http.Client that redirects every request to the
// test server, so code that dials https://{stored-domain} lands there.
func newRewriteClient(srv *httptest.Server) *http.Client {
	target, _ := url.Parse(srv.URL)
	return &http.Client{Transport: rewriteTransport{target: target}}
}

type rewriteTransport struct{ target *url.URL }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("OSSPREY_AUTH0_DOMAIN", "")
	t.Setenv("OSSPREY_AUTH0_CLIENT_ID", "")
	t.Setenv("OSSPREY_AUTH0_AUDIENCE", "")
	cfg := ConfigFromEnv()
	if cfg.Domain != DefaultDomain || cfg.ClientID != DefaultClientID || cfg.Audience != DefaultAudience {
		t.Errorf("defaults: got %+v", cfg)
	}

	t.Setenv("OSSPREY_AUTH0_DOMAIN", "auth.qa.ossprey.com")
	t.Setenv("OSSPREY_AUTH0_AUDIENCE", "https://api.qa.ossprey.com")
	cfg = ConfigFromEnv()
	if cfg.Domain != "auth.qa.ossprey.com" || cfg.Audience != "https://api.qa.ossprey.com" {
		t.Errorf("env overrides: got %+v", cfg)
	}
}

func TestPath_UsesConfigDirEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "credentials.json") {
		t.Errorf("Path: got %q", path)
	}
}
