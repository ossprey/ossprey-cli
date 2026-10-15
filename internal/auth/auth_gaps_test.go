package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A token inside the leeway is already treated as expired, so it never dies
// mid-scan.
func TestValid_HonoursExpiryLeeway(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name  string
		creds *Credentials
		want  bool
	}{
		{"nil", nil, false},
		{"no access token", &Credentials{ExpiresAt: now.Add(time.Hour)}, false},
		{"already expired", &Credentials{AccessToken: "a", ExpiresAt: now.Add(-time.Minute)}, false},
		{"inside the leeway", &Credentials{AccessToken: "a", ExpiresAt: now.Add(expiryLeeway / 2)}, false},
		{"zero expiry", &Credentials{AccessToken: "a"}, false},
		{"past the leeway", &Credentials{AccessToken: "a", ExpiresAt: now.Add(expiryLeeway + time.Minute)}, true},
	}
	for _, tt := range tests {
		if got := tt.creds.Valid(); got != tt.want {
			t.Errorf("%s: Valid() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// Refresh hits the tenant the user logged in against, whatever the env now says.
func TestAccessToken_RefreshUsesTheStoredTenant(t *testing.T) {
	var mu sync.Mutex
	var host, clientID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		mu.Lock()
		clientID = form.Get("client_id")
		mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at-new", "expires_in": 3600})
	}))
	defer srv.Close()

	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	t.Setenv("OSSPREY_AUTH0_DOMAIN", "auth.elsewhere.test")
	t.Setenv("OSSPREY_AUTH0_CLIENT_ID", "env-cid")
	if err := Save(&Credentials{
		Domain: "auth.stored.test", ClientID: "stored-cid",
		AccessToken: "at-old", RefreshToken: "rt", ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	target, _ := url.Parse(srv.URL)
	hc := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		host = req.URL.Host
		mu.Unlock()
		req.URL.Scheme, req.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(req)
	})}

	if _, err := AccessToken(context.Background(), hc); err != nil {
		t.Fatalf("AccessToken: %v", err)
	}
	if host != "auth.stored.test" {
		t.Errorf("refresh host: got %q, want the stored domain", host)
	}
	if clientID != "stored-cid" {
		t.Errorf("refresh client_id: got %q, want stored-cid", clientID)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A refused refresh tells the user to log in again and leaves the stored file
// alone, so a transient refusal cannot wipe the refresh token.
func TestAccessToken_FailedRefreshKeepsTheStoredLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "invalid_grant", "error_description": "Unknown or invalid refresh token."})
	}))
	defer srv.Close()

	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir())
	stored := &Credentials{
		Domain: "auth.test", ClientID: "cid",
		AccessToken: "at-old", RefreshToken: "rt-keep", ExpiresAt: time.Now().Add(-time.Hour),
	}
	if err := Save(stored); err != nil {
		t.Fatal(err)
	}

	_, err := AccessToken(context.Background(), newRewriteClient(srv))
	if err == nil || !strings.Contains(err.Error(), "ossprey login") || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("err: got %v, want a re-login hint naming invalid_grant", err)
	}
	if errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("a failed refresh must not read as not logged in: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.RefreshToken != "rt-keep" || got.AccessToken != "at-old" {
		t.Errorf("stored login changed after a failed refresh: %+v", got)
	}
}

func TestRefresh_RotatedTokensReplaceTheOldOnes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at", "refresh_token": "rt-new", "id_token": "id-new", "expires_in": 60})
	}))
	defer srv.Close()

	next, err := testConfig(srv).Refresh(context.Background(), srv.Client(), &Credentials{RefreshToken: "rt-old", IDToken: "id-old"})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if next.RefreshToken != "rt-new" || next.IDToken != "id-new" {
		t.Errorf("rotated tokens not taken: %+v", next)
	}
}

func TestRefresh_SuccessStatusWithoutTokenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{})
	}))
	defer srv.Close()

	if _, err := testConfig(srv).Refresh(context.Background(), srv.Client(), &Credentials{RefreshToken: "rt"}); err == nil {
		t.Fatal("a 200 with no access token must not count as a refresh")
	}
}

func TestPollToken_Errors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   map[string]any
		want   string
	}{
		{"unknown oauth error is named", http.StatusBadRequest, map[string]any{"error": "invalid_client", "error_description": "bad client"}, "login failed: invalid_client: bad client"},
		{"200 without a token", http.StatusOK, map[string]any{}, "token poll failed (status 200)"},
		{"non-200 without an error code", http.StatusInternalServerError, map[string]any{}, "token poll failed (status 500)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, tt.status, tt.body)
			}))
			defer srv.Close()

			_, err := testConfig(srv).PollToken(context.Background(), srv.Client(), &DeviceCode{DeviceCode: "d", ExpiresIn: 900})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err: got %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestPollToken_HonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "authorization_pending"})
	}))
	defer srv.Close()

	_, err := testConfig(srv).PollToken(ctx, srv.Client(), &DeviceCode{DeviceCode: "d", ExpiresIn: 900})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err: got %v, want context.Canceled", err)
	}
}

func TestRequestDeviceCode_Errors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"non-200", http.StatusUnauthorized, `{"error":"unauthorized_client"}`, "status 401"},
		{"missing codes", http.StatusOK, `{"verification_uri":"https://x"}`, "missing codes"},
		{"malformed", http.StatusOK, `<html>`, "decode device code"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			_, err := testConfig(srv).RequestDeviceCode(context.Background(), srv.Client())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err: got %v, want substring %q", err, tt.want)
			}
		})
	}
}

// A corrupt credentials file is an error to report, not "not logged in": the
// latter would send the user to log in again without saying what broke.
func TestLoad_DistinguishesCorruptFromMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OSSPREY_CONFIG_DIR", dir)
	path := filepath.Join(dir, "credentials.json")

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil || errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("corrupt file: got %v, want a parse error", err)
	}

	if err := os.WriteFile(path, []byte(`{"refresh_token":"rt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); !errors.Is(err, ErrNotLoggedIn) {
		t.Errorf("file without an access token: got %v, want ErrNotLoggedIn", err)
	}
}

func TestIdentity(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"email wins", fakeIDToken(t, map[string]any{"email": "a@b.c", "sub": "auth0|1"}), "a@b.c"},
		{"falls back to sub", fakeIDToken(t, map[string]any{"sub": "auth0|1"}), "auth0|1"},
		{"empty", "", ""},
		{"two parts", "a.b", ""},
		{"bad base64", "a.!!!.c", ""},
		{"payload not json", "a." + "bm90IGpzb24" + ".c", ""},
	}
	for _, tt := range tests {
		if got := (&Credentials{IDToken: tt.token}).Identity(); got != tt.want {
			t.Errorf("%s: Identity() = %q, want %q", tt.name, got, tt.want)
		}
	}
}
