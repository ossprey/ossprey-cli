package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ossprey/ossprey-cli/internal/auth"
	"github.com/ossprey/ossprey-cli/internal/client"
)

func TestCreateCIKey_RetriesOnNameCollision(t *testing.T) {
	var names []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		names = append(names, body["name"])
		if len(names) == 1 {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"message": "API key name already exists for this user"})
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"id": "k1", "api_key": "ospy_x", "name": body["name"], "expiry": body["expiry"],
		})
	}))
	defer ts.Close()

	key := createCIKey(context.Background(), ts.URL, "jwt", "", time.Hour)
	if key == nil {
		t.Fatal("want a key after retry, got nil")
	}
	if len(names) != 2 {
		t.Fatalf("want 2 attempts, got %d (%v)", len(names), names)
	}
	if names[0] == names[1] {
		t.Errorf("retry reused the colliding name %q", names[0])
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "ci-") {
			t.Errorf("generated name %q missing ci- prefix", n)
		}
	}
}

func TestCreateCIKey_ExplicitNameNotRetried(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"message": "API key name already exists for this user"})
	}))
	defer ts.Close()

	if key := createCIKey(context.Background(), ts.URL, "jwt", "my-key", time.Hour); key != nil {
		t.Fatalf("want nil key on conflict, got %+v", key)
	}
	if calls != 1 {
		t.Errorf("want 1 attempt for an explicit name, got %d", calls)
	}
}

func TestCreateCIKey_ServerErrorIsNonFatal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "boom"})
	}))
	defer ts.Close()

	// Returns nil rather than panicking or aborting: init continues to the
	// workflow file and first scan without a key.
	if key := createCIKey(context.Background(), ts.URL, "jwt", "", time.Hour); key != nil {
		t.Fatalf("want nil key on 500, got %+v", key)
	}
}

func TestCreateCIKey_SendsExpiryAndBearer(t *testing.T) {
	var gotAuth, gotExpiry string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		gotExpiry = body["expiry"]
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"id": "k", "api_key": "ospy_x", "name": body["name"]})
	}))
	defer ts.Close()

	before := time.Now().Add(48 * time.Hour)
	if key := createCIKey(context.Background(), ts.URL, "jwt-token", "", 48*time.Hour); key == nil {
		t.Fatal("want a key, got nil")
	}
	if gotAuth != "Bearer jwt-token" {
		t.Errorf("auth: got %q", gotAuth)
	}
	expiry, err := time.Parse(time.RFC3339, gotExpiry)
	if err != nil {
		t.Fatalf("expiry %q is not RFC3339: %v", gotExpiry, err)
	}
	if expiry.Before(before.Add(-time.Minute)) || expiry.After(before.Add(time.Minute)) {
		t.Errorf("expiry %s not ~48h from now", expiry)
	}
}

// A login stored against one tenant must not be reused when the flags name a
// different one — otherwise `init --audience <qa>` from a prod-logged-in machine
// silently sends a prod token to the QA API while reporting success.
func TestMatchesTenant(t *testing.T) {
	cases := []struct {
		name   string
		stored auth.Credentials
		cfg    auth.Config
		want   bool
	}{
		{
			name:   "same tenant",
			stored: auth.Credentials{Domain: "auth.ossprey.com", Audience: "https://api.ossprey.com"},
			cfg:    auth.Config{Domain: "auth.ossprey.com", Audience: "https://api.ossprey.com"},
			want:   true,
		},
		{
			name:   "different domain",
			stored: auth.Credentials{Domain: "auth.ossprey.com", Audience: "https://api.ossprey.com"},
			cfg:    auth.Config{Domain: "auth.qa.ossprey.com", Audience: "https://api.ossprey.com"},
			want:   false,
		},
		{
			name:   "different audience",
			stored: auth.Credentials{Domain: "auth.ossprey.com", Audience: "https://api.ossprey.com"},
			cfg:    auth.Config{Domain: "auth.ossprey.com", Audience: "https://api.qa.ossprey.com"},
			want:   false,
		},
		{
			// --client-id names a different Auth0 application; reusing a token
			// minted for another app is the same silent-ignore bug as domain.
			name: "different client id",
			stored: auth.Credentials{
				Domain: "auth.ossprey.com", ClientID: "app-a", Audience: "https://api.ossprey.com",
			},
			cfg: auth.Config{
				Domain: "auth.ossprey.com", ClientID: "app-b", Audience: "https://api.ossprey.com",
			},
			want: false,
		},
		{
			name: "all three match",
			stored: auth.Credentials{
				Domain: "auth.ossprey.com", ClientID: "app-a", Audience: "https://api.ossprey.com",
			},
			cfg: auth.Config{
				Domain: "auth.ossprey.com", ClientID: "app-a", Audience: "https://api.ossprey.com",
			},
			want: true,
		},
		{
			name:   "stored fields empty (older CLI) still reused",
			stored: auth.Credentials{},
			cfg:    auth.Config{Domain: "auth.ossprey.com", Audience: "https://api.ossprey.com"},
			want:   true,
		},
		{
			// Only the stored client id is known: nothing to contradict, reuse.
			name:   "stored client id but cfg empty",
			stored: auth.Credentials{ClientID: "app-a"},
			cfg:    auth.Config{Domain: "auth.ossprey.com"},
			want:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesTenant(&tc.stored, tc.cfg); got != tc.want {
				t.Errorf("matchesTenant: got %v, want %v", got, tc.want)
			}
		})
	}
}

// An over-limit --key-expiry should be rejected locally with a clear message,
// not surface as the generic "could not create an API key" warning after a
// pointless round trip.
func TestInitCmd_RejectsBadKeyExpiry(t *testing.T) {
	cases := []struct {
		expiry string
		want   string
	}{
		{"20000h", "cannot exceed 2 years"},
		{"0s", "must be positive"},
		{"-1h", "must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.expiry, func(t *testing.T) {
			cmd := newInitCmd()
			cmd.SetArgs([]string{".", "--key-expiry", tc.expiry})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("--key-expiry %s: want an error, got nil", tc.expiry)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// --no-key means the expiry is never used, so it must not be validated. The run
// still fails (it needs a login, and 127.0.0.1:9 is closed) — but it must fail
// on the login, not on the expiry, which proves validation was skipped.
func TestInitCmd_KeyExpiryUncheckedWithNoKey(t *testing.T) {
	t.Setenv("OSSPREY_CONFIG_DIR", t.TempDir()) // no stored login

	cmd := newInitCmd()
	cmd.SetArgs([]string{".",
		"--key-expiry", "20000h", // way over the 2-year cap
		"--no-key", "--no-scan",
		"--auth0-domain", "127.0.0.1:9",
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected a login failure, got success")
	}
	if strings.Contains(err.Error(), "key-expiry") {
		t.Errorf("--no-key should skip expiry validation, but got: %v", err)
	}
	if !strings.Contains(err.Error(), "device code") {
		t.Errorf("expected a device-code failure, got: %v", err)
	}
}

func TestInitCmd_Flags(t *testing.T) {
	cmd := newInitCmd()
	for _, name := range []string{"url", "key-name", "key-expiry", "no-key", "no-scan", "auth0-domain", "client-id", "audience"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
	// The workflow-file step was dropped: init is CI-agnostic now, so this flag
	// must not quietly come back.
	if cmd.Flags().Lookup("no-workflow") != nil {
		t.Error("--no-workflow should no longer exist")
	}
	if cmd.Use != "init [path]" {
		t.Errorf("Use: got %q", cmd.Use)
	}
}

func TestGenerateKeyName(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		name := generateKeyName()
		if len(name) > 20 {
			t.Errorf("name %q longer than the API's 20-char limit", name)
		}
		if strings.ContainsAny(name, " \t\n") {
			t.Errorf("name %q contains whitespace, which the API rejects", name)
		}
		if !strings.HasPrefix(name, "ci-") {
			t.Errorf("name %q missing ci- prefix", name)
		}
		if seen[name] {
			t.Errorf("duplicate name %q", name)
		}
		seen[name] = true
	}
}

func TestKeyValue(t *testing.T) {
	// "" is the signal submit.Validate reads as "use the stored login".
	if got := keyValue(nil); got != "" {
		t.Errorf("keyValue(nil): got %q, want empty", got)
	}
	if got := keyValue(&client.APIKey{Key: "ospy_x"}); got != "ospy_x" {
		t.Errorf("keyValue: got %q", got)
	}
}
