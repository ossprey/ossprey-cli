package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestInitCmd_Flags(t *testing.T) {
	cmd := newInitCmd()
	for _, name := range []string{"url", "key-name", "key-expiry", "no-workflow", "no-scan", "auth0-domain"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
	if cmd.Use != "init [path]" {
		t.Errorf("Use: got %q", cmd.Use)
	}
}
