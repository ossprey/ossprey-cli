package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateAPIKey(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"id":      "key-123",
			"api_key": "ospy_secret",
			"name":    gotBody["name"],
			"created": "2026-01-01T00:00:00Z",
			"expiry":  gotBody["expiry"],
		})
	}))
	defer ts.Close()

	c, err := NewBearer(ts.URL, "jwt-token")
	if err != nil {
		t.Fatal(err)
	}

	expiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	key, err := c.CreateAPIKey(context.Background(), "ci-abc123", expiry)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	if gotPath != "/dashboard/v1/api-keys" {
		t.Errorf("path: got %q", gotPath)
	}
	if gotAuth != "Bearer jwt-token" {
		t.Errorf("auth header: got %q", gotAuth)
	}
	if gotBody["name"] != "ci-abc123" {
		t.Errorf("name: got %q", gotBody["name"])
	}
	if gotBody["expiry"] != "2027-01-01T00:00:00Z" {
		t.Errorf("expiry: got %q", gotBody["expiry"])
	}
	if key.Key != "ospy_secret" || key.ID != "key-123" {
		t.Errorf("key: got %+v", key)
	}
}

func TestCreateAPIKey_ErrorEnvelope(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "FAILED",
			"error":   "API key name already exists for this user",
			"message": "API key name already exists for this user",
		})
	}))
	defer ts.Close()

	c, err := NewBearer(ts.URL, "jwt-token")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.CreateAPIKey(context.Background(), "dup", time.Now().Add(time.Hour))
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %v", err)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Errorf("status: got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "API key name already exists for this user" {
		t.Errorf("message: got %q", apiErr.Message)
	}
}

func TestCreateAPIKey_RequiresBearer(t *testing.T) {
	c, err := New("http://unused", "ospy_key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateAPIKey(context.Background(), "x", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("want error for API-key client, got nil")
	}
}
