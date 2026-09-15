package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveLatest_NPM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/lodash") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		io.WriteString(w, `{"dist-tags":{"latest":"4.17.21"}}`)
	}))
	defer srv.Close()

	old := npmBaseURL
	npmBaseURL = srv.URL + "/"
	defer func() { npmBaseURL = old }()

	v, err := ResolveLatest(context.Background(), "npm", "lodash")
	if err != nil {
		t.Fatalf("ResolveLatest: %v", err)
	}
	if v != "4.17.21" {
		t.Errorf("version: got %q, want 4.17.21", v)
	}
}

func TestResolveLatest_PyPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/requests/json") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		io.WriteString(w, `{"info":{"version":"2.31.0"}}`)
	}))
	defer srv.Close()

	old := pypiBaseURL
	pypiBaseURL = srv.URL + "/"
	defer func() { pypiBaseURL = old }()

	v, err := ResolveLatest(context.Background(), "pypi", "requests")
	if err != nil {
		t.Fatalf("ResolveLatest: %v", err)
	}
	if v != "2.31.0" {
		t.Errorf("version: got %q, want 2.31.0", v)
	}
}

func TestResolveLatest_Errors(t *testing.T) {
	t.Run("unsupported ecosystem", func(t *testing.T) {
		if _, err := ResolveLatest(context.Background(), "cargo", "serde"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		old := npmBaseURL
		npmBaseURL = srv.URL + "/"
		defer func() { npmBaseURL = old }()

		if _, err := ResolveLatest(context.Background(), "npm", "nope"); err == nil {
			t.Fatal("expected error on 404")
		}
	})

	t.Run("empty latest", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"dist-tags":{}}`)
		}))
		defer srv.Close()
		old := npmBaseURL
		npmBaseURL = srv.URL + "/"
		defer func() { npmBaseURL = old }()

		if _, err := ResolveLatest(context.Background(), "npm", "weird"); err == nil {
			t.Fatal("expected error when latest is empty")
		}
	})
}

// A 404 means the package is not on the public registry — the normal answer for
// a private or internal package. Callers grade that differently from an outage,
// so it must be distinguishable without string-matching the message.
func TestResolveLatestNotFoundIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	npmBaseURL = srv.URL + "/"

	_, err := ResolveLatest(context.Background(), "npm", "@wayflyer/flyui")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ResolveLatest() error = %v, want one matching ErrNotFound", err)
	}
}

// An outage must NOT look like a missing package.
func TestResolveLatestServerErrorIsNotNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	npmBaseURL = srv.URL + "/"

	_, err := ResolveLatest(context.Background(), "npm", "lodash")
	if err == nil {
		t.Fatal("expected an error on 500")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("ResolveLatest() error = %v, want it NOT to match ErrNotFound", err)
	}
}
