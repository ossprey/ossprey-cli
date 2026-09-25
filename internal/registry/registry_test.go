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
		if _, err := ResolveLatest(context.Background(), "maven", "commons-io"); err == nil {
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

func TestResolveLatestCargo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// crates.io 403s a generic client, so the request must identify itself.
		if ua := r.Header.Get("User-Agent"); ua == "" || strings.HasPrefix(ua, "Go-http-client") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"1.0.200","newest_version":"1.1.0-beta.1"}}`))
	}))
	defer srv.Close()
	old := cratesBaseURL
	cratesBaseURL = srv.URL + "/"
	defer func() { cratesBaseURL = old }()

	v, err := ResolveLatest(context.Background(), "cargo", "serde")
	if err != nil {
		t.Fatalf("ResolveLatest: %v", err)
	}
	// Stable wins over the newer pre-release, matching npm dist-tags.latest.
	if v != "1.0.200" {
		t.Errorf("version: got %q, want 1.0.200", v)
	}
}

func TestResolveLatestCargoPrereleaseOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"","newest_version":"0.1.0-alpha.3"}}`))
	}))
	defer srv.Close()
	old := cratesBaseURL
	cratesBaseURL = srv.URL + "/"
	defer func() { cratesBaseURL = old }()

	v, err := ResolveLatest(context.Background(), "cargo", "fresh-crate")
	if err != nil {
		t.Fatalf("ResolveLatest: %v", err)
	}
	if v != "0.1.0-alpha.3" {
		t.Errorf("version: got %q, want the pre-release fallback", v)
	}
}

func TestResolveNpmSpec(t *testing.T) {
	var accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		io.WriteString(w, `{
			"dist-tags": {"latest": "2.1.0", "next": "3.0.0-rc.1", "legacy": "1.2.0"},
			"versions": {
				"1.0.0": {}, "1.2.0": {}, "1.3.0": {}, "1.4.0": {"deprecated": "broken"},
				"1.5.0-beta.1": {}, "2.0.0": {}, "2.1.0": {}, "2.2.0": {}, "3.0.0-rc.1": {}
			}
		}`)
	}))
	defer srv.Close()
	old := npmBaseURL
	npmBaseURL = srv.URL + "/"
	defer func() { npmBaseURL = old }()

	cases := map[string]string{
		"next":   "3.0.0-rc.1", // a dist-tag runs what it points at, not latest
		"legacy": "1.2.0",
		"^1":     "1.3.0", // an older major line, skipping the deprecated 1.4.0 and the prerelease
		"1.x":    "1.3.0",
		"^2":     "2.1.0", // latest satisfies the range, so npm picks it over 2.2.0
		"~1.4.0": "1.4.0", // deprecated is still better than nothing
		"*":      "2.1.0",
	}
	for spec, want := range cases {
		got, err := ResolveNpmSpec(context.Background(), "pkg", spec)
		if err != nil || got != want {
			t.Errorf("ResolveNpmSpec(%q) = %q, %v; want %q", spec, got, err, want)
		}
	}
	if !strings.Contains(accept, "application/vnd.npm.install-v1+json") {
		t.Errorf("Accept = %q, want the abbreviated packument", accept)
	}
	for _, spec := range []string{"^9", "nosuchtag"} {
		if _, err := ResolveNpmSpec(context.Background(), "pkg", spec); !errors.Is(err, ErrNoMatch) {
			t.Errorf("ResolveNpmSpec(%q) err = %v, want ErrNoMatch", spec, err)
		}
	}
}
