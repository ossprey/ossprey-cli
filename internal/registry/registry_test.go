package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func npmPackument(t *testing.T, doc string) *string {
	t.Helper()
	var accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		io.WriteString(w, doc)
	}))
	t.Cleanup(srv.Close)
	old := npmBaseURL
	npmBaseURL = srv.URL + "/"
	t.Cleanup(func() { npmBaseURL = old })
	return &accept
}

func TestResolveNpmSpec(t *testing.T) {
	accept := npmPackument(t, `{
		"dist-tags": {"latest": "2.1.0", "next": "3.0.0-rc.1", "legacy": "1.2.0", "stable": "1.3.0"},
		"versions": {
			"1.0.0": {}, "1.2.0": {}, "1.3.0": {}, "1.4.0": {"deprecated": "broken"},
			"1.5.0-beta.1": {}, "2.0.0": {}, "2.1.0": {}, "2.2.0": {}, "3.0.0-rc.1": {}
		}
	}`)
	cases := []struct {
		spec, tag, want string
	}{
		{"next", "", "3.0.0-rc.1"}, // a dist-tag runs what it points at, not latest
		{"legacy", "", "1.2.0"},
		{"^1", "", "1.3.0"}, // an older major line, skipping the deprecated 1.4.0 and the prerelease
		{"1.x", "", "1.3.0"},
		{"^2", "", "2.1.0"},     // latest satisfies the range, so npm picks it over 2.2.0
		{"~1.4.0", "", "1.4.0"}, // deprecated is still better than nothing
		{"*", "", "2.1.0"},
		{"", "", "2.1.0"},
		// --tag moves the default an unpinned name or a range prefers.
		{"", "stable", "1.3.0"},
		{"^1", "legacy", "1.2.0"},
		{"^2", "legacy", "2.2.0"}, // the default tag is outside the range
	}
	for _, c := range cases {
		got, err := ResolveNpmSpec(context.Background(), "pkg", c.spec, NpmPick{DefaultTag: c.tag})
		if err != nil || got != c.want {
			t.Errorf("ResolveNpmSpec(%q, tag %q) = %q, %v; want %q", c.spec, c.tag, got, err, c.want)
		}
	}
	if !strings.Contains(*accept, "application/vnd.npm.install-v1+json") {
		t.Errorf("Accept = %q, want the abbreviated packument", *accept)
	}
	for _, spec := range []string{"^9", "nosuchtag"} {
		if _, err := ResolveNpmSpec(context.Background(), "pkg", spec, NpmPick{}); !errors.Is(err, ErrNoMatch) {
			t.Errorf("ResolveNpmSpec(%q) err = %v, want ErrNoMatch", spec, err)
		}
	}
}

// npm-pick-manifest only prefers the default tag when it is not deprecated: a
// deprecated latest must not be what gets checked while npm runs 2.2.0.
func TestResolveNpmSpecSkipsADeprecatedDefaultTag(t *testing.T) {
	npmPackument(t, `{
		"dist-tags": {"latest": "2.1.0", "canary": "2.2.0"},
		"versions": {"2.0.0": {}, "2.1.0": {"deprecated": "do not use"}, "2.2.0": {}}
	}`)
	for _, spec := range []string{"^2", ""} {
		got, err := ResolveNpmSpec(context.Background(), "pkg", spec, NpmPick{})
		if err != nil || got != "2.2.0" {
			t.Errorf("ResolveNpmSpec(%q) = %q, %v; want 2.2.0", spec, got, err)
		}
	}
}

// An unpinned name under --tag runs the tag's version even when it is a
// prerelease, because npm tests the implicit range `*` by string. Pinned
// against real npx: `npx --tag beta -p typescript tsc` ran 6.0.0-beta, with
// latest at 7.0.2.
func TestResolveNpmSpecPrereleaseDefaultTag(t *testing.T) {
	npmPackument(t, `{
		"dist-tags": {"latest": "7.0.2", "beta": "6.0.0-beta"},
		"versions": {"6.0.0-beta": {}, "6.0.0": {}, "7.0.2": {}}
	}`)
	cases := []struct{ spec, want string }{
		{"", "6.0.0-beta"},
		{"*", "6.0.0-beta"},
		{"^6", "6.0.0"}, // a real range does not admit the prerelease
	}
	for _, c := range cases {
		got, err := ResolveNpmSpec(context.Background(), "typescript", c.spec, NpmPick{DefaultTag: "beta"})
		if err != nil || got != c.want {
			t.Errorf("ResolveNpmSpec(%q, tag beta) = %q, %v; want %q", c.spec, got, err, c.want)
		}
	}
}

// --before counts only releases published by then, and needs the full
// packument for their times.
func TestResolveNpmSpecBefore(t *testing.T) {
	accept := npmPackument(t, `{
		"dist-tags": {"latest": "2.1.0", "next": "3.0.0"},
		"versions": {"1.0.0": {}, "2.0.0": {}, "2.1.0": {}, "3.0.0": {}},
		"time": {
			"1.0.0": "2023-01-01T00:00:00.000Z", "2.0.0": "2024-01-01T00:00:00.000Z",
			"2.1.0": "2025-01-01T00:00:00.000Z", "3.0.0": "2025-06-01T00:00:00.000Z"
		}
	}`)
	before := NpmPick{Before: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)}
	cases := map[string]string{
		"":     "2.0.0", // latest is too new
		"^2":   "2.0.0",
		"next": "2.0.0", // a tag that is too new falls back to <= its version
	}
	for spec, want := range cases {
		got, err := ResolveNpmSpec(context.Background(), "pkg", spec, before)
		if err != nil || got != want {
			t.Errorf("ResolveNpmSpec(%q, before) = %q, %v; want %q", spec, got, err, want)
		}
	}
	if *accept != "application/json" {
		t.Errorf("Accept = %q, want the full packument", *accept)
	}
	early := NpmPick{Before: time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := ResolveNpmSpec(context.Background(), "pkg", "", early); !errors.Is(err, ErrNoMatch) {
		t.Errorf("nothing published by then: err = %v, want ErrNoMatch", err)
	}
}
