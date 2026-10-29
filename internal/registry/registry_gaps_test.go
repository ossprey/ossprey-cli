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

// pointAt swaps every registry base URL for srv and restores them afterwards.
func pointAt(t *testing.T, srv *httptest.Server) {
	t.Helper()
	oldNpm, oldPyPI, oldCrates := npmBaseURL, pypiBaseURL, cratesBaseURL
	npmBaseURL, pypiBaseURL, cratesBaseURL = srv.URL+"/", srv.URL+"/", srv.URL+"/"
	t.Cleanup(func() { npmBaseURL, pypiBaseURL, cratesBaseURL = oldNpm, oldPyPI, oldCrates })
}

// npm addresses a scoped packument as "@scope%2Fname"; an unescaped slash asks
// for a different document.
func TestResolveNpm_EscapesTheScopeSlash(t *testing.T) {
	var uri string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri = r.RequestURI
		io.WriteString(w, `{"dist-tags":{"latest":"7.24.0"}}`)
	}))
	defer srv.Close()
	pointAt(t, srv)

	v, err := ResolveLatest(context.Background(), "npm", "@babel/core")
	if err != nil {
		t.Fatalf("ResolveLatest: %v", err)
	}
	if v != "7.24.0" {
		t.Errorf("version: got %q", v)
	}
	if uri != "/@babel%2Fcore" {
		t.Errorf("request URI: got %q, want /@babel%%2Fcore", uri)
	}
}

// A name comes from the command line, so it must not be able to steer the
// request to another path or add a query.
func TestResolveLatest_NameCannotRetargetTheRequest(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "cargo"} {
		for _, name := range []string{"../../admin", "x?token=1", "x#frag", "a/b/c", "%2e%2e"} {
			var path, query string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path, query = r.URL.Path, r.URL.RawQuery
				w.WriteHeader(http.StatusNotFound)
			}))
			pointAt(t, srv)

			_, _ = ResolveLatest(context.Background(), eco, name)
			srv.Close()

			if query != "" {
				t.Errorf("%s %q: request carried query %q", eco, name, query)
			}
			// The decoded path must keep the whole name inside one segment
			// (plus pypi's trailing /json).
			trimmed := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/json")
			if trimmed != name {
				t.Errorf("%s %q: request path %q does not hold the name verbatim", eco, name, path)
			}
		}
	}
}

// dist-tags.latest is what `npm install x` installs, not the newest publish.
func TestResolveNpm_UsesLatestNotNext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"dist-tags":{"next":"5.0.0-rc.1","latest":"4.17.21","beta":"5.0.0-beta.3"},"versions":{"5.0.0-rc.1":{}}}`)
	}))
	defer srv.Close()
	pointAt(t, srv)

	v, err := ResolveLatest(context.Background(), "npm", "lodash")
	if err != nil {
		t.Fatalf("ResolveLatest: %v", err)
	}
	if v != "4.17.21" {
		t.Errorf("version: got %q, want the latest tag", v)
	}
}

// Only a 404 means "not on the public registry"; every other failure is an
// outage and must not be counted with the private packages.
func TestResolveLatest_ErrorGrading(t *testing.T) {
	tests := []struct {
		name     string
		eco      string
		handler  http.HandlerFunc
		notFound bool
	}{
		{"pypi 404", "pypi", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }, true},
		{"cargo 404", "cargo", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }, true},
		{"npm 403", "npm", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }, false},
		{"pypi 503", "pypi", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }, false},
		{"npm 410", "npm", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGone) }, false},
		{"npm malformed body", "npm", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `<html>`) }, false},
		{"pypi no version", "pypi", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"info":{}}`) }, false},
		{"cargo no version", "cargo", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"crate":{}}`) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			pointAt(t, srv)

			_, err := ResolveLatest(context.Background(), tt.eco, "pkg")
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := errors.Is(err, ErrNotFound); got != tt.notFound {
				t.Errorf("errors.Is(err, ErrNotFound) = %v, want %v (err %v)", got, tt.notFound, err)
			}
		})
	}
}

func TestResolveLatest_NetworkErrorIsNotNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	pointAt(t, srv)
	srv.Close() // nothing listens any more

	_, err := ResolveLatest(context.Background(), "npm", "lodash")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Errorf("a refused connection read as not-found: %v", err)
	}
}

// The two causes never share a warning class, and neither do the two
// consequences (scan path vs forward path).
func TestUnresolvedEntry_Classes(t *testing.T) {
	missing := UnresolvedEntry("npm", "@acme/x", ErrNotFound, "left unversioned")
	down := UnresolvedEntry("npm", "lodash", errors.New("registry returned status 503"), "left unversioned")
	missingFwd := UnresolvedEntry("npm", "@acme/x", ErrNotFound, "skipping its check")

	if missing.Class == down.Class {
		t.Errorf("404 and outage share class %q", missing.Class)
	}
	if missing.Class == missingFwd.Class {
		t.Errorf("scan and forward outcomes share class %q", missing.Class)
	}
	if !strings.Contains(missing.One, "not on the public registry") || !strings.Contains(down.One, "unreachable") {
		t.Errorf("headlines: missing=%q down=%q", missing.One, down.One)
	}
	if !strings.Contains(missingFwd.Many, "skipping its check") {
		t.Errorf("forward headline does not name the consequence: %q", missingFwd.Many)
	}
	if !strings.Contains(missing.Item, "npm/@acme/x") || !strings.Contains(down.Item, "503") {
		t.Errorf("items: missing=%q down=%q", missing.Item, down.Item)
	}
	// A wrapped 404 is still a 404.
	wrapped := UnresolvedEntry("pypi", "x", errors.Join(errors.New("ctx"), ErrNotFound), "left unversioned")
	if wrapped.Class != missing.Class {
		t.Errorf("wrapped ErrNotFound graded as %q, want %q", wrapped.Class, missing.Class)
	}
}
