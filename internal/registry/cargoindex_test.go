package registry

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// serveIndex points the sparse index at a server holding one crate's lines at its cargo path.
func serveIndex(t *testing.T, path string, status int, lines ...string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path != "/"+path:
			http.NotFound(w, r)
			return
		case status != http.StatusOK:
			http.Error(w, "unavailable", status)
			return
		}
		io.WriteString(w, strings.Join(lines, "\n")+"\n")
	}))
	t.Cleanup(srv.Close)
	old := cratesIndexURL
	cratesIndexURL = srv.URL + "/"
	t.Cleanup(func() { cratesIndexURL = old })
}

func TestCargoInstallReleasesPicksAsCargoDoes(t *testing.T) {
	serveIndex(t, "it/oa/itoa", http.StatusOK,
		`{"name":"itoa","vers":"0.4.7","yanked":false}`,
		`{"name":"itoa","vers":"0.4.8","yanked":false}`,
		`{"name":"itoa","vers":"0.4.9","yanked":true}`,
		`{"name":"itoa","vers":"1.0.14","yanked":false}`,
		`{"name":"itoa","vers":"1.0.15+build.7","yanked":false}`,
		`{"name":"itoa","vers":"1.0.16","yanked":true}`,
		`{"name":"itoa","vers":"2.0.0-rc.1","yanked":false}`,
		`not json`,
		`{"name":"Itoa","vers":"9.0.0","yanked":false}`,
	)
	for _, tc := range []struct {
		req  string
		want []string
	}{
		// Cargo installs the newest stable release that is not yanked.
		{"", []string{"1.0.15+build.7"}},
		{"^0.4", []string{"0.4.8"}},
		{"<1", []string{"0.4.8"}},
		{">=0.4, <1", []string{"0.4.8"}},
		{"1.0.*", []string{"1.0.15+build.7"}},
		{"^2.0.0-rc", []string{"2.0.0-rc.1"}},
		// A pin matches whatever build metadata was published, and is checked even when yanked.
		{"=1.0.15", []string{"1.0.15+build.7"}},
		{"1.0.15", []string{"1.0.15+build.7"}},
		{"=1.0.14+zzz", []string{"1.0.14"}},
		{"=1.0.16", []string{"1.0.16"}},
	} {
		got, err := CargoInstallReleases(context.Background(), "itoa", tc.req)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("CargoInstallReleases(itoa, %q) = %q, %v; want %q", tc.req, got, err, tc.want)
		}
	}
	for _, req := range []string{"1.0", "1", "=3.0.0", "^5"} {
		if got, err := CargoInstallReleases(context.Background(), "itoa", req); err == nil {
			t.Errorf("CargoInstallReleases(itoa, %q) = %q; want an error, as cargo installs nothing", req, got)
		}
	}
	// Cargo matches the name exactly, so another spelling finds nothing.
	if got, err := CargoInstallReleases(context.Background(), "ITOA", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("CargoInstallReleases(ITOA) = %q, %v; want ErrNotFound", got, err)
	}
}

func TestCargoInstallReleasesChecksAnEntryOnlyANewerCargoReads(t *testing.T) {
	serveIndex(t, "3/s/syn", http.StatusOK,
		`{"name":"syn","vers":"1.0.0","yanked":false,"v":2}`,
		`{"name":"syn","vers":"1.1.0","yanked":false,"v":3}`,
	)
	got, err := CargoInstallReleases(context.Background(), "syn", "")
	if want := []string{"1.1.0", "1.0.0"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("CargoInstallReleases(syn) = %q, %v; want %q", got, err, want)
	}
}

func TestCargoInstallReleasesFailsWhenTheIndexCannotAnswer(t *testing.T) {
	serveIndex(t, "2/cc", http.StatusServiceUnavailable)
	if got, err := CargoInstallReleases(context.Background(), "cc", ""); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("CargoInstallReleases on a 503 = %q, %v; want an outage error", got, err)
	}
	if got, err := CargoInstallReleases(context.Background(), "x", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("CargoInstallReleases on a 404 = %q, %v; want ErrNotFound", got, err)
	}
}

func TestCrateIndexPathIsCargos(t *testing.T) {
	for name, want := range map[string]string{"a": "1/a", "cc": "2/cc", "Syn": "3/s/syn", "Serde_JSON": "se/rd/serde_json"} {
		if got := crateIndexPath(name); got != want {
			t.Errorf("crateIndexPath(%q) = %q, want %q", name, got, want)
		}
	}
}
