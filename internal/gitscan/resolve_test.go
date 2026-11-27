package gitscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeResolveAPI serves repos/<o>/<r> and repos/<o>/<r>/commits/<ref>.
func fakeResolveAPI(t *testing.T, repoStatus int, private bool, commits map[string]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); h != "" {
			t.Errorf("sent Authorization %q; lookups must be unauthenticated", h)
		}
		if ref, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/commits/"); ok {
			sha, found := commits[ref]
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(sha))
			return
		}
		if r.URL.Path != "/repos/o/r" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(repoStatus)
		if private {
			_, _ = w.Write([]byte(`{"private":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"private":false,"default_branch":"main"}`))
	}))
	t.Cleanup(srv.Close)
	old := githubAPIURL
	githubAPIURL = srv.URL + "/"
	t.Cleanup(func() { githubAPIURL = old })
}

func TestResolvePublicCommit(t *testing.T) {
	other := strings.Repeat("f", 40)
	cases := []struct {
		name, slug, ref string
		status          int
		private         bool
		want, wantErr   string
	}{
		{"tag resolves", "o/r", "v1.0.0", 200, false, sha, ""},
		{"sha resolves to itself", "o/r", sha, 200, false, sha, ""},
		{"upper-case sha", "o/r", strings.ToUpper(sha), 200, false, sha, ""},
		{"missing ref", "o/r", "", 200, false, "", "required"},
		{"bad slug", "o", "v1.0.0", 200, false, "", "owner/repo"},
		{"slug with path", "o/r/x", "v1.0.0", 200, false, "", "owner/repo"},
		{"unknown or private repo", "o/r", "v1.0.0", 404, false, "", "not found, or not public"},
		{"private repo", "o/r", "v1.0.0", 200, true, "", "not a public repository"},
		{"GitHub down", "o/r", "v1.0.0", 503, false, "", "GitHub API"},
		{"unknown ref", "o/r", "nope", 200, false, "", "no commit, tag or branch"},
		{"sha that resolves elsewhere", "o/r", other, 200, false, "", "resolved"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fakeResolveAPI(t, c.status, c.private, map[string]string{
				"v1.0.0": sha, sha: sha, strings.ToUpper(sha): sha, other: sha,
			})
			got, err := ResolvePublicCommit(context.Background(), c.slug, c.ref)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}
