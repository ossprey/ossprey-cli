package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A github check is sent at the commit the ref resolves to, and fails closed.
func TestCheckGitHub(t *testing.T) {
	const sha = "4ef51f69ca6347aaa76a5e64a87eac9c0c909f71"
	for _, tc := range []struct {
		name, token string
		resolveErr  error
		wantErr     string
		want        []string
	}{
		{"tag pinned to its commit", "trufflesecurity/trufflehog@v3.100.1", nil, "", []string{"pkg:github/trufflesecurity/trufflehog@" + sha}},
		{"sha", "trufflesecurity/trufflehog@" + sha, nil, "", []string{"pkg:github/trufflesecurity/trufflehog@" + sha}},
		{"no ref", "trufflesecurity/trufflehog", nil, "needs a ref", nil},
		{"lookup fails closed", "trufflesecurity/trufflehog@v3.100.1", errors.New("GitHub API 503"), "GitHub API 503", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := resolveGitHubFn
			resolveGitHubFn = func(_ context.Context, slug, ref string) (string, error) {
				if slug != "trufflesecurity/trufflehog" {
					t.Errorf("slug = %q", slug)
				}
				return sha, tc.resolveErr
			}
			t.Cleanup(func() { resolveGitHubFn = old })

			var mu sync.Mutex
			var sent []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					SBOM struct {
						Components []struct {
							Purl string `json:"purl"`
						} `json:"components"`
					} `json:"sbom"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				mu.Lock()
				for _, c := range body.SBOM.Components {
					sent = append(sent, c.Purl)
				}
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"components":[],"vulnerabilities":[]}`)
			}))
			t.Cleanup(srv.Close)

			err := runCheck(t, "-e", "github", tc.token, "--url", srv.URL, "--api-key", "k")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("err = %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(sent, tc.want) {
				t.Errorf("purls sent = %v, want %v", sent, tc.want)
			}
		})
	}
}
