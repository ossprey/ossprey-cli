package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRepoSBOM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/public/v1/tools/sbom" || r.Header.Get("x-api-key") != "k" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("purl"); got != "pkg:github/o/r@abc" {
			t.Errorf("purl = %q", got)
		}
		_, _ = w.Write([]byte(`{"components":[
			{"name":"x","purl":"pkg:npm/%40scope/left-pad@1.0.0"},
			{"purl":"pkg:cargo/regex@1.11.0"},
			{"purl":"pkg:github/o/r@abc?path=sub"},
			{"purl":"not a purl"},
			{"purl":"pkg:pypi/noversion"}]}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "k")
	got, err := c.RepoSBOM(context.Background(), "pkg:github/o/r@abc")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg:npm/@scope/left-pad@1.0.0", "pkg:cargo/regex@1.11.0", "pkg:github/o/r@abc?path=sub"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, w := range want {
		if got[i].Purl() != w {
			t.Errorf("[%d] = %s, want %s", i, got[i].Purl(), w)
		}
	}
}

func TestRepoSBOMErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"too large\nossprey: forged line\u001b[2J"}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "k")
	_, err := c.RepoSBOM(context.Background(), "pkg:github/o/r@abc")
	if err == nil {
		t.Fatal("want error on 400")
	}
	if strings.ContainsAny(err.Error(), "\n\x1b") {
		t.Errorf("API text reached the terminal unsanitised: %q", err)
	}
	ic := newClient(srv.URL)
	ic.IngestToken = "t"
	if _, err := ic.RepoSBOM(context.Background(), "x"); !errors.Is(err, ErrNoRepoSBOM) {
		t.Errorf("ingest: %v", err)
	}
}
