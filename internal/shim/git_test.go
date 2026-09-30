package shim

import (
	"path/filepath"
	"testing"
)

func TestGitIsOptIn(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	writeExec(t, filepath.Join(s.realDir, "git"), "#!/bin/sh\nexit 0\n")

	res, err := Install(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if contains(names(res.Done), "git") || contains(names(res.Skipped), "git") {
		t.Fatalf("default install touched git: done=%v skipped=%v", names(res.Done), names(res.Skipped))
	}
	st, err := Load(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range st.Managers {
		if m.Name == "git" {
			t.Fatal("status lists git before it is shimmed")
		}
	}

	o := s.opts()
	o.Git = true
	if res, err = Install(o); err != nil {
		t.Fatal(err)
	}
	if !contains(names(res.Done), "git") || !contains(names(res.Done), "npm") {
		t.Fatalf("--git installed %v, want git plus the defaults", names(res.Done))
	}

	// A flagless re-run keeps (re-points) the git shim.
	if res, err = Install(s.opts()); err != nil {
		t.Fatal(err)
	}
	if !contains(names(res.Done), "git") {
		t.Fatalf("re-run dropped git: %v", names(res.Done))
	}
}

func TestValidateManagersAcceptsGit(t *testing.T) {
	if _, err := ValidateManagers([]string{"git"}); err != nil {
		t.Fatal(err)
	}
}
