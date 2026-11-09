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

func TestBrewIsOptIn(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	writeExec(t, filepath.Join(s.realDir, "brew"), "#!/bin/sh\nexit 0\n")

	res, err := Install(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if contains(names(res.Done), "brew") {
		t.Fatalf("default install shimmed brew: %v", names(res.Done))
	}
	o := s.opts()
	o.Brew = true
	if res, err = Install(o); err != nil {
		t.Fatal(err)
	}
	if !contains(names(res.Done), "brew") || !contains(names(res.Done), "npm") {
		t.Fatalf("--brew installed %v, want brew plus the defaults", names(res.Done))
	}
	if res, err = Install(s.opts()); err != nil {
		t.Fatal(err)
	}
	if !contains(names(res.Done), "brew") {
		t.Fatalf("re-run dropped brew: %v", names(res.Done))
	}
}

func TestCargoIsOptIn(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	writeExec(t, filepath.Join(s.realDir, "cargo"), "#!/bin/sh\nexit 0\n")

	res, err := Install(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if contains(names(res.Done), "cargo") || contains(names(res.Skipped), "cargo") {
		t.Fatalf("default install touched cargo: done=%v skipped=%v", names(res.Done), names(res.Skipped))
	}
	st, err := Load(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range st.Managers {
		if m.Name == "cargo" {
			t.Fatal("status lists cargo before it is shimmed")
		}
	}

	o := s.opts()
	o.Managers = []string{"cargo"}
	if res, err = Install(o); err != nil {
		t.Fatal(err)
	}
	if got := names(res.Done); len(got) != 1 || got[0] != "cargo" {
		t.Fatalf("--managers cargo installed %v, want cargo alone", got)
	}
	if st, err = Load(s.opts()); err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, m := range st.Managers {
		listed = listed || m.Name == "cargo" && m.Shim != ""
	}
	if !listed {
		t.Fatal("status does not list the cargo shim once it is installed")
	}

	// A flagless re-run keeps (re-points) the cargo shim.
	if res, err = Install(s.opts()); err != nil {
		t.Fatal(err)
	}
	if !contains(names(res.Done), "cargo") || !contains(names(res.Done), "npm") {
		t.Fatalf("re-run installed %v, want cargo kept beside the defaults", names(res.Done))
	}

	o = s.opts()
	o.Cargo = true
	if res, err = Install(o); err != nil {
		t.Fatal(err)
	}
	if !contains(names(res.Done), "cargo") || !contains(names(res.Done), "npm") {
		t.Fatalf("--cargo installed %v, want cargo plus the defaults", names(res.Done))
	}
}

func TestCargoIsNotADefaultManager(t *testing.T) {
	if contains(DefaultManagers(), "cargo") {
		t.Fatal("cargo is opt-in: most accounts would pay a lookup for crates their plan does not check")
	}
	if _, err := ValidateManagers([]string{"cargo"}); err != nil {
		t.Fatal(err)
	}
}
