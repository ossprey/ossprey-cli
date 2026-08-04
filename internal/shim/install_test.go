package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sandbox builds an isolated home + shim dir + a stand-in ossprey binary, and
// puts a fake `npm` and `pip` on PATH so the "is it installed?" check has
// something to find.
type sandbox struct {
	root, home, shimDir, binary, realDir string
}

func newSandbox(t *testing.T) sandbox {
	t.Helper()
	root := t.TempDir()
	s := sandbox{
		root:    root,
		home:    filepath.Join(root, "home"),
		shimDir: filepath.Join(root, "home", ".ossprey", "shims"),
		binary:  filepath.Join(root, "bin", "ossprey"),
		realDir: filepath.Join(root, "real"),
	}
	mkdirs(t, s.home, filepath.Dir(s.binary), s.realDir)
	writeExec(t, s.binary, "#!/bin/sh\nexit 0\n")
	for _, m := range []string{"npm", "pip"} {
		writeExec(t, filepath.Join(s.realDir, m), "#!/bin/sh\nexit 0\n")
	}
	t.Setenv("PATH", s.realDir)
	return s
}

func (s sandbox) opts() Options {
	return Options{Dir: s.shimDir, Binary: s.binary, Home: s.home}
}

func TestInstallWritesShimsAndPath(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)

	res, err := Install(s.opts())
	if err != nil {
		t.Fatal(err)
	}

	if got := names(res.Done); !contains(got, "npm") || !contains(got, "pip") {
		t.Fatalf("installed %v, want npm and pip", got)
	}
	if got := names(res.Skipped); !contains(got, "poetry") {
		t.Fatalf("skipped %v, want uninstalled managers like poetry to be skipped", got)
	}
	for _, m := range res.Done {
		if !IsShim(m.Path) {
			t.Fatalf("%s is not a shim", m.Path)
		}
		fi, err := os.Stat(m.Path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s is not executable (%v)", m.Path, fi.Mode())
		}
	}

	profile := filepath.Join(s.home, ".profile")
	body := read(t, profile)
	if !strings.Contains(body, s.shimDir) || !strings.Contains(body, blockStart) {
		t.Fatalf("%s does not put the shim dir on PATH:\n%s", profile, body)
	}
	if !contains(res.Profiles, profile) {
		t.Fatalf("install reported profiles %v, want %s", res.Profiles, profile)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)

	if _, err := Install(s.opts()); err != nil {
		t.Fatal(err)
	}
	before := read(t, filepath.Join(s.home, ".profile"))

	res, err := Install(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	after := read(t, filepath.Join(s.home, ".profile"))

	if before != after {
		t.Fatalf("re-running install changed the profile:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if len(res.Profiles) != 0 {
		t.Fatalf("second install reported profile changes %v, want none", res.Profiles)
	}
	if n := strings.Count(after, blockStart); n != 1 {
		t.Fatalf("profile carries %d managed blocks, want 1", n)
	}
}

func TestInstallExplicitManagerNotOnPath(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)

	o := s.opts()
	o.Managers = []string{"poetry"} // deliberately not installed in the sandbox
	res, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Done) != 1 || res.Done[0].Name != "poetry" {
		t.Fatalf("naming a manager explicitly should shim it anyway, got %v", names(res.Done))
	}
}

func TestInstallRefusesToClobberForeignFile(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	mkdirs(t, s.shimDir)
	stranger := filepath.Join(s.shimDir, "npm")
	writeExec(t, stranger, "#!/bin/sh\necho not ours\n")

	if _, err := Install(s.opts()); err == nil {
		t.Fatal("install overwrote a file it did not create")
	}
	if body := read(t, stranger); !strings.Contains(body, "not ours") {
		t.Fatalf("the foreign file was modified: %s", body)
	}
}

func TestUninstallRemovesOnlyOurFiles(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)

	if _, err := Install(s.opts()); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(s.shimDir, "my-own-script")
	writeExec(t, keep, "#!/bin/sh\necho mine\n")

	res, err := Uninstall(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Done) == 0 {
		t.Fatal("uninstall removed nothing")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("uninstall deleted a file it did not create: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.shimDir, "npm")); !os.IsNotExist(err) {
		t.Fatal("npm shim survived uninstall")
	}
	if body := read(t, filepath.Join(s.home, ".profile")); strings.Contains(body, blockStart) {
		t.Fatalf("uninstall left the PATH block behind:\n%s", body)
	}
}

func TestUninstallOfOneManagerKeepsPath(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	if _, err := Install(s.opts()); err != nil {
		t.Fatal(err)
	}

	o := s.opts()
	o.Managers = []string{"npm"}
	if _, err := Uninstall(o); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(s.shimDir, "pip")); err != nil {
		t.Fatalf("removing the npm shim also removed pip: %v", err)
	}
	if body := read(t, filepath.Join(s.home, ".profile")); !strings.Contains(body, blockStart) {
		t.Fatal("a partial uninstall removed the PATH entry the remaining shims need")
	}
}

func TestUninstallOnCleanMachine(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	res, err := Uninstall(s.opts())
	if err != nil {
		t.Fatalf("uninstall with nothing installed should be a no-op, got %v", err)
	}
	if len(res.Done) != 0 {
		t.Fatalf("removed %v from an empty machine", names(res.Done))
	}
}

func TestInstallRejectsBinaryInsideShimDir(t *testing.T) {
	s := newSandbox(t)
	o := s.opts()
	o.Binary = filepath.Join(s.shimDir, "ossprey")
	if _, err := Install(o); err == nil {
		t.Fatal("expected an error: shims calling an ossprey inside the shim dir is a loop")
	}
}

func TestPlanWritesNothing(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)

	res, err := Plan(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Done) == 0 {
		t.Fatal("plan reported no shims")
	}
	if _, err := os.Stat(s.shimDir); !os.IsNotExist(err) {
		t.Fatal("--dry-run created the shim directory")
	}
	if _, err := os.Stat(filepath.Join(s.home, ".profile")); !os.IsNotExist(err) {
		t.Fatal("--dry-run touched a shell profile")
	}
}

func TestValidateManagers(t *testing.T) {
	got, err := ValidateManagers([]string{"npm", " pip ", "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "npm" || got[1] != "pip" {
		t.Fatalf("ValidateManagers = %v, want [npm pip] deduped and trimmed", got)
	}
	if _, err := ValidateManagers([]string{"cargo"}); err == nil {
		t.Fatal("expected an error for an unsupported manager")
	}
	if _, err := ValidateManagers(nil); err == nil {
		t.Fatal("expected an error for an empty list")
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func names(ms []ManagerResult) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
