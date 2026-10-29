package shim

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// LookPathReal must skip a shim however PATH spells its directory: a trailing
// slash, a duplicate entry or a symlink all reach the same marker-carrying file.
func TestLookPathRealSkipsShimsUnderAnySpelling(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)
	writeExec(t, filepath.Join(shimDir, "npm"), Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: filepath.Join(root, "ossprey")}))
	real := filepath.Join(realDir, "npm")
	writeExec(t, real, "#!/bin/sh\nexit 0\n")
	link := filepath.Join(root, "linked-shims")
	if err := os.Symlink(shimDir, link); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", strings.Join([]string{shimDir + "/", link, shimDir, shimDir + "//", realDir}, ":"))
	got, err := LookPathReal("npm")
	if err != nil || got != real {
		t.Fatalf("LookPathReal = %q, %v; want the real npm at %q", got, err, real)
	}
}

// A path containing a separator is taken as given, never searched: shims are
// only skipped on a PATH search.
func TestLookPathRealUsesAnExplicitPathAsGiven(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	tool := filepath.Join(root, "npm")
	writeExec(t, tool, "#!/bin/sh\nexit 0\n")
	t.Setenv("PATH", "")
	if got, err := LookPathReal(tool); err != nil || got != tool {
		t.Fatalf("LookPathReal(%q) = %q, %v", tool, got, err)
	}
	if _, err := LookPathReal(filepath.Join(root, "missing")); err == nil {
		t.Fatal("a missing explicit path resolved")
	}
}

// The binary and shim directory are interpolated into an executable script, so
// shell metacharacters in either must reach ossprey literally and run nothing.
func TestPosixShimQuotesHostilePaths(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	hostile := `we ird'"$(touch pwned-sub)` + "`touch pwned-tick`;touch pwned-semi"
	shimDir := filepath.Join(root, "shims "+hostile)
	binDir := filepath.Join(root, "bin "+hostile)
	realDir := filepath.Join(root, "real")
	mkdirs(t, shimDir, binDir, realDir)

	bin := filepath.Join(binDir, "ossprey "+hostile)
	writeExec(t, bin, "#!/bin/sh\necho \"ossprey called: $*\"\necho \"PATH=$PATH\"\n")
	writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\necho real npm\n")
	shimPath := filepath.Join(shimDir, "npm")
	writeExec(t, shimPath, Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: bin}))

	cmd := exec.Command(shimPath, "install", "left-pad")
	cmd.Dir = root
	cmd.Env = []string{"PATH=" + shimDir + ":" + realDir}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shim: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ossprey called: npm install left-pad") {
		t.Fatalf("shim did not reach the quoted binary:\n%s", out)
	}
	if strings.Contains(string(out), shimDir) {
		t.Fatalf("shim did not strip its own (quoted) directory from PATH:\n%s", out)
	}
	for _, f := range []string{"pwned-sub", "pwned-tick", "pwned-semi"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			t.Fatalf("a path in the shim was executed as shell: %s exists", f)
		}
	}
	if got := ShimBinary(shimPath); got != bin {
		t.Fatalf("ShimBinary = %q, want %q", got, bin)
	}
}

// Every argument reaches ossprey exactly as typed: no word splitting, no glob
// expansion, empty arguments kept.
func TestShimForwardsArgumentsVerbatim(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)
	writeExec(t, filepath.Join(root, "match-me"), "")
	bin := filepath.Join(root, "ossprey")
	writeExec(t, bin, "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]\\n' \"$a\"; done\n")
	writeExec(t, filepath.Join(shimDir, "npm"), Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: bin}))

	args := []string{"install", "a b", "", "*", "$(id)", "it's"}
	cmd := exec.Command(filepath.Join(shimDir, "npm"), args...)
	cmd.Dir = root
	cmd.Env = []string{"PATH=" + shimDir + ":" + realDir}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shim: %v\n%s", err, out)
	}
	want := "[npm]\n"
	for _, a := range args {
		want += "[" + a + "]\n"
	}
	if string(out) != want {
		t.Fatalf("arguments were altered:\ngot  %q\nwant %q", out, want)
	}
}

// Every occurrence of the shim directory is stripped, wherever it sits.
func TestShimStripsEveryOccurrenceOfItsDirectory(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir, other := filepath.Join(root, "shims"), filepath.Join(root, "real"), filepath.Join(root, "other")
	mkdirs(t, shimDir, realDir, other)
	bin := filepath.Join(root, "ossprey")
	writeExec(t, bin, "#!/bin/sh\necho \"PATH=$PATH\"\n")
	writeExec(t, filepath.Join(shimDir, "npm"), Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: bin}))

	cmd := exec.Command(filepath.Join(shimDir, "npm"), "install")
	cmd.Env = []string{"PATH=" + strings.Join([]string{shimDir, other, shimDir, realDir, shimDir}, ":")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run shim: %v\n%s", err, out)
	}
	if want := "PATH=" + other + ":" + realDir + "\n"; string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

// A binary that exists but cannot execute is as good as missing: fail open.
func TestShimFailsOpenOnANonExecutableBinary(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)
	bin := filepath.Join(root, "ossprey")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho ossprey called\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\necho \"real npm: $*\"\n")
	writeExec(t, filepath.Join(shimDir, "npm"), Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: bin}))

	out := runShim(t, shimDir, realDir, nil, "install", "x")
	if strings.Contains(out, "ossprey called") || !strings.Contains(out, "real npm: install x") || !strings.Contains(out, "is missing") {
		t.Fatalf("shim did not fail open with a warning:\n%s", out)
	}
}

// The real manager's exit status survives the bypass path.
func TestShimBypassKeepsTheManagersExitCode(t *testing.T) {
	requirePOSIX(t)

	root := t.TempDir()
	shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
	mkdirs(t, shimDir, realDir)
	writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\nexit 7\n")
	writeExec(t, filepath.Join(shimDir, "npm"), Script(ScriptOptions{Manager: "npm", Dir: shimDir, Binary: filepath.Join(root, "ossprey")}))

	cmd := exec.Command(filepath.Join(shimDir, "npm"), "install")
	cmd.Env = []string{"PATH=" + shimDir + ":" + realDir, BypassEnv + "=1"}
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("exit = %v, want the real npm's 7", err)
	}
}

// The .cmd generator runs on every OS, so its content is pinned here too.
func TestWindowsScriptContent(t *testing.T) {
	dir := `C:\Users\dev\AppData\Local\ossprey\shims\`
	bin := `C:\Program Files\ossprey\ossprey.exe`
	script := windowsScript(ScriptOptions{Manager: "npm", Dir: dir, Binary: bin, Mode: ModeMonitor, MonitorID: testMonitorID})

	for _, want := range []string{
		"@echo off\n",
		":: " + Marker + "\n",
		":: " + binPrefix + bin + "\n",
		":: " + modePrefix + "monitor " + testMonitorID + "\n",
		// Trailing backslash dropped so the ";"-anchored strip matches.
		`call set "PATH=%%PATH:C:\Users\dev\AppData\Local\ossprey\shims;=%%"`,
		// ...and the trailing-backslash spelling of the same entry.
		`call set "PATH=%%PATH:C:\Users\dev\AppData\Local\ossprey\shims\;=%%"`,
		// Re-entry guard: counted on the bypass path, checked on entry.
		`set /a "ossprey_depth=` + depthEnv + `+0"`,
		"if %ossprey_depth% GEQ " + maxDepth + " (",
		":ossprey_bypass\nset /a \"" + depthEnv + "=ossprey_depth+1\" >nul\n",
		"if defined " + BypassEnv + " goto ossprey_bypass\n",
		`if not exist "` + bin + `" (`,
		`set "` + passiveEnv + `=1"` + "\n",
		`set "` + monitorEnv + `=` + testMonitorID + `"` + "\n",
		`"` + bin + `" npm %*` + "\n",
		"call npm %*\nexit /b %ERRORLEVEL%\n",
	} {
		if !strings.Contains(script, want) {
			t.Errorf(".cmd shim is missing %q:\n%s", want, script)
		}
	}
	// The env block must come before the exec it configures.
	if strings.Index(script, passiveEnv) > strings.Index(script, `"`+bin+`" npm %*`) {
		t.Error("passive env is set after ossprey is invoked")
	}

	path := filepath.Join(t.TempDir(), "npm.cmd")
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	if !IsShim(path) || ShimBinary(path) != bin {
		t.Fatalf("IsShim/ShimBinary do not read the .cmd shim: %v %q", IsShim(path), ShimBinary(path))
	}
	if mode, id := ShimMode(path); mode != ModeMonitor || id != testMonitorID {
		t.Fatalf("ShimMode(.cmd) = %q / %q", mode, id)
	}
}

func TestWindowsBlockingScriptSetsNoPassiveEnv(t *testing.T) {
	script := windowsScript(ScriptOptions{Manager: "pip", Dir: `C:\s`, Binary: `C:\o.exe`})
	if strings.Contains(script, passiveEnv) || strings.Contains(script, monitorEnv) || strings.Contains(script, modePrefix) {
		t.Fatalf("blocking .cmd shim carries passive settings:\n%s", script)
	}
}

// A file named like a manager but not ours survives uninstall, including a
// targeted `--managers` uninstall, and so does a directory of that name.
func TestUninstallKeepsForeignFilesNamedLikeManagers(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	o := s.opts()
	o.Managers = []string{"pip"}
	o.All = true
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(s.shimDir, "npm")
	writeExec(t, foreign, "#!/bin/sh\necho my own npm wrapper\n")
	mkdirs(t, filepath.Join(s.shimDir, "yarn"))

	only := s.opts()
	only.Managers = []string{"npm", "pip", "yarn"}
	if _, err := Uninstall(only); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(s.opts()); err != nil {
		t.Fatal(err)
	}
	if body := read(t, foreign); !strings.Contains(body, "my own npm wrapper") {
		t.Fatalf("foreign npm was modified: %s", body)
	}
	if fi, err := os.Stat(filepath.Join(s.shimDir, "yarn")); err != nil || !fi.IsDir() {
		t.Fatalf("directory named yarn was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.shimDir, "pip")); !os.IsNotExist(err) {
		t.Fatal("our pip shim survived uninstall")
	}
}

// Removing every shim removes the now-empty directory too.
func TestUninstallRemovesAnEmptyShimDir(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	if _, err := Install(s.opts()); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(s.opts()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.shimDir); !os.IsNotExist(err) {
		t.Fatalf("empty shim dir left behind: %v", err)
	}
}

// Docs: `shim uninstall --managers git` removes git alone and keeps the PATH
// entry the remaining shims need.
func TestUninstallGitOnlyKeepsTheRest(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	writeExec(t, filepath.Join(s.realDir, "git"), "#!/bin/sh\nexit 0\n")
	o := s.opts()
	o.Git = true
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}

	only := s.opts()
	only.Managers = []string{"git"}
	res, err := Uninstall(only)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(res.Done); len(got) != 1 || got[0] != "git" {
		t.Fatalf("removed %v, want [git]", got)
	}
	if !IsShim(filepath.Join(s.shimDir, "npm")) {
		t.Fatal("removing git removed npm")
	}
	if !strings.Contains(read(t, filepath.Join(s.home, ".profile")), blockStart) {
		t.Fatal("removing git removed the PATH block")
	}

	// And a flagless re-run no longer brings git back.
	res2, err := Install(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if contains(names(res2.Done), "git") {
		t.Fatal("flagless re-run re-created an uninstalled git shim")
	}
}

// status lists git once it is shimmed (and only then, see TestGitIsOptIn), and
// an explicit --managers run leaves an installed git shim alone.
func TestGitShimStatusAndExplicitRerun(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	writeExec(t, filepath.Join(s.realDir, "git"), "#!/bin/sh\nexit 0\n")
	o := s.opts()
	o.Managers = []string{"git"}
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}

	st, err := Load(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, m := range st.Managers {
		if m.Name == "git" {
			listed = m.Shim != ""
		}
	}
	if !listed {
		t.Fatal("status does not list the installed git shim")
	}

	npmOnly := s.opts()
	npmOnly.Managers = []string{"npm"}
	res, err := Install(npmOnly)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(res.Done); len(got) != 1 || got[0] != "npm" {
		t.Fatalf("explicit --managers npm touched %v", got)
	}
	if !IsShim(filepath.Join(s.shimDir, "git")) {
		t.Fatal("explicit run removed the git shim")
	}
}

// A machine with a mix of modes reports each shim's own mode in status, and
// the plan summary is the strongest one present.
func TestMixedModesReportPerManager(t *testing.T) {
	requirePOSIX(t)
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	bin := filepath.Join(root, "ossprey")
	writeExec(t, bin, "#!/bin/sh\nexit 0\n")
	base := Options{Dir: shimDir, Binary: bin, All: true, SkipProfiles: true, Home: root}

	install := func(m string, mode Mode, id string) {
		o := base
		o.Managers, o.Mode, o.MonitorID = []string{m}, mode, id
		if _, err := Install(o); err != nil {
			t.Fatalf("install %s: %v", m, err)
		}
	}
	install("npm", ModeBlocking, "")
	install("pip", ModeWatchdog, "")
	install("uv", ModeMonitor, testMonitorID)

	st, err := Load(base)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Mode{"npm": ModeBlocking, "pip": ModeWatchdog, "uv": ModeMonitor}
	for _, m := range st.Managers {
		if w, ok := want[m.Name]; ok {
			if m.Mode != w {
				t.Errorf("%s reported as %q, want %q", m.Name, m.Mode, w)
			}
			delete(want, m.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("status did not list %v", want)
	}

	plan := base
	plan.Managers = []string{"npm", "pip", "uv"}
	res, err := Plan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != ModeMonitor || res.MonitorID != testMonitorID {
		t.Fatalf("plan summary = %q / %q, want the monitor", res.Mode, res.MonitorID)
	}
}

// A symlink planted at the predictable .tmp path is replaced, never written
// through: the shim write must not clobber the link's target.
func TestInstallDoesNotWriteThroughAPlantedTmpSymlink(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	mkdirs(t, s.shimDir)
	victim := filepath.Join(s.root, "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(s.shimDir, "npm.tmp")); err != nil {
		t.Fatal(err)
	}

	o := s.opts()
	o.Managers = []string{"npm"}
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}
	if body := read(t, victim); body != "precious" {
		t.Fatalf("shim install wrote through the planted symlink: %q", body)
	}
	if !IsShim(filepath.Join(s.shimDir, "npm")) {
		t.Fatal("npm shim not installed")
	}
}

// Profile blocks on a CRLF file round-trip byte for byte, and re-writing is a
// no-op.
func TestProfileBlockRoundTripsOnCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".bashrc")
	original := "export A=1\r\nalias g=git\r\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	p := Profile{Path: path}
	if changed, err := WriteBlock(p, "/opt/shims"); err != nil || !changed {
		t.Fatalf("WriteBlock = %v, %v", changed, err)
	}
	if changed, err := WriteBlock(p, "/opt/shims"); err != nil || changed {
		t.Fatalf("second WriteBlock = %v, %v; want no change", changed, err)
	}
	if _, err := RemoveBlock(p); err != nil {
		t.Fatal(err)
	}
	if got := read(t, path); got != original {
		t.Fatalf("CRLF profile not restored:\nwant %q\ngot  %q", original, got)
	}
}

// User lines after our block survive a re-install pointing elsewhere and an
// uninstall; duplicated blocks collapse to one.
func TestProfileBlockKeepsContentAroundIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".zshrc")
	p := Profile{Path: path}
	if err := os.WriteFile(path, []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBlock(p, "/old/shims"); err != nil {
		t.Fatal(err)
	}
	dup := read(t, path) + "after\n" + block(p, "/older/shims")
	if err := os.WriteFile(path, []byte(dup), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteBlock(p, "/new/shims"); err != nil {
		t.Fatal(err)
	}
	body := read(t, path)
	if n := strings.Count(body, blockStart); n != 1 {
		t.Fatalf("%d blocks after re-install, want 1:\n%s", n, body)
	}
	if strings.Contains(body, "/old/shims") || strings.Contains(body, "/older/shims") || !strings.Contains(body, "/new/shims") {
		t.Fatalf("stale entries survived:\n%s", body)
	}
	if !strings.Contains(body, "before\n") || !strings.Contains(body, "after\n") {
		t.Fatalf("user content lost:\n%s", body)
	}

	if _, err := RemoveBlock(p); err != nil {
		t.Fatal(err)
	}
	if got := read(t, path); got != "before\nafter\n" {
		t.Fatalf("uninstall left %q, want the user's lines", got)
	}
}

// The POSIX block prepends the directory once, however often the profile is
// sourced, and handles a directory with spaces and quotes.
func TestProfileBlockIsIdempotentWhenSourced(t *testing.T) {
	requirePOSIX(t)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := `/opt/my shims/it's`
	path := filepath.Join(t.TempDir(), ".profile")
	if _, err := WriteBlock(Profile{Path: path}, dir); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sh, "-c", `. "$1"; . "$1"; printf '%s' "$PATH"`, "sh", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source profile: %v\n%s", err, out)
	}
	if want := dir + ":/usr/bin:/bin"; string(out) != want {
		t.Fatalf("PATH = %q, want %q", out, want)
	}
}

func TestFishBlockQuotesTheDirectory(t *testing.T) {
	b := block(Profile{Fish: true}, `/opt/it's`)
	for _, want := range []string{`if not contains '/opt/it\'s' $PATH`, `set -gx PATH '/opt/it\'s' $PATH`} {
		if !strings.Contains(b, want) {
			t.Errorf("fish block missing %q:\n%s", want, b)
		}
	}
}

// Uninstall strips the block from every managed profile, fish included.
func TestUninstallRemovesBlockFromEveryProfile(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	for _, rel := range []string{".bash_profile", ".zprofile", filepath.Join(".config", "fish", "config.fish")} {
		mkdirs(t, filepath.Dir(filepath.Join(s.home, rel)))
		if err := os.WriteFile(filepath.Join(s.home, rel), []byte("# mine\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Install(s.opts()); err != nil {
		t.Fatal(err)
	}
	for _, p := range Profiles(s.home) {
		if !HasBlock(p.Path) {
			t.Errorf("%s has no block after install", p.Path)
		}
	}
	if _, err := Uninstall(s.opts()); err != nil {
		t.Fatal(err)
	}
	for _, p := range Profiles(s.home) {
		if HasBlock(p.Path) {
			t.Errorf("%s still has a block after uninstall", p.Path)
		}
	}
	if got := read(t, filepath.Join(s.home, ".config", "fish", "config.fish")); got != "# mine\n" {
		t.Errorf("fish config not restored: %q", got)
	}
}
