package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// allHookCommands returns every SessionStart command in a settings file.
func allHookCommands(t *testing.T, path string) []string {
	t.Helper()
	s, err := parseSettings([]byte(read(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return s.hookCommands()
}

// runClaudeHook runs our hook the way Claude Code would, n times (startup,
// then resume or compact), and returns PATH as a later Bash command sees it.
func runClaudeHook(t *testing.T, dir, startPath string, n int) (path, envFile string) {
	t.Helper()
	root := t.TempDir()
	settings := filepath.Join(root, "settings.json")
	if _, err := WriteClaudeHook(settings, dir); err != nil {
		t.Fatal(err)
	}
	cmds := allHookCommands(t, settings)
	if len(cmds) != 1 {
		t.Fatalf("hook commands = %v, want one", cmds)
	}
	envFile = filepath.Join(root, "claude-env")
	for range n {
		hook := exec.Command("sh", "-c", cmds[0])
		hook.Env = append(os.Environ(), "CLAUDE_ENV_FILE="+envFile)
		if out, err := hook.CombinedOutput(); err != nil {
			t.Fatalf("hook failed: %v\n%s", err, out)
		}
	}
	// Claude Code runs the env file before every Bash command.
	cmd := exec.Command("sh", "-c", `. "$1"; . "$1"; printf '%s' "$PATH"`, "sh", envFile)
	cmd.Env = append(os.Environ(), "PATH="+startPath)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out), envFile
}

func TestClaudeHookPutsShimsFirstOnPathForLaterCommands(t *testing.T) {
	requirePOSIX(t)
	dir := filepath.Join(t.TempDir(), "it's shims")
	got, _ := runClaudeHook(t, dir, "/usr/bin:/bin", 1)
	if want := dir + ":/usr/bin:/bin"; got != want {
		t.Fatalf("PATH = %q, want %q", got, want)
	}
}

func TestClaudeHookMovesShimsAheadOfAnInheritedNpm(t *testing.T) {
	requirePOSIX(t)
	// A terminal whose .bashrc adds the shims and then nvm's bin hands Claude
	// Code a PATH with npm ahead of the shim.
	dir := filepath.Join(t.TempDir(), "shims")
	got, _ := runClaudeHook(t, dir, "/nvm/bin:"+dir+":/usr/bin", 1)
	if want := dir + ":/nvm/bin:/usr/bin"; got != want {
		t.Fatalf("PATH = %q, want %q", got, want)
	}
}

func TestClaudeHookWritesItsLineOnceAcrossResumes(t *testing.T) {
	requirePOSIX(t)
	_, envFile := runClaudeHook(t, "/s", "/usr/bin", 3)
	if n := strings.Count(read(t, envFile), agentHookMarker); n != 1 {
		t.Fatalf("env file has %d copies of the PATH line, want 1:\n%s", n, read(t, envFile))
	}
}

func TestClaudeHookDoesNothingOutsideASession(t *testing.T) {
	requirePOSIX(t)
	cmd := exec.Command("sh", "-c", claudeHookCommand("/x"))
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hook without CLAUDE_ENV_FILE failed: %v\n%s", err, out)
	}
}

func TestClaudeHookRoundTripLeavesTheUsersFileAsItWas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	// Unsorted keys, a number float64 would round, and a hook group whose
	// keys are out of alphabetical order: all must survive install+uninstall.
	user := `{
  "model": "opus",
  "cleanupPeriodDays": 12345678901234567890,
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "echo stop"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "type": "command",
            "command": "echo mine",
            "timeout": 30
          }
        ]
      }
    ]
  },
  "env": {}
}
`
	if err := os.WriteFile(path, []byte(user), 0o600); err != nil {
		t.Fatal(err)
	}

	if wrote, err := WriteClaudeHook(path, "/a"); err != nil || !wrote {
		t.Fatalf("first write = %v, %v", wrote, err)
	}
	if wrote, err := WriteClaudeHook(path, "/a"); err != nil || wrote {
		t.Fatalf("re-write = %v, %v; want an unchanged file", wrote, err)
	}
	// A moved shim directory replaces our hook rather than adding a second.
	if _, err := WriteClaudeHook(path, "/b"); err != nil {
		t.Fatal(err)
	}
	cmds := allHookCommands(t, path)
	if len(cmds) != 2 || cmds[0] != "echo mine" || !hasClaudeHookFor(path, "/b") {
		t.Fatalf("SessionStart commands = %q, want the user's hook then ours for /b", cmds)
	}
	if strings.Contains(read(t, path), "\\u003e") {
		t.Fatalf("the hook's >> was HTML-escaped:\n%s", read(t, path))
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want the user's 0600 kept", fi.Mode().Perm())
	}

	if removed, err := RemoveClaudeHook(path); err != nil || !removed {
		t.Fatalf("remove = %v, %v", removed, err)
	}
	if got := read(t, path); got != user {
		t.Fatalf("after uninstall:\n%s\nwant the original file:\n%s", got, user)
	}
}

func TestWriteClaudeHookFollowsASymlinkedSettingsFile(t *testing.T) {
	requirePOSIX(t)
	root := t.TempDir()
	target := filepath.Join(root, "dotfiles", "settings.json")
	mkdirs(t, filepath.Dir(target), filepath.Join(root, ".claude"))
	if err := os.WriteFile(target, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".claude", "settings.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteClaudeHook(link, "/a"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the settings symlink was replaced by a file")
	}
	if !hasClaudeHookFor(target, "/a") {
		t.Fatal("hook not written to the symlink's target")
	}
}

func TestWriteClaudeHookRefusesInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	const broken = `{"model": "opus",` // truncated
	if err := os.WriteFile(path, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteClaudeHook(path, "/a"); err == nil {
		t.Fatal("wrote into a settings file it could not parse")
	}
	if got := read(t, path); got != broken {
		t.Fatalf("file changed to %q", got)
	}
}

func TestMarkerOutsideAHookIsNotOurHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"note": "`+agentHookMarker+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if HasClaudeHook(path) {
		t.Fatal("a marker in an unrelated value read as an installed hook")
	}
}

func agentSandbox(t *testing.T) (sandbox, string) {
	t.Helper()
	requirePOSIX(t)
	s := newSandbox(t)
	t.Setenv(claudeConfigDirEnv, "")
	return s, filepath.Join(s.home, ".claude", "settings.json")
}

func TestInstallAgentHookIsRepointedAndUninstalled(t *testing.T) {
	s, settings := agentSandbox(t)

	o := s.opts()
	o.Agents = []string{AgentClaude}
	res, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(res.Agents, settings) || !hasClaudeHookFor(settings, s.shimDir) {
		t.Fatalf("install reported agents %v; hook for %s not written", res.Agents, s.shimDir)
	}

	// A flagless re-run into a new directory, as after moving the shims, keeps
	// the hook and points it at the new directory.
	moved := s.opts()
	moved.Dir = filepath.Join(s.root, "moved")
	if _, err := Install(moved); err != nil {
		t.Fatal(err)
	}
	if !hasClaudeHookFor(settings, moved.Dir) {
		t.Fatalf("hook not re-pointed at %s: %v", moved.Dir, allHookCommands(t, settings))
	}

	res, err = Uninstall(moved)
	if err != nil {
		t.Fatal(err)
	}
	if HasClaudeHook(settings) || !contains(res.Profiles, settings) {
		t.Fatalf("uninstall left the hook (reported %v)", res.Profiles)
	}
}

func TestNoPathInstallLeavesAnExistingHookAlone(t *testing.T) {
	s, settings := agentSandbox(t)
	o := s.opts()
	o.Agents = []string{AgentClaude}
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}

	// A throwaway install, as in a test or image build, must not move the
	// user's hook to a directory that is about to be deleted.
	tmp := s.opts()
	tmp.Dir = filepath.Join(s.root, "throwaway")
	tmp.SkipProfiles = true
	plan, err := Plan(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Agents) != 0 {
		t.Fatalf("--no-path dry run would touch %v", plan.Agents)
	}
	if _, err := Install(tmp); err != nil {
		t.Fatal(err)
	}
	if !hasClaudeHookFor(settings, s.shimDir) {
		t.Fatalf("--no-path install moved the hook: %v", allHookCommands(t, settings))
	}
}

func TestNoPathUninstallRemovesOnlyAHookForItsDirectory(t *testing.T) {
	s, settings := agentSandbox(t)
	o := s.opts()
	o.Agents = []string{AgentClaude}
	o.SkipProfiles = true
	if _, err := Install(o); err != nil {
		t.Fatal(err)
	}

	other := s.opts()
	other.Dir = filepath.Join(s.root, "other")
	other.SkipProfiles = true
	if _, err := Uninstall(other); err != nil {
		t.Fatal(err)
	}
	if !hasClaudeHookFor(settings, s.shimDir) {
		t.Fatal("uninstalling another directory removed the hook")
	}

	if _, err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if HasClaudeHook(settings) {
		t.Fatal("--no-path uninstall left a hook pointing at the removed shims")
	}
}

func TestBrokenAgentSettingsWarnButNeverFail(t *testing.T) {
	s, settings := agentSandbox(t)
	mkdirs(t, filepath.Dir(settings))
	broken := `{"hooks": "` + agentHookMarker + `",`
	if err := os.WriteFile(settings, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := Plan(s.opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Agents) != 0 || len(plan.Warnings) == 0 {
		t.Fatalf("dry run: agents %v, warnings %v; want a warning and no write", plan.Agents, plan.Warnings)
	}
	if _, err := Install(s.opts()); err != nil {
		t.Fatalf("upgrade failed over a broken agent settings file: %v", err)
	}
	res, err := Uninstall(s.opts())
	if err != nil {
		t.Fatalf("uninstall failed over a broken agent settings file: %v", err)
	}
	if len(res.Done) == 0 || len(res.Warnings) == 0 {
		t.Fatalf("uninstall removed %v with warnings %v; want shims removed and a warning", names(res.Done), res.Warnings)
	}
	if read(t, settings) != broken {
		t.Fatal("rewrote a settings file it could not parse")
	}
}

func TestValidateAgentsRejectsUnknown(t *testing.T) {
	if err := ValidateAgents([]string{"cursor"}); err == nil {
		t.Fatal("accepted an unsupported agent")
	}
}
