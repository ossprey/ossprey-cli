package shim

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// claudeHookCommands returns the SessionStart commands in a settings file.
func claudeHookCommands(t *testing.T, path string) []string {
	t.Helper()
	settings, err := parseSettings([]byte(read(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, g := range sessionStartGroups(settings) {
		for _, h := range hookList(g) {
			cmd, _ := h["command"].(string)
			out = append(out, cmd)
		}
	}
	return out
}

func TestClaudeHookPutsShimsFirstOnPathForLaterCommands(t *testing.T) {
	requirePOSIX(t)
	root := t.TempDir()
	dir := filepath.Join(root, "it's shims")
	settings := filepath.Join(root, "settings.json")
	if _, err := WriteClaudeHook(settings, dir); err != nil {
		t.Fatal(err)
	}
	cmds := claudeHookCommands(t, settings)
	if len(cmds) != 1 {
		t.Fatalf("hook commands = %v, want one", cmds)
	}

	envFile := filepath.Join(root, "claude-env")
	hook := exec.Command("sh", "-c", cmds[0])
	hook.Env = append(os.Environ(), "CLAUDE_ENV_FILE="+envFile)
	if out, err := hook.CombinedOutput(); err != nil {
		t.Fatalf("hook failed: %v\n%s", err, out)
	}

	// Claude Code runs the env file before every Bash command; running it twice
	// in one shell must not stack a second entry.
	bash := exec.Command("sh", "-c", `. "$1"; . "$1"; printf '%s' "$PATH"`, "sh", envFile)
	bash.Env = append(os.Environ(), "PATH=/usr/bin:/bin")
	out, err := bash.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), dir+":/usr/bin:/bin"; got != want {
		t.Fatalf("PATH = %q, want %q", got, want)
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

func TestWriteClaudeHookKeepsTheUsersSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	user := `{
  "model": "opus",
  "hooks": {
    "SessionStart": [{"matcher": "startup", "hooks": [{"type": "command", "command": "echo mine"}]}],
    "Stop": [{"hooks": [{"type": "command", "command": "echo stop"}]}]
  }
}`
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
	cmds := claudeHookCommands(t, path)
	if len(cmds) != 2 || cmds[0] != "echo mine" || !strings.Contains(cmds[1], "'/b'") {
		t.Fatalf("SessionStart commands = %q, want the user's hook then ours for /b", cmds)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want the user's 0600 kept", fi.Mode().Perm())
	}

	if removed, err := RemoveClaudeHook(path); err != nil || !removed {
		t.Fatalf("remove = %v, %v", removed, err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(read(t, path)), &got); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(user), &want)
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("after uninstall:\n%s\nwant the original settings:\n%s", gotJSON, wantJSON)
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

func TestInstallAgentHookIsRepointedAndUninstalled(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	t.Setenv(claudeConfigDirEnv, "")
	settings := filepath.Join(s.home, ".claude", "settings.json")

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
		t.Fatalf("hook not re-pointed at %s: %v", moved.Dir, claudeHookCommands(t, settings))
	}

	res, err = Uninstall(moved)
	if err != nil {
		t.Fatal(err)
	}
	if HasClaudeHook(settings) || !contains(res.Profiles, settings) {
		t.Fatalf("uninstall left the hook (reported %v)", res.Profiles)
	}
}

func TestFlaglessReinstallSurvivesBrokenAgentSettings(t *testing.T) {
	requirePOSIX(t)
	s := newSandbox(t)
	t.Setenv(claudeConfigDirEnv, "")
	settings := filepath.Join(s.home, ".claude", "settings.json")
	mkdirs(t, filepath.Dir(settings))
	broken := `{"note": "` + agentHookMarker + `",`
	if err := os.WriteFile(settings, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(s.opts()); err != nil {
		t.Fatalf("upgrade failed over a broken agent settings file: %v", err)
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
