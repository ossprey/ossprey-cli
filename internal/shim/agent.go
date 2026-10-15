package shim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// AgentClaude is Claude Code. Its Bash tool runs non-interactive, non-login
// shells, which read no shell profile, so the profile PATH block never reaches
// it. A SessionStart hook that appends to $CLAUDE_ENV_FILE does: Claude Code
// sources that file before every Bash command it runs.
const AgentClaude = "claude"

// agentHookMarker identifies the hook we wrote, so a re-run replaces it and
// uninstall removes it without touching anyone else's hooks.
const agentHookMarker = "# ossprey-shim-path"

// claudeConfigDirEnv relocates Claude Code's user settings.
const claudeConfigDirEnv = "CLAUDE_CONFIG_DIR"

func SupportedAgents() []string { return []string{AgentClaude} }

// ValidateAgents rejects unknown names and agent hooks on Windows, where the
// hook is a POSIX shell snippet.
func ValidateAgents(names []string) error {
	for _, n := range names {
		if !slices.Contains(SupportedAgents(), n) {
			return fmt.Errorf("unknown agent %q (supported: %s)", n, strings.Join(SupportedAgents(), ", "))
		}
	}
	if len(names) > 0 && runtime.GOOS == "windows" {
		return fmt.Errorf("--agent is not supported on Windows yet; the user PATH already reaches agents there")
	}
	return nil
}

func ClaudeSettingsPath(home string) string {
	if d := os.Getenv(claudeConfigDirEnv); d != "" {
		return filepath.Join(d, "settings.json")
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// claudeHookCommand prepends dir to PATH for every later Bash command, and does
// nothing when run outside a session that provides CLAUDE_ENV_FILE. Claude Code
// runs the env file before each command, so the line only prepends once.
func claudeHookCommand(dir string) string {
	q := shellQuote(dir)
	line := `case ":$PATH:" in *:` + q + `:*) ;; *) export PATH=` + q + `:"$PATH" ;; esac`
	return `[ -z "${CLAUDE_ENV_FILE:-}" ] || printf '%s\n' ` + shellQuote(line) + ` >> "$CLAUDE_ENV_FILE" ` + agentHookMarker
}

func HasClaudeHook(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && bytes.Contains(b, []byte(agentHookMarker))
}

func hasClaudeHookFor(path, dir string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	settings, err := parseSettings(b)
	if err != nil {
		return false
	}
	want := claudeHookCommand(dir)
	for _, group := range sessionStartGroups(settings) {
		for _, h := range hookList(group) {
			if h["command"] == want {
				return true
			}
		}
	}
	return false
}

// WriteClaudeHook adds (or re-points) our SessionStart hook in settings.json,
// keeping every other setting and hook. It refuses to rewrite a file it cannot
// parse, since writing back only what parsed would delete the rest.
func WriteClaudeHook(path, dir string) (bool, error) {
	old, settings, err := readSettings(path)
	if err != nil {
		return false, err
	}
	groups := withoutOurHook(sessionStartGroups(settings))
	groups = append(groups, map[string]any{
		"hooks": []any{map[string]any{"type": "command", "command": claudeHookCommand(dir)}},
	})
	setSessionStart(settings, groups)
	return writeSettings(path, old, settings)
}

func RemoveClaudeHook(path string) (bool, error) {
	if !HasClaudeHook(path) {
		return false, nil
	}
	old, settings, err := readSettings(path)
	if err != nil {
		return false, err
	}
	setSessionStart(settings, withoutOurHook(sessionStartGroups(settings)))
	return writeSettings(path, old, settings)
}

func readSettings(path string) ([]byte, map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	settings, err := parseSettings(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not valid JSON, leaving it untouched: %w", path, err)
	}
	return b, settings, nil
}

func parseSettings(b []byte) (map[string]any, error) {
	settings := map[string]any{}
	if len(bytes.TrimSpace(b)) == 0 {
		return settings, nil
	}
	if err := json.Unmarshal(b, &settings); err != nil {
		return nil, err
	}
	return settings, nil
}

func writeSettings(path string, old []byte, settings map[string]any) (bool, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep the hook's `>>` readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(settings); err != nil {
		return false, err
	}
	out := buf.Bytes()
	if bytes.Equal(out, old) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := writeFilePreservingMode(path, out, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func sessionStartGroups(settings map[string]any) []any {
	hooks, _ := settings["hooks"].(map[string]any)
	groups, _ := hooks["SessionStart"].([]any)
	return groups
}

func setSessionStart(settings map[string]any, groups []any) {
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		if len(groups) == 0 {
			return
		}
		hooks = map[string]any{}
		settings["hooks"] = hooks
	}
	if len(groups) == 0 {
		delete(hooks, "SessionStart")
	} else {
		hooks["SessionStart"] = groups
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	}
}

func hookList(group any) []map[string]any {
	g, _ := group.(map[string]any)
	list, _ := g["hooks"].([]any)
	var out []map[string]any
	for _, h := range list {
		if m, ok := h.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// withoutOurHook drops our hook from each group, and any group it leaves empty.
func withoutOurHook(groups []any) []any {
	var out []any
	for _, group := range groups {
		g, ok := group.(map[string]any)
		list, isList := g["hooks"].([]any)
		if !ok || !isList {
			out = append(out, group)
			continue
		}
		var kept []any
		for _, h := range list {
			if m, ok := h.(map[string]any); ok {
				if cmd, _ := m["command"].(string); strings.Contains(cmd, agentHookMarker) {
					continue
				}
			}
			kept = append(kept, h)
		}
		if len(kept) == 0 {
			continue
		}
		g["hooks"] = kept
		out = append(out, g)
	}
	return out
}
