package shim

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// AgentClaude is Claude Code. Its Bash tool runs non-interactive, non-login
// shells, which read no shell profile, so the profile PATH block never reaches
// it. A SessionStart hook that appends to $CLAUDE_ENV_FILE does: Claude Code
// runs that file before every Bash command it runs.
const AgentClaude = "claude"

// agentHookMarker identifies the hook we wrote, and the line it writes, so a
// re-run replaces it and uninstall removes it without touching anyone else's.
const agentHookMarker = "# ossprey-shim-path"

// claudeConfigDirEnv relocates Claude Code's user settings.
const claudeConfigDirEnv = "CLAUDE_CONFIG_DIR"

func SupportedAgents() []string { return []string{AgentClaude} }

func ValidateAgents(names []string) error {
	for _, n := range names {
		if !slices.Contains(SupportedAgents(), n) {
			return fmt.Errorf("unknown agent %q (supported: %s)", n, strings.Join(SupportedAgents(), ", "))
		}
	}
	return nil
}

// agentsUnsupported is the warning for --agent on Windows, where the user PATH
// already reaches every process and the hook would be a POSIX snippet.
const agentsUnsupported = "--agent is not needed on Windows: the user PATH already reaches agents. Nothing was changed for it."

func ClaudeSettingsPath(home string) string {
	if d := os.Getenv(claudeConfigDirEnv); d != "" {
		return filepath.Join(d, "settings.json")
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// claudeHookCommand makes the shim directory the first PATH entry for every
// later Bash command, and does nothing outside a session that provides
// CLAUDE_ENV_FILE. The env file line moves an existing entry to the front
// rather than skipping it, since an inherited PATH may carry the shims behind
// nvm's or a venv's bin. The hook also fires on resume, clear and compact, so
// it appends only once per env file.
func claudeHookCommand(dir string) string {
	q := shellQuote(dir)
	line := `case ":$PATH:" in :` + q + `:*) ;; *) _osp=; _osi=$IFS; IFS=:; set -f; ` +
		`for _ose in $PATH; do [ "$_ose" = ` + q + ` ] || _osp="$_osp:$_ose"; done; ` +
		`set +f; IFS=$_osi; export PATH=` + q + `"$_osp"; unset _osp _osi _ose ;; esac ` + agentHookMarker
	return `[ -z "${CLAUDE_ENV_FILE:-}" ] || grep -qsF ` + shellQuote(agentHookMarker) + ` "$CLAUDE_ENV_FILE" || printf '%s\n' ` +
		shellQuote(line) + ` >> "$CLAUDE_ENV_FILE" ` + agentHookMarker
}

// errSettingsUnparsable is returned for a settings file carrying our hook
// marker that no longer parses. Callers re-pointing or removing the hook treat
// it as a warning: the user's hand edit must not fail an upgrade or uninstall.
var errSettingsUnparsable = errors.New("not valid JSON")

// claudeHookCommands returns our hook commands in path. A
// missing file has none; a file mentioning our marker that does not parse
// returns errSettingsUnparsable.
func claudeHookCommands(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	s, err := parseSettings(b)
	if err != nil {
		if bytes.Contains(b, []byte(agentHookMarker)) {
			return nil, fmt.Errorf("%s: %w", path, errSettingsUnparsable)
		}
		return nil, nil
	}
	var ours []string
	for _, cmd := range s.hookCommands() {
		if isOurs(cmd) {
			ours = append(ours, cmd)
		}
	}
	return ours, nil
}

// HasClaudeHook reports whether path carries one of our SessionStart hooks.
func HasClaudeHook(path string) bool {
	cmds, _ := claudeHookCommands(path)
	return len(cmds) > 0
}

// hasClaudeHookFor reports whether path carries our hook for exactly dir.
func hasClaudeHookFor(path, dir string) bool {
	cmds, _ := claudeHookCommands(path)
	return slices.Contains(cmds, claudeHookCommand(dir))
}

// WriteClaudeHook adds (or re-points) our SessionStart hook, keeping every
// other setting, its key order and its numbers. It refuses to rewrite a file it
// cannot parse, since writing back only what parsed would delete the rest.
func WriteClaudeHook(path, dir string) (bool, error) {
	old, s, err := readSettings(path)
	if err != nil {
		return false, err
	}
	ours, err := encodeJSON(map[string]any{
		"hooks": []any{map[string]any{"type": "command", "command": claudeHookCommand(dir)}},
	})
	if err != nil {
		return false, err
	}
	if err := s.setSessionStart(append(withoutOurHook(s.sessionStart()), ours)); err != nil {
		return false, err
	}
	return writeSettings(path, old, s)
}

func RemoveClaudeHook(path string) (bool, error) {
	if _, err := claudeHookCommands(path); err != nil {
		return false, err
	}
	if !HasClaudeHook(path) {
		return false, nil
	}
	old, s, err := readSettings(path)
	if err != nil {
		return false, err
	}
	if err := s.setSessionStart(withoutOurHook(s.sessionStart())); err != nil {
		return false, err
	}
	return writeSettings(path, old, s)
}

func readSettings(path string) ([]byte, *settings, error) {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	s, err := parseSettings(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not valid JSON, leaving it untouched: %w", path, err)
	}
	return b, s, nil
}

func writeSettings(path string, old []byte, s *settings) (bool, error) {
	out, err := s.marshal()
	if err != nil {
		return false, err
	}
	if bytes.Equal(out, old) {
		return false, nil
	}
	if err := writeFileAtomic(path, out, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// writeFileAtomic replaces path through a temp file and a rename, so Claude
// Code, which writes this file too, never reads a half-written one and a failed
// write leaves the original intact. A symlinked file (a dotfiles repo) is
// written at its target so the link survives.
func writeFileAtomic(path string, data []byte, def os.FileMode) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	mode := def
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".ossprey-*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// settings is a JSON object that keeps its keys in file order and its values
// as raw bytes, so editing hooks.SessionStart leaves every other value as the
// user wrote it. Only whitespace is normalised, to two-space indentation.
type settings struct{ fields []field }

type field struct {
	key   string
	value json.RawMessage
}

func parseSettings(b []byte) (*settings, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return &settings{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	s, err := decodeObject(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the settings object")
	}
	return s, nil
}

func decodeObject(dec *json.Decoder) (*settings, error) {
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("settings is not a JSON object")
	}
	s := &settings{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		s.fields = append(s.fields, field{key, raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *settings) get(key string) (json.RawMessage, bool) {
	for _, f := range s.fields {
		if f.key == key {
			return f.value, true
		}
	}
	return nil, false
}

func (s *settings) set(key string, v json.RawMessage) {
	for i := range s.fields {
		if s.fields[i].key == key {
			s.fields[i].value = v
			return
		}
	}
	s.fields = append(s.fields, field{key, v})
}

func (s *settings) remove(key string) {
	s.fields = slices.DeleteFunc(s.fields, func(f field) bool { return f.key == key })
}

func (s *settings) marshal() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range s.fields {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(f.key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(f.value)
	}
	b.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, b.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func (s *settings) hooks() *settings {
	raw, ok := s.get("hooks")
	if !ok {
		return &settings{}
	}
	h, err := decodeObject(json.NewDecoder(bytes.NewReader(raw)))
	if err != nil {
		return &settings{}
	}
	return h
}

// sessionStart returns the SessionStart matcher groups, each still raw so a
// group we do not touch is written back exactly as it was.
func (s *settings) sessionStart() []json.RawMessage {
	raw, ok := s.hooks().get("SessionStart")
	if !ok {
		return nil
	}
	var groups []json.RawMessage
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil
	}
	return groups
}

// hookGroup is the part of a matcher group we read.
type hookGroup struct {
	Hooks []json.RawMessage `json:"hooks"`
}

func groupCommands(raw json.RawMessage) []string {
	var g hookGroup
	if json.Unmarshal(raw, &g) != nil {
		return nil
	}
	var out []string
	for _, h := range g.Hooks {
		var c struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(h, &c) == nil && c.Command != "" {
			out = append(out, c.Command)
		}
	}
	return out
}

func (s *settings) hookCommands() []string {
	var out []string
	for _, g := range s.sessionStart() {
		out = append(out, groupCommands(g)...)
	}
	return out
}

func (s *settings) setSessionStart(groups []json.RawMessage) error {
	h := s.hooks()
	if len(groups) == 0 {
		h.remove("SessionStart")
	} else {
		raw, err := encodeJSON(groups)
		if err != nil {
			return err
		}
		h.set("SessionStart", raw)
	}
	if len(h.fields) == 0 {
		s.remove("hooks")
		return nil
	}
	raw, err := h.marshal()
	if err != nil {
		return err
	}
	s.set("hooks", bytes.TrimSpace(raw))
	return nil
}

func isOurs(cmd string) bool { return strings.HasSuffix(cmd, agentHookMarker) }

// withoutOurHook drops the groups holding only our hook. A group someone added
// our hook to by hand keeps its other hooks, re-encoded; every other group is
// returned byte for byte.
func withoutOurHook(groups []json.RawMessage) []json.RawMessage {
	var out []json.RawMessage
	for _, raw := range groups {
		if !slices.ContainsFunc(groupCommands(raw), isOurs) {
			out = append(out, raw)
			continue
		}
		var g map[string]json.RawMessage
		var gh hookGroup
		if json.Unmarshal(raw, &g) != nil || json.Unmarshal(raw, &gh) != nil {
			out = append(out, raw)
			continue
		}
		kept := slices.DeleteFunc(gh.Hooks, func(h json.RawMessage) bool {
			return slices.ContainsFunc(groupCommands(json.RawMessage(`{"hooks":[`+string(h)+`]}`)), isOurs)
		})
		if len(kept) == 0 {
			continue
		}
		g["hooks"], _ = encodeJSON(kept)
		if b, err := encodeJSON(g); err == nil {
			out = append(out, b)
		}
	}
	return out
}

func encodeJSON(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep the hook's `>>` readable
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

// agentSettings returns the agent settings files to write: those asked for,
// plus, unless PATH handling is off, one already carrying our hook, so a
// flagless re-run re-points it at a shim directory that may have moved.
func agentSettings(o Options, home string) []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	path := ClaudeSettingsPath(home)
	if slices.Contains(o.Agents, AgentClaude) {
		return []string{path}
	}
	if o.SkipProfiles {
		return nil
	}
	if _, err := claudeHookCommands(path); err != nil || HasClaudeHook(path) {
		return []string{path}
	}
	return nil
}
