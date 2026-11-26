// Package config holds the machine's scan settings, today the paths every
// project scan leaves out: config.json beside credentials.json, plus the
// environment. It is never read from the
// repository being scanned, for the same reason trust.json is not: an ignore
// pattern is a hole in the scan, and a pull request must not be able to open
// one for itself.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// IgnoreEnv adds ignore patterns from the environment, for CI and other
// machines where writing config.json is awkward. Comma or newline separated,
// so a pattern may hold a space.
const IgnoreEnv = "OSSPREY_SCAN_IGNORE"

// KeyScanIgnore is the one setting `ossprey config` reads and writes.
const KeyScanIgnore = "scan.ignore"

// Settings is config.json. The file is nested by area so a later setting
// has somewhere to go without a new file.
type Settings struct {
	Scan Scan `json:"scan"`
}

// Scan holds the settings that shape a project scan.
type Scan struct {
	Ignore []string `json:"ignore,omitempty"`
}

// Empty reports whether nothing is set.
func (s Settings) Empty() bool { return len(s.Scan.Ignore) == 0 }

// Path returns the settings file: $OSSPREY_CONFIG_DIR/config.json when set,
// else <user config dir>/ossprey/config.json, beside credentials.json.
func Path() (string, error) {
	if dir := os.Getenv("OSSPREY_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "config.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(dir, "ossprey", "config.json"), nil
}

// Load returns the stored settings with OSSPREY_SCAN_IGNORE's patterns added.
//
// It always returns the usable part. A non-nil error means some of it was
// not usable, and the caller should say so and carry on: a pattern dropped
// here only means more is scanned, so nothing is skipped that the user did
// not ask to skip.
func Load() (Settings, error) {
	file, fileErr := LoadFile()
	fromEnv, envErr := FromEnv()
	merged := file
	merged.Scan.Ignore = union(file.Scan.Ignore, fromEnv.Scan.Ignore)
	return merged, errors.Join(fileErr, envErr)
}

// LoadFile reads config.json. A missing file is empty settings, not an error.
// An unknown key is an error, so that `config add` and friends refuse to
// rewrite a file written by a newer ossprey (or holding a typo) and lose it.
func LoadFile() (Settings, error) {
	p, err := Path()
	if err != nil {
		return Settings{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("read config: %w", err)
	}
	var raw Settings
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		// Read again leniently, so a runtime load still keeps what it can.
		var lenient Settings
		_ = json.Unmarshal(data, &lenient)
		s, _ := validate(lenient)
		return s, fmt.Errorf("parse config %s: %w", p, err)
	}
	// Re-validated on the way in, not just on `config add`: the file is plain
	// JSON and anyone can edit it.
	s, err := validate(raw)
	if err != nil {
		err = fmt.Errorf("config %s: %w", p, err)
	}
	return s, err
}

// FromEnv reads OSSPREY_SCAN_IGNORE.
func FromEnv() (Settings, error) {
	var s Settings
	var errs []error
	for _, p := range splitPatterns(os.Getenv(IgnoreEnv)) {
		n, err := NormalizeIgnore(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", IgnoreEnv, err))
			continue
		}
		s.Scan.Ignore = union(s.Scan.Ignore, []string{n})
	}
	return s, errors.Join(errs...)
}

// Save writes settings to config.json, creating the config directory.
func Save(s Settings) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	// Through a temp file and a rename, as auth.Save does: an interrupted
	// write must not leave a truncated file that the next run reads as empty.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".config-*.json")
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// NormalizeIgnore validates an ignore pattern and returns it in the form
// stored and matched: a doublestar glob relative to the scanned directory,
// with "/" separators, no leading "./" and no trailing "/".
//
// Patterns are anchored at the scanned directory: `wf` is the top-level wf
// directory and `*.md` the top-level markdown files; `**/fixtures` is a
// fixtures directory at any depth. A matching directory is skipped whole.
//
// Refused: an absolute path or one climbing out with "..", since the pattern
// names part of the project and either would mean something else on every
// machine; a backslash, which doublestar reads as an escape rather than a
// separator; and a pattern made only of wildcards (`*`, `**`, `**/*`), which
// would skip the whole project and turn every scan into a clean result that
// checked nothing.
func NormalizeIgnore(pattern string) (string, error) {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return "", errors.New("an ignore pattern cannot be empty")
	}
	if strings.Contains(p, `\`) {
		return "", fmt.Errorf("ignore pattern %q: use / as the path separator", pattern)
	}
	if strings.HasPrefix(p, "/") || filepath.IsAbs(p) || (len(p) > 1 && p[1] == ':') {
		return "", fmt.Errorf("ignore pattern %q: patterns are relative to the scanned directory, not absolute", pattern)
	}
	for strings.HasPrefix(p, "./") {
		p = strings.TrimLeft(strings.TrimPrefix(p, "./"), "/")
	}
	p = strings.TrimRight(p, "/")
	segments := strings.Split(p, "/")
	if p == "" || p == "." {
		return "", fmt.Errorf("ignore pattern %q would skip the whole project", pattern)
	}
	onlyWildcards := true
	for _, s := range segments {
		if s == "" || s == "." {
			return "", fmt.Errorf("ignore pattern %q: empty or '.' path segment", pattern)
		}
		if s == ".." {
			return "", fmt.Errorf("ignore pattern %q: '..' would leave the scanned directory", pattern)
		}
		if strings.Trim(s, "*") != "" {
			onlyWildcards = false
		}
	}
	if onlyWildcards {
		return "", fmt.Errorf("ignore pattern %q would skip the whole project", pattern)
	}
	if !doublestar.ValidatePattern(p) {
		return "", fmt.Errorf("ignore pattern %q is not a valid glob", pattern)
	}
	return p, nil
}

// validate keeps the valid parts of s and reports the rest.
func validate(s Settings) (Settings, error) {
	var out Settings
	var errs []error
	for _, p := range s.Scan.Ignore {
		n, err := NormalizeIgnore(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out.Scan.Ignore = union(out.Scan.Ignore, []string{n})
	}
	return out, errors.Join(errs...)
}

func splitPatterns(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// union appends b's entries missing from a, keeping a's order.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// Without returns patterns with drop's entries removed.
func Without(patterns, drop []string) []string {
	return slices.DeleteFunc(slices.Clone(patterns), func(p string) bool { return slices.Contains(drop, p) })
}
