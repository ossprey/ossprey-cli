package ansi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Precedence: NO_COLOR / TERM=dumb > FORCE_COLOR > CLICOLOR_FORCE > CI viewer > TTY.
func TestDetectPrecedence(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want Profile
	}{
		{"NO_COLOR beats CLICOLOR_FORCE", map[string]string{"NO_COLOR": "1", "CLICOLOR_FORCE": "1"}, None},
		{"TERM=dumb beats FORCE_COLOR", map[string]string{"TERM": "dumb", "FORCE_COLOR": "1"}, None},
		{"CLICOLOR_FORCE on a pipe", map[string]string{"CLICOLOR_FORCE": "1"}, Basic},
		{"CLICOLOR_FORCE takes depth", map[string]string{"CLICOLOR_FORCE": "1", "COLORTERM": "24bit"}, TrueColor},
		{"CLICOLOR_FORCE=0 is not forcing", map[string]string{"CLICOLOR_FORCE": "0"}, None},
		{"CLICOLOR_FORCE=0 still allows CI", map[string]string{"CLICOLOR_FORCE": "0", "GITLAB_CI": "true"}, Basic},
		{"FORCE_COLOR=false disables", map[string]string{"FORCE_COLOR": "FALSE", "GITHUB_ACTIONS": "true"}, None},
		{"FORCE_COLOR=0 beats CLICOLOR_FORCE", map[string]string{"FORCE_COLOR": "0", "CLICOLOR_FORCE": "1"}, None},
		{"FORCE_COLOR depth beats the CI default", map[string]string{"FORCE_COLOR": "1", "GITHUB_ACTIONS": "true", "COLORTERM": "truecolor"}, TrueColor},
		{"CI viewer ignores depth hints", map[string]string{"BUILDKITE": "true", "COLORTERM": "truecolor", "TERM": "xterm-256color"}, Basic},
		{"COLORTERM is case-insensitive", map[string]string{"FORCE_COLOR": "1", "COLORTERM": "TrueColor"}, TrueColor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if got := Detect(&bytes.Buffer{}); got != tt.want {
				t.Errorf("Detect = %v, want %v", got, tt.want)
			}
		})
	}
}

// A redirect to a regular file has an Fd but is not a terminal.
func TestDetectRegularFileIsNone(t *testing.T) {
	clearEnv(t)
	t.Setenv("TERM", "xterm-256color")
	f, err := os.Create(filepath.Join(t.TempDir(), "out.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got := Detect(f); got != None {
		t.Errorf("Detect(regular file) = %v, want None", got)
	}
}

// Styling an empty string emits nothing, so a blank cell cannot leave a bare
// reset sequence behind.
func TestStylesOfEmptyAreEmpty(t *testing.T) {
	for _, p := range []Profile{Basic, ANSI256, TrueColor} {
		if got := p.Bold("") + p.Dim("") + p.Red("") + p.RGB(1, 2, 3, ""); got != "" {
			t.Errorf("%v: got %q, want empty", p, got)
		}
	}
}
