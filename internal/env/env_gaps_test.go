package env

import (
	"testing"

	"github.com/ossprey/ossprey-cli/internal/monitor"
)

// Both spellings switch passive mode on, and either alone is enough.
func TestPassiveReadsBothSpellings(t *testing.T) {
	tests := []struct {
		passive, legacy string
		want            bool
	}{
		{"", "", false},
		{"1", "", true},
		{"yes", "", true},
		{"", "true", true},
		{"0", "1", true},
		{"off", "no", false},
	}
	for _, tt := range tests {
		t.Setenv(PassiveEnv, tt.passive)
		t.Setenv(CacheScanOnlyEnv, tt.legacy)
		if got := Passive(); got != tt.want {
			t.Errorf("%s=%q %s=%q: Passive() = %v, want %v", PassiveEnv, tt.passive, CacheScanOnlyEnv, tt.legacy, got, tt.want)
		}
	}
}

// A monitor id read from a file or a CI secret commonly carries a trailing
// newline; it must still validate rather than fail on whitespace.
func TestMonitorIDTrimsWhitespace(t *testing.T) {
	id := monitor.Prefix + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, raw := range []string{id, id + "\n", "  " + id + "\r\n", "\t" + id} {
		t.Setenv(MonitorIDEnv, raw)
		got := MonitorID()
		if got != id || !monitor.ValidToken(got) {
			t.Errorf("%s=%q: MonitorID() = %q, want %q", MonitorIDEnv, raw, got, id)
		}
	}
	t.Setenv(MonitorIDEnv, "   ")
	if got := MonitorID(); got != "" {
		t.Errorf("blank %s: MonitorID() = %q, want empty", MonitorIDEnv, got)
	}
}

func TestVerbose(t *testing.T) {
	for in, want := range map[string]bool{"": false, "0": false, "False": false, "1": true, "debug": true} {
		t.Setenv(VerboseEnv, in)
		if got := Verbose(); got != want {
			t.Errorf("%s=%q: Verbose() = %v, want %v", VerboseEnv, in, got, want)
		}
	}
}
