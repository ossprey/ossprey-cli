package monitor

import (
	"strings"
	"testing"
)

// ValidToken is the guard in front of a URL path and a generated /bin/sh file,
// so its edges are pinned shape by shape.
func TestValidTokenBoundaries(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"canonical", Prefix + hex64, true},
		{"all f", Prefix + strings.Repeat("f", 64), true},
		{"empty", "", false},
		{"prefix only", Prefix, false},
		{"63 hex", Prefix + hex64[:63], false},
		{"65 hex", Prefix + hex64 + "0", false},
		{"uppercase hex", Prefix + strings.ToUpper(hex64), false},
		{"one uppercase char", Prefix + "A" + hex64[1:], false},
		{"uppercase prefix", "OSPI_" + hex64, false},
		{"api key prefix", "ospy_" + hex64, false},
		{"no prefix", hex64, false},
		{"trailing newline", Prefix + hex64 + "\n", false},
		{"trailing CRLF", Prefix + hex64 + "\r\n", false},
		{"leading space", " " + Prefix + hex64, false},
		{"trailing space", Prefix + hex64 + " ", false},
		{"embedded newline", Prefix + hex64[:32] + "\n" + hex64[32:], false},
		{"slash", Prefix + hex64[:63] + "/", false},
		{"path traversal", Prefix + hex64 + "/../x", false},
		{"query", Prefix + hex64 + "?a=1", false},
		{"fragment", Prefix + hex64 + "#x", false},
		{"percent encoded", Prefix + hex64[:61] + "%2f", false},
		{"shell metachar", Prefix + hex64[:63] + "$", false},
		{"backtick", Prefix + hex64[:63] + "`", false},
		{"semicolon", Prefix + hex64[:63] + ";", false},
		{"quote", Prefix + hex64[:63] + "'", false},
		{"non-hex letter", Prefix + hex64[:63] + "g", false},
		{"unicode digit", Prefix + hex64[:63] + "٣", false},
		{"two tokens", Prefix + hex64 + Prefix + hex64, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidToken(tt.token); got != tt.want {
				t.Errorf("ValidToken(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

// The redacted form must never itself pass as a token, or a log line could be
// pasted back as a working credential.
func TestRedactedTokenIsNotValid(t *testing.T) {
	full := Prefix + strings.Repeat("ab", 32)
	if !ValidToken(full) {
		t.Fatalf("fixture %q should be valid", full)
	}
	if got := Redact(full); ValidToken(got) {
		t.Errorf("Redact(%q) = %q, which still validates", full, got)
	}
}
