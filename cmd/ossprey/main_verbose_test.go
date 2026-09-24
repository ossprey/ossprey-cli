package main

import (
	"testing"

	"github.com/spf13/cobra"
)

// Cobra reports a flag as Changed whenever it appears on the command line,
// value included, so `--verbose=false` is both changed and false. Keying the
// verbosity switch on Changed alone turned detail on for someone explicitly
// turning it off.
func TestVerboseRequested(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--verbose"}, true},
		{[]string{"-v"}, true},
		{[]string{"--verbose=true"}, true},
		{[]string{"--verbose=false"}, false},
	}
	for _, tc := range tests {
		cmd := &cobra.Command{Use: "scan"}
		var verbose bool
		cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "")
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatalf("args %v: %v", tc.args, err)
		}
		if got := verboseRequested(cmd); got != tc.want {
			t.Errorf("verboseRequested(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// A command without the flag must not panic or claim verbosity.
func TestVerboseRequestedOnACommandWithoutTheFlag(t *testing.T) {
	if verboseRequested(&cobra.Command{Use: "login"}) {
		t.Error("a command with no --verbose flag must not report verbose")
	}
}
