//go:build !windows

package main

import (
	"errors"
	"os/exec"
	"testing"
)

// A child killed by a signal exits as a shell reports it, 128 plus the signal, where ExitCode's -1 made os.Exit return 255 (OSS-2553).
func TestExitCodeOfASignalledChild(t *testing.T) {
	for script, want := range map[string]int{"kill -INT $$": 130, "kill -TERM $$": 143, "exit 3": 3} {
		var ee *exec.ExitError
		if err := exec.Command("sh", "-c", script).Run(); !errors.As(err, &ee) {
			t.Fatalf("sh -c %q: %v", script, err)
		}
		if got := exitCodeOf(ee); got != want {
			t.Errorf("sh -c %q: exit code %d, want %d", script, got, want)
		}
	}
}
