//go:build smoke

package smoke

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPassThroughReplacesTheProcess proves a pass-through command (`npm run
// start`) leaves no ossprey process behind: the manager runs under the PID the
// shell launched, so process listings and parent-PID checks see npm.
//
// A stand-in `npm` prints its own PID. If ossprey forked it, that PID would
// differ from the one we started; if ossprey replaced itself, they match.
func TestPassThroughReplacesTheProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no exec(2); the forwarder keeps ossprey as the parent there")
	}

	bin := t.TempDir()
	fake := "#!/bin/sh\necho \"pid=$$ args=$*\"\n"
	if err := os.WriteFile(filepath.Join(bin, "npm"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}

	env := forwardEnv(t.TempDir(), "http://127.0.0.1:1", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd := exec.Command(binPath, "npm", "run", "start")
	cmd.Dir = t.TempDir()
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("npm run start: %v\nstderr: %s", err, stderr.String())
	}

	want := fmt.Sprintf("pid=%d args=run start", pid)
	if got := strings.TrimSpace(stdout.String()); got != want {
		t.Errorf("manager output = %q, want %q (ossprey forked instead of replacing itself)\nstderr: %s",
			got, want, stderr.String())
	}
}
