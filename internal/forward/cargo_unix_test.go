//go:build !windows

package forward

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// A Cargo.lock that is a FIFO or a link to a device is never read, so a passive run whose cargo failed at once neither blocks nor reads without end (OSS-2553).
func TestRunCargo_PassiveReadsOnlyARegularLock(t *testing.T) {
	for name, mk := range map[string]func(string) error{
		"a FIFO":                 func(p string) error { return syscall.Mkfifo(p, 0o644) },
		"a symlink to /dev/zero": func(p string) error { return os.Symlink("/dev/zero", p) },
	} {
		t.Run(name, func(t *testing.T) {
			_, ws := cargoProject(t)
			if err := mk(ws.Lock); err != nil {
				t.Skipf("cannot make the lock: %v", err)
			}
			// Releases a reader blocked on the FIFO, so a failure ends the test instead of hanging it.
			t.Cleanup(func() {
				if f, err := os.OpenFile(ws.Lock, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					f.Close()
				}
			})
			// cargo 1.99.1 fails `add nosuchcrate` before it opens the lock.
			exit101 := errors.New("exit status 101")
			swap(t, func(context.Context, string, []string) error { return exit101 }, cleanSBOM)
			type result struct {
				out string
				err error
			}
			done := make(chan result, 1)
			go func() {
				out, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"add", "nosuchcrate"}, Passive: true})
				done <- result{out, err}
			}()
			select {
			case r := <-done:
				want := "ossprey: warning: could not post scan (read " + ws.Lock + ": not a regular file); the install was not blocked (passive)\n"
				if !errors.Is(r.err, exit101) || r.out != want {
					t.Errorf("Run = %v, output %q; want cargo's error and %q", r.err, r.out, want)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("Run did not return")
			}
		})
	}
}
