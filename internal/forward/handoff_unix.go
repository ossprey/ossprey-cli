//go:build !windows

package forward

import (
	"context"
	"syscall"

	"github.com/ossprey/ossprey-cli/internal/shim"
)

// Handoff replaces this process with the real manager instead of running it as
// a child. Use it only where nothing of ours runs afterwards: with the fork
// gone the manager keeps our PID, so `ps`, process monitors and a script's own
// `$PPID` see `npm` rather than `ossprey`, and signals, the terminal and the
// exit status reach it directly.
//
// Nothing after a successful exec runs, including defers, so the caller must
// have flushed warnings and removed its temp files first. The argv[0] is the
// bare manager name, as it would have been had the shell launched it.
//
// syscall.Exec returns only on failure (ENOEXEC, EACCES, ...). That is not a
// reason to fail an install, so it falls back to running the manager as a
// child, which is what every path did before.
func Handoff(ctx context.Context, bin string, args []string) error {
	path, err := shim.LookPathReal(bin)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	argv := append([]string{bin}, args...)
	_ = syscall.Exec(path, argv, envWithoutMonitorID())
	return Exec(ctx, bin, args)
}
