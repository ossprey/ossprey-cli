//go:build windows

package forward

import "context"

// Handoff runs the real manager as a child: Windows has no exec(2) to replace
// the process with, so the process name stays ossprey.exe there.
func Handoff(ctx context.Context, bin string, args []string) error {
	return Exec(ctx, bin, args)
}
