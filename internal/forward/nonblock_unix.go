//go:build !windows

package forward

import "syscall"

// oNonblock lets an open return at once on a FIFO with no writer, so the file can be refused instead of waited on.
const oNonblock = syscall.O_NONBLOCK
