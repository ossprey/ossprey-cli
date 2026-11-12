//go:build unix

package catalog

import "syscall"

// oNonblock lets an open return at once on a FIFO with no writer, so the file can be refused instead of waited on.
const oNonblock = syscall.O_NONBLOCK
