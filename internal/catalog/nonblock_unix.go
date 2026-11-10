//go:build !windows

package catalog

import "syscall"

// ONonblock lets an open return at once on a FIFO with no writer, so the file can be refused instead of waited on.
const ONonblock = syscall.O_NONBLOCK
