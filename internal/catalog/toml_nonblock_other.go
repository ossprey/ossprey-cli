//go:build !unix

package catalog

// oNonblock is zero where an open cannot block on a FIFO.
const oNonblock = 0
