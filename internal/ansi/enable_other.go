//go:build !windows

package ansi

import "io"

func Enable(io.Writer) {}
