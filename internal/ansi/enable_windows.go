//go:build windows

package ansi

import (
	"io"

	"golang.org/x/sys/windows"
)

func Enable(w io.Writer) {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok {
		return
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
