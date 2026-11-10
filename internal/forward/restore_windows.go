//go:build windows

package forward

import (
	"io/fs"
	"os"
)

// oneLink is true on Windows, where a staged copy replaces the file whenever it can be made.
func oneLink(fs.FileInfo) bool { return true }

// ownAs is true on Windows, where a staged copy is not given an owner.
func ownAs(*os.File, fs.FileInfo) bool { return true }

// sameOwner is true on Windows, where ownership is not compared.
func sameOwner(a, b fs.FileInfo) bool { return true }
