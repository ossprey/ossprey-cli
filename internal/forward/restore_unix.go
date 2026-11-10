//go:build !windows

package forward

import (
	"io/fs"
	"os"
	"syscall"
)

// oneLink reports whether fi has one name, since a copy renamed over a file with more leaves the others as they were.
func oneLink(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 1
}

// ownAs gives a staged copy the owner and group of fi, which a write in place keeps, and reports whether it has them.
func ownAs(tmp *os.File, fi fs.FileInfo) bool {
	got, err := tmp.Stat()
	if err != nil {
		return false
	}
	if sameOwner(got, fi) {
		return true
	}
	have, ok := got.Sys().(*syscall.Stat_t)
	want, ok2 := fi.Sys().(*syscall.Stat_t)
	if !ok || !ok2 {
		return false
	}
	// Only root may give a file away, so the owner is left as it is when it already matches.
	uid := int(want.Uid)
	if have.Uid == want.Uid {
		uid = -1
	}
	return tmp.Chown(uid, int(want.Gid)) == nil
}

// sameOwner reports whether a and b have the same owner and group.
func sameOwner(a, b fs.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok && ok2 && x.Uid == y.Uid && x.Gid == y.Gid
}
