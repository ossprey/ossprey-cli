//go:build linux

package forward

import (
	"bytes"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const aclAccess = "system.posix_acl_access"

// hasACL reports whether p carries a POSIX access ACL, which a renamed copy would not keep.
func hasACL(p string) bool {
	n, err := syscall.Getxattr(p, aclAccess, nil)
	return err == nil && n > 0
}

// sameACL reports whether a staged copy has target's access ACL, or neither has one, since a copy made under a directory's default ACL inherits it.
func sameACL(tmp *os.File, target string) bool {
	a, okA := readACL(func(b []byte) (int, error) { return unix.Fgetxattr(int(tmp.Fd()), aclAccess, b) })
	b, okB := readACL(func(b []byte) (int, error) { return unix.Getxattr(target, aclAccess, b) })
	return okA && okB && bytes.Equal(a, b)
}

// readACL reads an access ACL through get, nil when there is none, and false when it cannot be read.
func readACL(get func([]byte) (int, error)) ([]byte, bool) {
	n, err := get(nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return nil, true
	}
	if err != nil {
		return nil, false
	}
	buf := make([]byte, n)
	n, err = get(buf)
	return buf[:n], err == nil
}
