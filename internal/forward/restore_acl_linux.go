//go:build linux

package forward

import "syscall"

// hasACL reports whether p carries a POSIX access ACL, which a renamed copy would not keep.
func hasACL(p string) bool {
	n, err := syscall.Getxattr(p, "system.posix_acl_access", nil)
	return err == nil && n > 0
}
