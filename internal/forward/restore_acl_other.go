//go:build !linux

package forward

import "os"

// hasACL is false where ACLs are not read, so macOS keeps an ACL only when the restore writes in place.
func hasACL(string) bool { return false }

// sameACL is true where ACLs are not read.
func sameACL(*os.File, string) bool { return true }
