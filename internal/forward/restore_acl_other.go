//go:build !linux

package forward

// hasACL is false where ACLs are not read, so macOS keeps an ACL only when the restore writes in place.
func hasACL(string) bool { return false }
