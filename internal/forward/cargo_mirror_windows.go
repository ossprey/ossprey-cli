//go:build windows

package forward

// cargoSymlinkHint explains a link the mirror could not make.
const cargoSymlinkHint = "; Windows makes links only in Developer Mode or for a user granted the right to"

// privateDir accepts the user cache, which Windows keeps private by its ACL.
func privateDir(string) error { return nil }
