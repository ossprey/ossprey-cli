//go:build !windows

package forward

import (
	"fmt"
	"os"
	"syscall"
)

// cargoSymlinkHint explains a link the mirror could not make; none is needed here.
const cargoSymlinkHint = ""

// privateDir fails unless p is a directory this user owns and no one else may write to, since a link planted in a mirror would lead cargo add into the project.
func privateDir(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is not a directory only you can write to", p)
	}
	return nil
}
