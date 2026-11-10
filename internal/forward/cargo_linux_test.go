//go:build linux

package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
)

// testACL is a POSIX ACL of version 2, then user::rw-, user:65534:rw-, group::r--, mask::rw-, other::r--.
func testACL() []byte {
	acl := []byte{2, 0, 0, 0}
	for _, e := range [][3]uint32{{1, 6, 0xffffffff}, {2, 6, 65534}, {4, 4, 0xffffffff}, {0x10, 6, 0xffffffff}, {0x20, 4, 0xffffffff}} {
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[0]))
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[1]))
		acl = binary.LittleEndian.AppendUint32(acl, e[2])
	}
	return acl
}

// A lock carrying a POSIX access ACL is restored in place, since a renamed copy would drop the ACL cargo's own write keeps (OSS-2553).
func TestRunCargoUpdate_RestoreKeepsAnAccessACL(t *testing.T) {
	const oldLock = "version = 4\n# before\n"
	_, ws := cargoProject(t)
	writeFile(t, ws.Lock, oldLock)
	if err := syscall.Setxattr(ws.Lock, "system.posix_acl_access", testACL(), 0); err != nil {
		t.Skipf("no POSIX ACLs here: %v", err)
	}
	fi, err := os.Stat(ws.Lock)
	if err != nil {
		t.Fatal(err)
	}
	swap(t, func(context.Context, string, []string) error {
		f, err := os.OpenFile(ws.Lock, os.O_WRONLY|os.O_TRUNC, 0)
		if err == nil {
			_, err = f.WriteString(evilLock)
			f.Close()
		}
		return err
	}, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return evilSBOM(), nil })

	if _, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}}); !errors.Is(err, ErrBlocked) {
		t.Fatalf("Run = %v, want ErrBlocked", err)
	}
	now, err := os.Stat(ws.Lock)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, ws.Lock); got != oldLock || !os.SameFile(fi, now) {
		t.Errorf("lock = %q (same file %v), want the old bytes written in place", got, os.SameFile(fi, now))
	}
	if n, err := syscall.Getxattr(ws.Lock, "system.posix_acl_access", nil); err != nil || n == 0 {
		t.Errorf("access ACL gone after the restore (%v)", err)
	}
}

// A lock with no ACL in a directory with a default ACL is restored in place, since a staged copy would inherit an ACL the lock never had (OSS-2553).
func TestRunCargoUpdate_RestoreAddsNoInheritedACL(t *testing.T) {
	const oldLock = "version = 4\n# before\n"
	root, ws := cargoProject(t)
	writeFile(t, ws.Lock, oldLock)
	if err := os.Chmod(ws.Lock, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setxattr(root, "system.posix_acl_default", testACL(), 0); err != nil {
		t.Skipf("no POSIX ACLs here: %v", err)
	}
	fi, err := os.Stat(ws.Lock)
	if err != nil {
		t.Fatal(err)
	}
	swap(t, func(context.Context, string, []string) error {
		f, err := os.OpenFile(ws.Lock, os.O_WRONLY|os.O_TRUNC, 0)
		if err == nil {
			_, err = f.WriteString(evilLock)
			f.Close()
		}
		return err
	}, cleanSBOM)
	swapScan(t, func(context.Context, scanRequest) (*ossbom.SBOM, error) { return evilSBOM(), nil })

	if _, err := quietOutput(t, context.Background(), Options{Bin: "cargo", Args: []string{"update"}}); !errors.Is(err, ErrBlocked) {
		t.Fatalf("Run = %v, want ErrBlocked", err)
	}
	now, err := os.Stat(ws.Lock)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, ws.Lock); got != oldLock || !os.SameFile(fi, now) || now.Mode().Perm() != 0o640 {
		t.Errorf("lock = %q, mode %v (same file %v), want the old bytes and mode written in place", got, now.Mode().Perm(), os.SameFile(fi, now))
	}
	if n, err := syscall.Getxattr(ws.Lock, "system.posix_acl_access", nil); err == nil || n > 0 {
		t.Errorf("the restored lock has an access ACL of %d bytes it never had", n)
	}
	if entries, _ := os.ReadDir(root); slices.ContainsFunc(entries, func(e os.DirEntry) bool { return strings.Contains(e.Name(), "ossprey") }) {
		t.Errorf("a staged copy was left in %v", entries)
	}
}

// An ACL that grows or goes between the size probe and the read counts as unreadable, never a panic (OSS-2553).
func TestReadACLChangingBetweenCallsIsUnreadable(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ERANGE, syscall.ENODATA} {
		calls := 0
		got, ok := readACL(func(b []byte) (int, error) {
			if calls++; calls == 1 {
				return 8, nil
			}
			return -1, errno
		})
		if ok || got != nil {
			t.Errorf("%v on the read: readACL = %v, %v; want nil, false", errno, got, ok)
		}
	}
}
