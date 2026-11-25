package env

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ScanDepthEnv limits how many directory levels a project scan reads: 1 is
// the scanned directory's own files, 0 the whole tree. It is `scan --depth`
// from the environment, and the only way to change a forwarder's depth, since
// forwarders parse no flags of their own.
const ScanDepthEnv = "OSSPREY_SCAN_DEPTH"

// ScanDepth reads ScanDepthEnv. set is false when it is unset or blank; err is
// non-nil when it is set to anything but a non-negative integer.
func ScanDepth() (depth int, set bool, err error) {
	v := strings.TrimSpace(os.Getenv(ScanDepthEnv))
	if v == "" {
		return 0, false, nil
	}
	d, err := strconv.Atoi(v)
	if err != nil || d < 0 {
		return 0, true, fmt.Errorf("%s must be 0 (no limit) or more, got %q", ScanDepthEnv, v)
	}
	return d, true, nil
}
