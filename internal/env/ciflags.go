package env

import (
	"os"
	"strings"
)

const (
	SkipCIEnv        = "OSSPREY_SKIP_CI"
	CacheScanOnlyEnv = "OSSPREY_CI_CACHE_SCAN_ONLY"
)

func SkipCI() bool { return boolEnv(SkipCIEnv) }

func CacheScanOnly() bool { return boolEnv(CacheScanOnlyEnv) }

func boolEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
