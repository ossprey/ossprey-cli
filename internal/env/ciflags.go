package env

import (
	"os"
	"strings"
)

const (
	SkipCIEnv = "OSSPREY_SKIP_CI"

	// PassiveEnv and CacheScanOnlyEnv name the same behaviour: submit the scan,
	// never wait for a verdict, never fail the caller. CacheScanOnlyEnv is the
	// original CI-facing spelling, kept working indefinitely because it is set
	// in pipelines we do not control.
	PassiveEnv       = "OSSPREY_PASSIVE"
	CacheScanOnlyEnv = "OSSPREY_CI_CACHE_SCAN_ONLY"

	// MonitorIDEnv carries a monitor's ingest token, which lets a machine submit
	// with no login and no API key. Set by `ossprey shim install --monitor`.
	MonitorIDEnv = "OSSPREY_MONITOR_ID"
)

func SkipCI() bool { return boolEnv(SkipCIEnv) }

// Passive reports whether passive mode is set by either env var.
func Passive() bool { return boolEnv(PassiveEnv) || boolEnv(CacheScanOnlyEnv) }

// MonitorID returns the configured monitor ingest token, or "" if unset.
func MonitorID() string { return strings.TrimSpace(os.Getenv(MonitorIDEnv)) }

func boolEnv(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
