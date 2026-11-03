package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// VerdictTimeoutEnv overrides how long Validate waits for a verdict.
const VerdictTimeoutEnv = "OSSPREY_VERDICT_TIMEOUT"

// defaultVerdictTimeout is maxPollAttempts polls at pollInterval (~15m).
const defaultVerdictTimeout = maxPollAttempts * pollInterval

// dashboardURL is where a scan the CLI stopped waiting for still lands.
const dashboardURL = "https://dashboard.ossprey.com"

// ErrVerdictTimeout means the CLI stopped polling before the scan settled.
// The scan itself keeps running server-side, so this is not a scan failure.
type ErrVerdictTimeout struct {
	SBOMID     string
	ScanID     string
	Waited     time.Duration
	LastStatus string // last status the API reported, e.g. RUNNING
}

func (e *ErrVerdictTimeout) Error() string {
	status := e.LastStatus
	if status == "" {
		status = "pending"
	}
	return fmt.Sprintf(
		"scan took too long to complete: no verdict after %s (scan %q still %s). "+
			"The scan keeps running and its result will appear at %s; re-run later to pick up the cached verdict, "+
			"or raise %s (e.g. %s=30m)",
		e.Waited.Round(time.Second), e.ScanID, strings.ToLower(status), dashboardURL,
		VerdictTimeoutEnv, VerdictTimeoutEnv)
}

// verdictTimeoutFromEnv reads VerdictTimeoutEnv, falling back to the default.
func verdictTimeoutFromEnv() time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(os.Getenv(VerdictTimeoutEnv))); err == nil && d > 0 {
		return d
	}
	return defaultVerdictTimeout
}

// pollAttempts caps status polls at what fits in VerdictTimeout at the default
// interval, as a backstop to the elapsed-time deadline.
func (c *Client) pollAttempts() int {
	if c.VerdictTimeout <= 0 {
		return maxPollAttempts
	}
	return max(1, int((c.VerdictTimeout+pollInterval-1)/pollInterval))
}

// explainTimeout names a network timeout so it does not read as a bare Go error.
func explainTimeout(err error, during string) error {
	if err == nil {
		return nil
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return fmt.Errorf("timed out %s; the Ossprey API may be busy, retry shortly: %w", during, err)
	}
	return err
}
