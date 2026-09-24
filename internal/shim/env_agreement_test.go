package shim_test

import (
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/env"
	"github.com/ossprey/ossprey-cli/internal/shim"
)

// A generated shim is the only thing that sets these variables and the
// forwarder is the only thing that reads them, but the two names are written
// out in separate packages. Renaming one alone compiles clean and leaves a
// fleet of passive shims quietly blocking installs again, so pin them here
// rather than trusting the compiler.
func TestShimExportsTheVariablesForwardReads(t *testing.T) {
	const id = "ospi_" + "ab12cd34" + "00000000000000000000000000000000000000000000000000000000"
	script := shim.Script(shim.ScriptOptions{
		Manager:   "npm",
		Dir:       "/tmp/shims",
		Binary:    "/usr/local/bin/ossprey",
		Mode:      shim.ModeMonitor,
		MonitorID: id,
	})
	for _, name := range []string{env.PassiveEnv, env.MonitorIDEnv} {
		if !strings.Contains(script, name+"=") {
			t.Errorf("a monitor shim does not set %s, so the forwarder never sees it:\n%s", name, script)
		}
	}
}
