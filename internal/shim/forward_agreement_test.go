// This is an external test (package shim_test) on purpose: internal/forward
// imports internal/shim, so only a test outside the package can import both.
package shim_test

import (
	"slices"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/shim"
)

// TestDefaultManagersAreForwarders is the tripwire for the one silent breakage
// this design allows: shimming a command that `ossprey <command>` cannot handle.
// The shim would then turn every `foo install` into "unsupported package
// manager" — worse than no shim at all.
func TestDefaultManagersAreForwarders(t *testing.T) {
	forwarders := forward.Managers()
	for _, m := range shim.DefaultManagers() {
		if !slices.Contains(forwarders, m) {
			t.Errorf("shim installs a %q shim, but `ossprey %s` is not a registered forwarder (%v)", m, m, forwarders)
		}
	}
}
