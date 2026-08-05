package shim_test

import (
	"slices"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/forward"
	"github.com/ossprey/ossprey-cli/internal/shim"
)

func TestDefaultManagersAreForwarders(t *testing.T) {
	forwarders := forward.Managers()
	for _, m := range shim.DefaultManagers() {
		if !slices.Contains(forwarders, m) {
			t.Errorf("shim installs a %q shim, but `ossprey %s` is not a registered forwarder (%v)", m, m, forwarders)
		}
	}
}
