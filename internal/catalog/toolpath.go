package catalog

import (
	"os"
	"strings"

	"github.com/ossprey/ossprey-cli/internal/shim"
)

// lookTool resolves a package manager the resolver catalogers shell out to.
//
// It is deliberately not exec.LookPath. `ossprey shim install` puts a shim
// directory at the *front* of PATH, so on a machine with the shims installed
// exec.LookPath("npm") returns a script whose whole job is to run
// `ossprey npm ...`. A cataloger that executes it re-enters ossprey: the
// forwarder sees no packages named, scans the temp manifest the cataloger just
// wrote, and shells out to the shim again, once per level, until the
// per-resolve timeout fires (OSS-1993). shim.LookPathReal skips every
// marker-carrying candidate and returns the genuine tool.
//
// When only shims resolve, LookPathReal errors and callers skip silently — the
// same fail-open behaviour as a machine with no npm/uv at all.
func lookTool(name string) (string, error) {
	return shim.LookPathReal(name)
}

// toolEnv builds the environment for one of those invocations. It sets the shim
// bypass so that a shim reached by a route PATH scanning cannot see — a
// symlinked or misspelled PATH entry, or the tool re-invoking itself — forwards
// to the real manager instead of re-entering ossprey. Same belt-and-braces
// pairing as the shim script's own PATH-stripping guard.
//
// Ossprey's own credentials are dropped (see resolverEnv).
func toolEnv(extra ...string) []string {
	env := append(resolverEnv(), shim.BypassEnv+"=1")
	return append(env, extra...)
}

// resolverEnv is the environment minus ossprey's credentials and settings, for
// every resolver subprocess (pip, uv, npm). Those resolve the tree being
// scanned, so anything they run — a build backend, a planted pip.py — must not
// find an API key or monitor token to steal. OSSPREY_SHIM_* stays: it is how a
// shim reached anyway knows to step aside.
func resolverEnv() []string {
	full := os.Environ()
	out := make([]string, 0, len(full))
	for _, kv := range full {
		if isOsspreySecret(kv) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// isOsspreySecret reports whether a KEY=value entry is one resolverEnv drops:
// API_KEY (the CLI reads it as a key) and every OSSPREY_* but OSSPREY_SHIM_*.
// Case-folded, since Windows environment names are.
func isOsspreySecret(kv string) bool {
	key, _, _ := strings.Cut(kv, "=")
	key = strings.ToUpper(key)
	if key == "API_KEY" {
		return true
	}
	return strings.HasPrefix(key, "OSSPREY_") && !strings.HasPrefix(key, "OSSPREY_SHIM_")
}
