// Package monitor holds the shape of a monitor's ingest token.
//
// It is a leaf with no dependencies because two packages that must not depend on
// each other both need this check: `client` builds the request URL the token
// sits in, and `shim` writes the token into a generated shell script. Keeping
// one definition means the wire path and the generated-file path can never
// disagree about what a valid token is.
package monitor

import "regexp"

// Prefix distinguishes an ingest token from an API key ("ospy_").
const Prefix = "ospi_"

// tokenPattern must stay in step with the service's ingest/config.py
// TOKEN_PATTERN. Anchored and restricted to lowercase hex on purpose: this is
// the guard that stops a hostile value reaching a URL path or a /bin/sh file, so
// it must never be loosened to something permissive.
var tokenPattern = regexp.MustCompile(`^ospi_[0-9a-f]{64}$`)

// ValidToken reports whether a string is shaped like a token the service could
// have issued.
func ValidToken(token string) bool { return tokenPattern.MatchString(token) }
