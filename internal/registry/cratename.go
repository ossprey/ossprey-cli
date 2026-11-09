package registry

import "regexp"

// cargoName is the crates.io name shape, which the Ossprey API enforces too: one
// component failing it rejects the whole SBOM, taking every other ecosystem with it.
var cargoName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// IsCargoName reports whether name has the shape of a crates.io crate name.
func IsCargoName(name string) bool { return cargoName.MatchString(name) }

// MaxCargoVersion mirrors the API's version cap; a longer one rejects the SBOM.
const MaxCargoVersion = 256
