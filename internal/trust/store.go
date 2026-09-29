package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Environment variables that add to the stored policy, for CI and other
// machines where writing trust.json is awkward. Comma or whitespace separated.
const (
	RegistriesEnv = "OSSPREY_TRUSTED_REGISTRIES"
	NpmScopesEnv  = "OSSPREY_TRUSTED_NPM_SCOPES"
)

// Path returns the policy file: $OSSPREY_CONFIG_DIR/trust.json when set, else
// <user config dir>/ossprey/trust.json — beside credentials.json.
func Path() (string, error) {
	if dir := os.Getenv("OSSPREY_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "trust.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(dir, "ossprey", "trust.json"), nil
}

// Load returns the stored policy merged with the environment's.
//
// It always returns the usable part of the policy. A non-nil error means some
// of it was not usable — an unreadable file, an entry that does not validate —
// and the caller should say so and carry on: an entry dropped here only means
// its packages are checked, which is the safe direction.
func Load() (Policy, error) {
	file, fileErr := LoadFile()
	envPolicy, envErr := FromEnv()
	return file.Merge(envPolicy), errors.Join(fileErr, envErr)
}

// LoadFile reads trust.json. A missing file is an empty policy, not an error.
func LoadFile() (Policy, error) {
	p, err := Path()
	if err != nil {
		return Policy{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Policy{}, nil
	}
	if err != nil {
		return Policy{}, fmt.Errorf("read trust config: %w", err)
	}
	var raw Policy
	if err := json.Unmarshal(data, &raw); err != nil {
		return Policy{}, fmt.Errorf("parse trust config %s: %w", p, err)
	}
	// Re-validated on the way in, not just on `trust add`: the file is plain
	// JSON and anyone can edit it, and an entry that does not normalise would
	// otherwise be compared in a form that matches nothing — or too much.
	policy, err := build(raw.Registries, raw.NpmScopes)
	if err != nil {
		err = fmt.Errorf("trust config %s: %w", p, err)
	}
	return policy, err
}

// FromEnv reads OSSPREY_TRUSTED_REGISTRIES and OSSPREY_TRUSTED_NPM_SCOPES.
func FromEnv() (Policy, error) {
	policy, err := build(splitList(os.Getenv(RegistriesEnv)), splitList(os.Getenv(NpmScopesEnv)))
	if err != nil {
		err = fmt.Errorf("%s/%s: %w", RegistriesEnv, NpmScopesEnv, err)
	}
	return policy, err
}

// Save writes the policy to trust.json, creating the config directory.
func Save(policy Policy) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("encode trust config: %w", err)
	}
	// 0600 like credentials.json: the file names the customer's private
	// registries, which is not a secret but is nobody else's business either.
	if err := os.WriteFile(p, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write trust config: %w", err)
	}
	return nil
}

// build normalises raw entries, keeping the valid ones and reporting the rest.
func build(registries, scopes []string) (Policy, error) {
	var policy Policy
	var errs []error
	for _, r := range registries {
		n, err := NormalizeRegistry(r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		policy.Registries = union(policy.Registries, []string{n})
	}
	for _, s := range scopes {
		n, err := NormalizeNpmScope(s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		policy.NpmScopes = union(policy.NpmScopes, []string{n})
	}
	return policy, errors.Join(errs...)
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
}
