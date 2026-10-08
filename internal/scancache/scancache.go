// Package scancache remembers what this machine has already sent to the
// Ossprey API, so a repeat of the identical scan within the TTL never reaches
// the platform (OSS-2229).
//
// It holds two kinds of entry, and the whole design rests on their never
// being confused:
//
//   - A verdict entry is written only by a blocking Validate, only when the API
//     said the SBOM was clean, and stores the raw response so a hit is graded
//     exactly as the live run was. Malware, informational findings, a quota
//     skip, a failure and a timeout are never stored.
//   - A posted entry is written only by a passive Post, after the API accepted
//     the submission. It carries no verdict at all — a passive post returns
//     before one exists — so it must never satisfy a blocking Validate.
//
// The kinds live in the filename, in the entry and in the key, so a posted
// entry cannot answer a verdict lookup even if two of the three were wrong.
//
// Everything here is best-effort. A cache that cannot be read is a miss, one
// that cannot be written is a no-op, and neither changes a scan's outcome or
// exit code. Nothing a user types — API key, monitor id, login — is written
// to disk; only sha256 fingerprints take part in the key.
package scancache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ossprey/ossprey-cli/internal/ossbom"
	"github.com/ossprey/ossprey-cli/internal/warn"
)

// Kind names what an entry proves. See the package comment.
type Kind string

const (
	// Verdict: the API returned a clean result for this SBOM.
	Verdict Kind = "verdict"
	// Posted: the API accepted this SBOM for a passive scan.
	Posted Kind = "posted"
)

const (
	// DirEnv overrides where the cache lives. Entries go in its scans/
	// subdirectory, so pruning never touches a file that is not ours even
	// when the variable names a shared cache root.
	DirEnv = "OSSPREY_CACHE_DIR"
	// TTLEnv is how long an entry is reused for: a Go duration such as 30m,
	// 0 or off to disable, capped at MaxTTL.
	TTLEnv = "OSSPREY_SCAN_CACHE_TTL"
	// DefaultTTL mirrors the server-side reuse window (ossprey#1295).
	DefaultTTL = time.Hour
	// MaxTTL is the hard cap on staleness, whatever the environment asks for.
	MaxTTL = 24 * time.Hour
)

// schema versions the canonical key encoding. Bump it when the encoding
// changes shape, and every existing entry becomes a miss rather than a wrong
// answer.
const schema = "v1"

// KeyInput is everything that must be identical for two scans to share an
// entry. Identity is a fingerprint (see the Fingerprint functions), never the
// credential itself.
type KeyInput struct {
	Kind       Kind
	APIURL     string
	Identity   string
	CLIVersion string
	BOM        ossbom.MiniBOM
}

// keyDoc is the canonical encoding Key hashes. encoding/json writes struct
// fields in declaration order and the MiniBOM holds no maps, so the output is
// deterministic.
type keyDoc struct {
	Schema     string         `json:"schema"`
	Kind       Kind           `json:"kind"`
	APIURL     string         `json:"api_url"`
	Identity   string         `json:"identity"`
	CLIVersion string         `json:"cli_version"`
	BOM        ossbom.MiniBOM `json:"bom"`
}

// Key returns the sha256 hex of the canonical encoding of in.
//
// Created is blanked: it is the one field that differs between two otherwise
// identical scans. The CLI version is included so an upgrade invalidates
// every entry — note that MiniBOM.Creators is a constant, not the version.
// Components are sorted by purl on a copy, so the key does not depend on
// callers having sorted the SBOM, and the caller's slice is left alone.
func Key(in KeyInput) string {
	bom := in.BOM
	bom.Created = ""
	bom.Components = slices.Clone(bom.Components)
	slices.SortStableFunc(bom.Components, func(a, b ossbom.MiniComponent) int {
		return strings.Compare(a.Purl, b.Purl)
	})
	doc := keyDoc{
		Schema:     schema,
		Kind:       in.Kind,
		APIURL:     strings.TrimRight(in.APIURL, "/"),
		Identity:   in.Identity,
		CLIVersion: in.CLIVersion,
		BOM:        bom,
	}
	// Marshal cannot fail on this shape: every field is a string, a slice of
	// strings or a struct of those.
	b, _ := json.Marshal(doc)
	return sha256Hex(b)
}

// FingerprintAPIKey identifies an API-key credential without recording it.
func FingerprintAPIKey(key string) string { return fingerprint("apikey", key) }

// FingerprintLogin identifies a stored login by the identity the caller
// derived for it (the Auth0 tenant and subject; see submit.loginIdentity).
// "" in, "" out: a login with no identity is not cached.
func FingerprintLogin(identity string) string { return fingerprint("login", identity) }

// FingerprintMonitor identifies a monitor id. The id is the credential, so it
// is hashed like one and never written anywhere.
func FingerprintMonitor(id string) string { return fingerprint("monitor", id) }

// fingerprint domain-separates the three credential kinds so the same bytes
// used as, say, both an API key and a monitor id would still be two
// identities.
//
// A single SHA-256 is the right tool here, and CodeQL's
// go/weak-sensitive-data-hashing alert on it is dismissed as a false
// positive. That rule is about low-entropy human passwords stored for later
// verification, where a fast hash lets an attacker try millions of guesses.
// This input is an API key or a monitor id, both backend-generated random
// tokens (a monitor id carries 256 bits of randomness), or a login's email,
// which is an identifier rather than a secret. The output is folded into a
// cache filename in a 0700 directory, which anyone able to read is already
// this user and could read credentials.json instead. A slow KDF would add
// latency to every CLI invocation and protect nothing.
func fingerprint(kind, secret string) string {
	if secret == "" {
		return ""
	}
	return sha256Hex([]byte(kind + "\x00" + secret))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TTL reads OSSPREY_SCAN_CACHE_TTL. Zero means the cache is off, for reads
// and writes alike. A value that does not parse, or is negative, warns and
// falls back to the default rather than silently disabling the cache or
// silently keeping entries forever.
func TTL(ctx context.Context) time.Duration {
	raw := strings.TrimSpace(os.Getenv(TTLEnv))
	if raw == "" {
		return DefaultTTL
	}
	if strings.EqualFold(raw, "off") {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		warn.Add(ctx, warn.Entry{
			Class: "scan-cache-ttl",
			One: fmt.Sprintf("%s=%q is not a duration (try 30m, 2h, or 0 to disable); using the default %s",
				TTLEnv, raw, DefaultTTL),
			Many: fmt.Sprintf("%s=%q is not a duration; using the default %s (%%d times)", TTLEnv, raw, DefaultTTL),
		})
		return DefaultTTL
	}
	if d > MaxTTL {
		return MaxTTL
	}
	return d
}

// Dir is where entries live: $OSSPREY_CACHE_DIR/scans when set, else
// <user cache dir>/ossprey/scans.
func Dir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv(DirEnv)); dir != "" {
		return filepath.Join(dir, "scans"), nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve cache dir: %w", err)
	}
	return filepath.Join(base, "ossprey", "scans"), nil
}

// Clean reports whether raw is an API response that found nothing: a present
// vulnerabilities array with no entries, at any severity. A response with no
// such array is one we do not understand and is never treated as clean.
func Clean(raw json.RawMessage) bool {
	var r struct {
		Vulnerabilities *[]json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.Vulnerabilities == nil {
		return false
	}
	return len(*r.Vulnerabilities) == 0
}

// formatAge renders how long ago an entry was stored, coarsely: a person
// reading "reused from a scan 5m ago" does not need the seconds.
func formatAge(d time.Duration) string {
	d = d.Round(time.Second)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if m == 0 {
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh %dm", h, m)
}
