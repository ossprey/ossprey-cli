package registry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// cratesIndexURL is crates.io's sparse index, which cargo reads to choose a release. A var so tests can point it at httptest.
var cratesIndexURL = "https://index.crates.io/"

// maxCrateIndex bounds one crate's index file; the largest on crates.io is a few MiB.
const maxCrateIndex = 64 << 20

// cargoIndexV is the newest index entry format cargo 1.99.1 reads; it skips any newer entry.
const cargoIndexV = 2

// crateIndexPath is where the sparse index keeps a crate, under its name lowercased as cargo asks for it.
func crateIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1, 2:
		return fmt.Sprintf("%d/%s", len(n), n)
	case 3:
		return "3/" + n[:1] + "/" + n
	}
	return n[:2] + "/" + n[2:4] + "/" + n
}

// CargoInstallReleases are the releases `cargo install name@req` may take from crates.io, spelled as its index spells them; req "" is cargo's own `*`.
func CargoInstallReleases(ctx context.Context, name, req string) ([]string, error) {
	exact, err := cargoInstallReq(req)
	if err != nil {
		return nil, err
	}
	if req == "" {
		req = "*"
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, cratesIndexURL+crateIndexPath(name), nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("User-Agent", userAgent)
	resp, err := DefaultHTTP.Do(r)
	if err != nil {
		return nil, fmt.Errorf("registry request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, notFound("crates.io's index has no crate " + name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crates.io's index returned status %d", resp.StatusCode)
	}
	// Cargo 1.99.1 skips an entry newer than cargoIndexV that a later cargo may read, so the best of both is checked.
	var best, bestOld string
	var bestV, bestOldV semver
	lines := bufio.NewScanner(io.LimitReader(resp.Body, maxCrateIndex))
	lines.Buffer(nil, maxCrateIndex)
	for lines.Scan() {
		var e struct {
			Name   string `json:"name"`
			Vers   string `json:"vers"`
			Yanked bool   `json:"yanked"`
			V      int    `json:"v"`
		}
		if json.Unmarshal(lines.Bytes(), &e) != nil || e.Name != name || !IsCargoRelease(e.Vers) {
			continue
		}
		if exact != "" {
			// A pin matches whatever build metadata the release carries, and a yanked one is checked though cargo refuses it.
			if stripBuild(e.Vers) == exact {
				return []string{e.Vers}, nil
			}
			continue
		}
		if m, ok := CargoSatisfies(req, e.Vers); e.Yanked || !ok || !m {
			continue
		}
		v, _ := parseSemver(e.Vers, true)
		if best == "" || v.compare(bestV) > 0 {
			best, bestV = e.Vers, v
		}
		if e.V <= cargoIndexV && (bestOld == "" || v.compare(bestOldV) > 0) {
			bestOld, bestOldV = e.Vers, v
		}
	}
	if err := lines.Err(); err != nil {
		return nil, fmt.Errorf("read crates.io's index: %w", err)
	}
	if best == "" {
		return nil, notFound(fmt.Sprintf("crates.io's index has no release of %s matching %s", name, req))
	}
	out := []string{best}
	if bestOld != "" && bestOld != best {
		out = append(out, bestOld)
	}
	return slices.Clip(out), nil
}

// cargoInstallReq is the release a cargo install requirement pins, or "" for a range; cargo takes a bare version as `=` and refuses a partial one.
func cargoInstallReq(req string) (string, error) {
	switch {
	case req == "":
		return "", nil
	case strings.ContainsAny(req[:1], "<>=^~") || strings.Contains(req, "*"):
		if v, ok := strings.CutPrefix(req, "="); ok && IsCargoRelease(strings.TrimSpace(v)) {
			return stripBuild(strings.TrimSpace(v)), nil
		}
		return "", nil
	case IsCargoRelease(req):
		return stripBuild(req), nil
	}
	return "", fmt.Errorf("cargo reads no version in %q", req)
}

// notFound is an ErrNotFound in words of its own.
type notFound string

func (e notFound) Error() string        { return string(e) }
func (e notFound) Is(target error) bool { return target == ErrNotFound }

// stripBuild drops a release's build metadata, which semver ignores when it matches.
func stripBuild(v string) string {
	v, _, _ = strings.Cut(v, "+")
	return v
}
