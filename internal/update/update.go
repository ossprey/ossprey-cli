// Package update implements self-updating of the ossprey binary from
// GitHub releases. It mirrors install.sh: resolve the release tag, download
// the ossprey-<os>-<arch> asset, verify its sha256 sidecar, and swap the
// binary into place.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultBaseURL is the release area binaries are published to.
const DefaultBaseURL = "https://github.com/ossprey/ossprey-cli/releases"

// errNotFound marks a 404 so callers can distinguish "asset missing"
// from transport failures.
var errNotFound = errors.New("not found")

// Options configures an update.
type Options struct {
	Current   string // running version, with or without "v" prefix
	Target    string // tag to install (e.g. "v0.2.0"); empty means latest
	Force     bool   // reinstall even when already on the target version
	CheckOnly bool   // report whether an update exists; don't install
	BaseURL   string // release base URL; empty means DefaultBaseURL
	ExePath   string // binary to replace; empty means the running executable
	Out       io.Writer
}

// Run checks for (and unless CheckOnly, installs) a new release.
func Run(ctx context.Context, opts Options) error {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	base := opts.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	base = strings.TrimRight(base, "/")

	tag := opts.Target
	if tag == "" {
		t, err := latestTag(ctx, base)
		if err != nil {
			return fmt.Errorf("resolve latest release: %w", err)
		}
		tag = t
	}
	// Accept "0.2.0" and "v0.2.0" alike; release tags always carry the prefix.
	tag = "v" + strings.TrimPrefix(tag, "v")

	target := strings.TrimPrefix(tag, "v")
	current := strings.TrimPrefix(opts.Current, "v")
	if !opts.Force && target == current {
		fmt.Fprintf(out, "ossprey %s is already the latest version\n", current)
		return nil
	}
	if opts.CheckOnly {
		fmt.Fprintf(out, "update available: %s -> %s (run `ossprey update` to install)\n", current, target)
		return nil
	}

	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	assetURL := base + "/download/" + tag + "/" + asset

	fmt.Fprintf(out, "downloading %s\n", assetURL)
	bin, err := fetch(ctx, assetURL)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return fmt.Errorf("release %s has no binary for %s/%s", tag, runtime.GOOS, runtime.GOARCH)
		}
		return fmt.Errorf("download %s: %w", assetURL, err)
	}

	// Verify the sha256 sidecar when published; tolerate its absence,
	// exactly like install.sh.
	switch sum, err := fetch(ctx, assetURL+".sha256"); {
	case errors.Is(err, errNotFound):
		fmt.Fprintln(out, "no sha256 file found, skipping verification")
	case err != nil:
		return fmt.Errorf("download checksum: %w", err)
	default:
		fmt.Fprintln(out, "verifying sha256")
		if err := verifySHA256(bin, string(sum)); err != nil {
			return err
		}
	}

	exePath := opts.ExePath
	if exePath == "" {
		p, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate running executable: %w", err)
		}
		if p, err = filepath.EvalSymlinks(p); err != nil {
			return fmt.Errorf("resolve executable path: %w", err)
		}
		exePath = p
	}

	if err := replaceExecutable(exePath, bin); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("%w\ninstall location is not writable; re-run with sudo (e.g. `sudo ossprey update`)", err)
		}
		return err
	}

	fmt.Fprintf(out, "updated ossprey %s -> %s (%s)\n", current, target, exePath)
	return nil
}

// AssetName reports the release asset name for an OS/arch pair, matching
// the names produced by the release workflow.
func AssetName(goos, goarch string) string {
	name := "ossprey-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// latestTag resolves the latest release tag by reading the redirect GitHub
// serves on <base>/latest, avoiding the rate-limited API.
func latestTag(ctx context.Context, base string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("expected a redirect from %s/latest, got %s", base, resp.Status)
	}
	loc := resp.Header.Get("Location")
	tag := path.Base(loc)
	if loc == "" || tag == "" || tag == "latest" || tag == "." || tag == "/" {
		return "", fmt.Errorf("could not parse release tag from redirect %q", loc)
	}
	return tag, nil
}

// fetch downloads url fully into memory, following redirects. A 404 is
// reported as errNotFound.
func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// verifySHA256 checks data against the first field of a sha256sum-format
// sidecar ("<hex>  <filename>").
func verifySHA256(data []byte, sidecar string) error {
	fields := strings.Fields(sidecar)
	if len(fields) == 0 {
		return errors.New("sha256 file is empty")
	}
	expected := strings.ToLower(fields[0])
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("sha256 mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

// replaceExecutable atomically swaps the binary at exePath for data: the new
// binary is written to a temp file in the same directory (so the rename never
// crosses filesystems) and renamed into place. On Windows the running
// executable can't be overwritten, so it is first renamed aside.
func replaceExecutable(exePath string, data []byte) error {
	dir := filepath.Dir(exePath)
	tmp, err := os.CreateTemp(dir, ".ossprey-update-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write new binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write new binary: %w", err)
	}

	mode := os.FileMode(0o755)
	if info, err := os.Stat(exePath); err == nil {
		mode = info.Mode().Perm() | 0o111
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod new binary: %w", err)
	}

	if runtime.GOOS == "windows" {
		old := exePath + ".old"
		os.Remove(old)
		if err := os.Rename(exePath, old); err != nil {
			return fmt.Errorf("move old binary aside: %w", err)
		}
		if err := os.Rename(tmpName, exePath); err != nil {
			os.Rename(old, exePath) // best-effort rollback
			return fmt.Errorf("install new binary: %w", err)
		}
		os.Remove(old) // fails while the old binary is still running; harmless
		return nil
	}

	if err := os.Rename(tmpName, exePath); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}
