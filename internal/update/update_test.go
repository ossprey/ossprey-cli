package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// newReleaseServer serves a fake GitHub release area: /latest redirects to
// /tag/<tag>, and /download/<tag>/<asset>[.sha256] serve the binary and its
// checksum. withSum controls whether the sidecar exists.
func newReleaseServer(t *testing.T, tag string, binary []byte, withSum bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(binary)
	sidecar := hex.EncodeToString(sum[:]) + "  " + asset + "\n"

	var downloads atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/download/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.Write(binary)
	})
	mux.HandleFunc("/download/"+tag+"/"+asset+".sha256", func(w http.ResponseWriter, r *http.Request) {
		if !withSum {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, sidecar)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &downloads
}

// fakeExe writes a stand-in "installed binary" and returns its path.
func fakeExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ossprey")
	if err := os.WriteFile(p, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunUpdatesBinary(t *testing.T) {
	newBin := []byte("new binary contents")
	srv, _ := newReleaseServer(t, "v1.2.3", newBin, true)
	exe := fakeExe(t)

	var out bytes.Buffer
	err := Run(context.Background(), Options{
		Current: "1.0.0",
		BaseURL: srv.URL,
		ExePath: exe,
		Out:     &out,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBin) {
		t.Errorf("binary not replaced: got %q", got)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Errorf("installed binary is not executable: %v", info.Mode())
	}
	if !strings.Contains(out.String(), "updated ossprey 1.0.0 -> 1.2.3") {
		t.Errorf("missing update message in output: %q", out.String())
	}
}

func TestRunAlreadyUpToDate(t *testing.T) {
	srv, downloads := newReleaseServer(t, "v1.2.3", []byte("bin"), true)
	exe := fakeExe(t)

	var out bytes.Buffer
	err := Run(context.Background(), Options{
		Current: "1.2.3",
		BaseURL: srv.URL,
		ExePath: exe,
		Out:     &out,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if downloads.Load() != 0 {
		t.Error("binary was downloaded despite being up to date")
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Errorf("binary was modified: %q", got)
	}
	if !strings.Contains(out.String(), "already the latest version") {
		t.Errorf("missing up-to-date message: %q", out.String())
	}
}

func TestRunForceReinstalls(t *testing.T) {
	newBin := []byte("same version rebuild")
	srv, downloads := newReleaseServer(t, "v1.2.3", newBin, true)
	exe := fakeExe(t)

	err := Run(context.Background(), Options{
		Current: "1.2.3",
		Force:   true,
		BaseURL: srv.URL,
		ExePath: exe,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if downloads.Load() != 1 {
		t.Errorf("expected 1 download, got %d", downloads.Load())
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, newBin) {
		t.Errorf("binary not replaced: %q", got)
	}
}

func TestRunCheckOnly(t *testing.T) {
	srv, downloads := newReleaseServer(t, "v2.0.0", []byte("bin"), true)
	exe := fakeExe(t)

	var out bytes.Buffer
	err := Run(context.Background(), Options{
		Current:   "1.0.0",
		CheckOnly: true,
		BaseURL:   srv.URL,
		ExePath:   exe,
		Out:       &out,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if downloads.Load() != 0 {
		t.Error("check-only run downloaded the binary")
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Errorf("check-only run modified the binary: %q", got)
	}
	if !strings.Contains(out.String(), "update available: 1.0.0 -> 2.0.0") {
		t.Errorf("missing update-available message: %q", out.String())
	}
}

func TestRunExplicitTarget(t *testing.T) {
	// Target versions are accepted with or without the "v" prefix and skip
	// the latest-tag lookup entirely.
	newBin := []byte("pinned version")
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	sum := sha256.Sum256(newBin)

	mux := http.NewServeMux()
	mux.HandleFunc("/download/v0.9.0/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write(newBin)
	})
	mux.HandleFunc("/download/v0.9.0/"+asset+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	for _, target := range []string{"v0.9.0", "0.9.0"} {
		exe := fakeExe(t)
		err := Run(context.Background(), Options{
			Current: "1.0.0",
			Target:  target,
			BaseURL: srv.URL,
			ExePath: exe,
		})
		if err != nil {
			t.Fatalf("Run(target=%q): %v", target, err)
		}
		if got, _ := os.ReadFile(exe); !bytes.Equal(got, newBin) {
			t.Errorf("target %q: binary not replaced: %q", target, got)
		}
	}
}

func TestRunSHA256Mismatch(t *testing.T) {
	asset := AssetName(runtime.GOOS, runtime.GOARCH)
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tag/v1.2.3", http.StatusFound)
	})
	mux.HandleFunc("/download/v1.2.3/"+asset, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tampered binary"))
	})
	mux.HandleFunc("/download/v1.2.3/"+asset+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("ab", 32), asset)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	exe := fakeExe(t)
	err := Run(context.Background(), Options{
		Current: "1.0.0",
		BaseURL: srv.URL,
		ExePath: exe,
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch error, got %v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old binary" {
		t.Errorf("binary replaced despite checksum failure: %q", got)
	}
}

func TestRunMissingSidecarStillInstalls(t *testing.T) {
	newBin := []byte("unverified but present")
	srv, _ := newReleaseServer(t, "v1.2.3", newBin, false)
	exe := fakeExe(t)

	var out bytes.Buffer
	err := Run(context.Background(), Options{
		Current: "1.0.0",
		BaseURL: srv.URL,
		ExePath: exe,
		Out:     &out,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, newBin) {
		t.Errorf("binary not replaced: %q", got)
	}
	if !strings.Contains(out.String(), "skipping verification") {
		t.Errorf("missing skip-verification notice: %q", out.String())
	}
}

func TestRunMissingAsset(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/tag/v1.2.3", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	err := Run(context.Background(), Options{
		Current: "1.0.0",
		BaseURL: srv.URL,
		ExePath: fakeExe(t),
	})
	if err == nil || !strings.Contains(err.Error(), "no binary for") {
		t.Fatalf("expected missing-asset error, got %v", err)
	}
}

func TestLatestTagNoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	if _, err := latestTag(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error when /latest does not redirect")
	}
}

// TestAssetName pins the asset naming to what .github/workflows/release.yml
// publishes: ossprey-<goos>-<goarch>, with .exe appended on Windows only.
// Every platform the release matrix builds is covered — a rename on either
// side breaks `ossprey update` for that platform and nothing else.
func TestAssetName(t *testing.T) {
	tests := []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "ossprey-linux-amd64"},
		{"linux", "arm64", "ossprey-linux-arm64"},
		{"darwin", "amd64", "ossprey-darwin-amd64"},
		{"darwin", "arm64", "ossprey-darwin-arm64"},
		{"windows", "amd64", "ossprey-windows-amd64.exe"},
		{"windows", "arm64", "ossprey-windows-arm64.exe"},
	}
	for _, tt := range tests {
		if got := AssetName(tt.goos, tt.goarch); got != tt.want {
			t.Errorf("AssetName(%s, %s) = %q, want %q", tt.goos, tt.goarch, got, tt.want)
		}
	}
}

// TestAssetNameMatchesHost guards the case that actually matters at runtime:
// the binary asks for its own platform's asset. runtime.GOOS/GOARCH are fixed
// at compile time, so a Windows build requests the .exe and a Linux build
// does not. This assertion is what the windows-latest CI leg verifies.
func TestAssetNameMatchesHost(t *testing.T) {
	got := AssetName(runtime.GOOS, runtime.GOARCH)
	if want := "ossprey-" + runtime.GOOS + "-" + runtime.GOARCH; !strings.HasPrefix(got, want) {
		t.Errorf("host asset %q does not describe %s/%s", got, runtime.GOOS, runtime.GOARCH)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(got, ".exe") {
		t.Errorf("host asset %q is missing the .exe suffix on Windows", got)
	}
	if runtime.GOOS != "windows" && strings.HasSuffix(got, ".exe") {
		t.Errorf("host asset %q has an .exe suffix on %s", got, runtime.GOOS)
	}
}

func TestVerifySHA256(t *testing.T) {
	data := []byte("hello")
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])

	if err := verifySHA256(data, good+"  ossprey-linux-amd64\n"); err != nil {
		t.Errorf("valid checksum rejected: %v", err)
	}
	if err := verifySHA256(data, strings.ToUpper(good)+"  x\n"); err != nil {
		t.Errorf("uppercase checksum rejected: %v", err)
	}
	if err := verifySHA256(data, strings.Repeat("00", 32)); err == nil {
		t.Error("bad checksum accepted")
	}
	if err := verifySHA256(data, "  \n"); err == nil {
		t.Error("empty sidecar accepted")
	}
}
