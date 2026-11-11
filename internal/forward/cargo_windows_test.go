//go:build windows

package forward

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Windows volume is one directory in the mirror, so a path keeps its drive or share and two never meet.
func TestMirrorPathKeepsTheVolume(t *testing.T) {
	for p, want := range map[string]string{
		`C:\Users\x\proj`:  `D:\m\C\Users\x\proj`,
		`C:\`:              `D:\m\C`,
		`\\srv\share\proj`: `D:\m\5c5c7372765c7368617265\proj`,
	} {
		if got := mirrorPath(`D:\m`, p); got != want {
			t.Errorf("%s: %s, want %s", p, got, want)
		}
	}
}

// cargo's messages name each share as it is, though one share's directory in the mirror begins another's.
func TestMirrorStripKeepsEachVolume(t *testing.T) {
	mi := &cargoMirror{s: `D:\m`, real: map[string]bool{`C:\`: true, `\\srv\share\`: true, `\\srv\share1\`: true}}
	r := strings.NewReplacer(mi.strip()...)
	for _, p := range []string{`C:\proj\Cargo.toml`, `\\srv\share\proj\Cargo.toml`, `\\srv\share1\proj\Cargo.toml`} {
		if got := r.Replace("error: " + mi.at(p)); got != "error: "+p {
			t.Errorf("%s: %q", p, got)
		}
	}
}

// A --path rooted with no drive, on a drive with no root, or on the mirror's own drive the mirror lacks is placed or recorded from the mirror, so it is refused rather than recorded as a path climbing out of it; a mirrored volume is found in any spelling Rust reads as it (OSS-2553).
func TestMirrorDependencyRefusesAPathCargoPlacesFromTheMirror(t *testing.T) {
	mi := &cargoMirror{s: `D:\m`, real: map[string]bool{`C:\`: true, `\\srv\share\`: true}}
	for _, v := range []string{`\dep`, `/dep`, `C:dep`, `D:\dep`, `d:\dep`} {
		if got, err := mi.dependency(v); err == nil {
			t.Errorf("%s: %s, want refused", v, got)
		}
	}
	for v, want := range map[string]string{`C:\dep`: `D:\m\C\dep`, `c:\dep`: `D:\m\C\dep`, `//srv/share/dep`: `D:\m\5c5c7372765c7368617265\dep`, `\\SRV\share\dep`: `\\SRV\share\dep`, `E:\dep`: `E:\dep`, `dep`: `dep`, `..\dep`: `..\dep`} {
		if got, err := mi.dependency(v); err != nil || got != want {
			t.Errorf("%s: %s (%v), want %s", v, got, err, want)
		}
	}
}

// Windows cargo reads configs above the working directory as set, a linked one unresolved, so a config above the mirror is refused when only the link's target lies under it.
func TestBuildCargoMirrorRefusesAConfigAboveALinkTarget(t *testing.T) {
	needSymlinks(t)
	_, ws := cargoProject(t)
	top, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache, proj := filepath.Join(top, "cache"), filepath.Join(top, "phys", "proj")
	for _, d := range []string{cache, proj, filepath.Join(top, ".cargo")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(top, ".cargo", "config.toml")
	writeFile(t, config, "[patch.crates-io]\nitoa = { path = \"x\" }\n")
	t.Setenv("LocalAppData", cache)
	t.Setenv("CARGO_HOME", t.TempDir())
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(proj, link); err != nil {
		t.Fatal(err)
	}
	ws.ConfigDir = canonicalDir(link)
	if _, err := buildCargoMirror(ws, nil, link, link); err == nil || !strings.Contains(err.Error(), config) {
		t.Errorf("err = %v, want %s named", err, config)
	}
}
