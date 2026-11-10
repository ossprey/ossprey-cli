package forward

import (
	"path/filepath"
	"testing"
)

// A link text rooted without a drive starts at the root of the link's own drive, and a drive-relative one on that drive, as Windows reads them, not under the link's directory (OSS-2553).
func TestLinkTargetReadsWindowsTextsAsWindowsDoes(t *testing.T) {
	driveRelative, err := filepath.Abs(`C:x\Cargo.toml`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ dir, to, want string }{
		{`D:\proj`, `\store\Cargo.toml`, `D:\store\Cargo.toml`},
		{`\\srv\share\proj`, `\store\Cargo.toml`, `\\srv\share\store\Cargo.toml`},
		{`D:\proj`, `C:x\Cargo.toml`, driveRelative},
		{`D:\proj`, `C:\store\Cargo.toml`, `C:\store\Cargo.toml`},
		{`D:\proj`, `\\srv\share\Cargo.toml`, `\\srv\share\Cargo.toml`},
		{`D:\proj`, `..\store\Cargo.toml`, `D:\proj\..\store\Cargo.toml`},
	} {
		if got := linkTarget(tc.dir, tc.to); got != tc.want {
			t.Errorf("linkTarget(%q, %q) = %q, want %q", tc.dir, tc.to, got, tc.want)
		}
	}
}
