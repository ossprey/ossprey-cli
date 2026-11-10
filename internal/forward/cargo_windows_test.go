//go:build windows

package forward

import "testing"

// A Windows volume is one directory in the mirror, so a path keeps its drive or share and two never meet.
func TestMirrorPathKeepsTheVolume(t *testing.T) {
	for p, want := range map[string]string{
		`C:\Users\x\proj`:  `D:\m\C\Users\x\proj`,
		`C:\`:              `D:\m\C`,
		`\\srv\share\proj`: `D:\m\__srv_share\proj`,
	} {
		if got := mirrorPath(`D:\m`, p); got != want {
			t.Errorf("%s: %s, want %s", p, got, want)
		}
	}
}
