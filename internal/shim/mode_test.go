package shim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testMonitorID = "ospi_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestValidateModeAcceptsTheSupportedPairings(t *testing.T) {
	for _, o := range []Options{
		{Mode: ModeBlocking},
		{Mode: ModeWatchdog},
		{Mode: ModeMonitor, MonitorID: testMonitorID},
	} {
		if err := ValidateMode(o); err != nil {
			t.Errorf("ValidateMode(%+v) = %v, want nil", o, err)
		}
	}
}

// The monitor id is interpolated into an executable file, so this is the guard
// between a hostile flag value and a generated /bin/sh script. Every one of
// these must be refused before anything is written.
func TestValidateModeRejectsAHostileMonitorID(t *testing.T) {
	hostile := []string{
		"",
		"nope",
		"ospi_short",
		"ospi_" + strings.Repeat("z", 64),
		"ospi_" + strings.Repeat("a", 63),
		"ospi_" + strings.Repeat("a", 65),
		"ospi_" + strings.Repeat("a", 64) + "'; rm -rf / #",
		"'; rm -rf / #",
		"$(id)",
		"`id`",
		"a\nexport EVIL=1",
		"%PATH%",
		"& calc.exe",
	}
	for _, id := range hostile {
		if err := ValidateMode(Options{Mode: ModeMonitor, MonitorID: id}); err == nil {
			t.Errorf("ValidateMode accepted hostile monitor id %q", id)
		}
	}
}

func TestValidateModeRejectsContradictoryOptions(t *testing.T) {
	if err := ValidateMode(Options{Mode: ModeWatchdog, MonitorID: testMonitorID}); err == nil {
		t.Error("watchdog with a monitor id should be refused")
	}
	if err := ValidateMode(Options{Mode: ModeBlocking, MonitorID: testMonitorID}); err == nil {
		t.Error("a monitor id with no mode should be refused")
	}
}

// Plan runs ValidateMode, so --dry-run rejects a bad id too rather than
// printing a plan that install would then refuse.
func TestPlanRejectsABadMonitorID(t *testing.T) {
	dir := t.TempDir()
	_, err := Plan(Options{
		Dir:       filepath.Join(dir, "shims"),
		Binary:    filepath.Join(dir, "ossprey"),
		Mode:      ModeMonitor,
		MonitorID: "not-a-token",
	})
	if err == nil {
		t.Fatal("Plan accepted a malformed monitor id")
	}
}

func TestBlockingShimSetsNoPassiveEnv(t *testing.T) {
	script := Script(ScriptOptions{Manager: "npm", Dir: "/shims", Binary: "/bin/ossprey"})
	if strings.Contains(script, passiveEnv) {
		t.Error("a blocking shim must not set the passive env var")
	}
	if mode, id := modeFromScript(t, script); mode != ModeBlocking || id != "" {
		t.Errorf("blocking shim reported mode %q / %q", mode, id)
	}
}

func TestWatchdogShimExportsPassive(t *testing.T) {
	script := Script(ScriptOptions{Manager: "npm", Dir: "/shims", Binary: "/bin/ossprey", Mode: ModeWatchdog})
	if !strings.Contains(script, passiveEnv+"=1") {
		t.Errorf("watchdog shim did not set %s:\n%s", passiveEnv, script)
	}
	if strings.Contains(script, monitorEnv) {
		t.Error("watchdog shim must not set a monitor id")
	}
	if mode, _ := modeFromScript(t, script); mode != ModeWatchdog {
		t.Errorf("watchdog shim reported mode %q", mode)
	}
}

func TestMonitorShimExportsBothVars(t *testing.T) {
	script := Script(ScriptOptions{
		Manager: "npm", Dir: "/shims", Binary: "/bin/ossprey",
		Mode: ModeMonitor, MonitorID: testMonitorID,
	})
	if !strings.Contains(script, passiveEnv+"=1") {
		t.Errorf("monitor shim did not set %s", passiveEnv)
	}
	if !strings.Contains(script, testMonitorID) {
		t.Error("monitor shim did not carry the monitor id")
	}
	mode, id := modeFromScript(t, script)
	if mode != ModeMonitor || id != testMonitorID {
		t.Errorf("monitor shim reported mode %q / id %q", mode, id)
	}
}

// The generated script has to reach the child process with the right
// environment, which only running it actually proves.
func TestPassiveShimPassesEnvToTheBinary(t *testing.T) {
	requirePOSIX(t)

	for _, tc := range []struct {
		name        string
		opts        ScriptOptions
		wantPassive string
		wantMonitor string
	}{
		{"watchdog", ScriptOptions{Mode: ModeWatchdog}, "1", ""},
		{"monitor", ScriptOptions{Mode: ModeMonitor, MonitorID: testMonitorID}, "1", testMonitorID},
		{"blocking", ScriptOptions{}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			shimDir, realDir := filepath.Join(root, "shims"), filepath.Join(root, "real")
			mkdirs(t, shimDir, realDir)

			// Stands in for the ossprey binary and reports what it was handed.
			bin := filepath.Join(root, "ossprey")
			writeExec(t, bin, "#!/bin/sh\necho \"passive=${OSSPREY_PASSIVE:-}\"\necho \"monitor=${OSSPREY_MONITOR_ID:-}\"\n")
			writeExec(t, filepath.Join(realDir, "npm"), "#!/bin/sh\nexit 0\n")

			opts := tc.opts
			opts.Manager, opts.Dir, opts.Binary = "npm", shimDir, bin
			writeExec(t, filepath.Join(shimDir, "npm"), Script(opts))

			out := runShim(t, shimDir, realDir, nil, "install", "left-pad")

			if got := "passive=" + tc.wantPassive; !strings.Contains(out, got) {
				t.Errorf("want %q in output:\n%s", got, out)
			}
			if got := "monitor=" + tc.wantMonitor; !strings.Contains(out, got) {
				t.Errorf("want %q in output:\n%s", got, out)
			}
		})
	}
}

// Install must refuse a bad id before it writes anything at all -- a file
// written and then rolled back is a file that briefly existed and was runnable.
func TestInstallWritesNothingForABadMonitorID(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")

	_, err := Install(Options{
		Dir:          shimDir,
		Binary:       filepath.Join(root, "ossprey"),
		Managers:     []string{"npm"},
		All:          true,
		SkipProfiles: true,
		Mode:         ModeMonitor,
		MonitorID:    "'; rm -rf / #",
	})

	if err == nil {
		t.Fatal("Install accepted a hostile monitor id")
	}
	if _, statErr := os.Stat(shimDir); !os.IsNotExist(statErr) {
		t.Errorf("Install created %s despite refusing the id", shimDir)
	}
}

func TestInstalledMonitorShimRoundTripsThroughStatus(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	bin := filepath.Join(root, "ossprey")
	writeExec(t, bin, "#!/bin/sh\nexit 0\n")

	if _, err := Install(Options{
		Dir: shimDir, Binary: bin, Managers: []string{"npm"}, All: true,
		SkipProfiles: true, Mode: ModeMonitor, MonitorID: testMonitorID, Home: root,
	}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	st, err := Load(Options{Dir: shimDir, Home: root})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, m := range st.Managers {
		if m.Name != "npm" {
			continue
		}
		if m.Mode != ModeMonitor || m.MonitorID != testMonitorID {
			t.Fatalf("status reported mode %q / id %q", m.Mode, m.MonitorID)
		}
		return
	}
	t.Fatal("npm not reported by status")
}

// modeFromScript writes the script to disk and reads its mode back, which is
// how `shim status` sees it.
func modeFromScript(t *testing.T, script string) (Mode, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), scriptName("npm"))
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return ShimMode(path)
}

// `shim install` is documented as safe to re-run and install.sh calls it on
// every upgrade, so a re-run that names no mode must not silently rewrite a
// fleet's passive shims into blocking ones.
func TestReinstallWithoutAModeKeepsTheInstalledOne(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	bin := filepath.Join(root, "ossprey")
	writeExec(t, bin, "#!/bin/sh\nexit 0\n")
	base := Options{
		Dir: shimDir, Binary: bin, Managers: []string{"npm"}, All: true,
		SkipProfiles: true, Home: root,
	}

	first := base
	first.Mode, first.MonitorID = ModeMonitor, testMonitorID
	if _, err := Install(first); err != nil {
		t.Fatalf("first install: %v", err)
	}

	// A plain re-run, exactly what an upgrade does.
	res, err := Install(base)
	if err != nil {
		t.Fatalf("reinstall: %v", err)
	}

	if res.Mode != ModeMonitor || res.MonitorID != testMonitorID {
		t.Errorf("reinstall reported mode %q / id %q, want the installed monitor", res.Mode, res.MonitorID)
	}
	mode, id := ShimMode(filepath.Join(shimDir, scriptName("npm")))
	if mode != ModeMonitor || id != testMonitorID {
		t.Errorf("reinstall rewrote the shim to mode %q / id %q", mode, id)
	}
}

func TestReinstallWithADifferentModeReplacesIt(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	bin := filepath.Join(root, "ossprey")
	writeExec(t, bin, "#!/bin/sh\nexit 0\n")
	base := Options{
		Dir: shimDir, Binary: bin, Managers: []string{"npm"}, All: true,
		SkipProfiles: true, Home: root,
	}

	first := base
	first.Mode, first.MonitorID = ModeMonitor, testMonitorID
	if _, err := Install(first); err != nil {
		t.Fatalf("first install: %v", err)
	}
	second := base
	second.Mode = ModeWatchdog
	if _, err := Install(second); err != nil {
		t.Fatalf("second install: %v", err)
	}

	if mode, _ := ShimMode(filepath.Join(shimDir, scriptName("npm"))); mode != ModeWatchdog {
		t.Errorf("shim mode = %q, want watchdog", mode)
	}
}

// Going back to blocking has to be possible, but only on purpose.
func TestNoPassiveClearsAnInstalledMode(t *testing.T) {
	root := t.TempDir()
	shimDir := filepath.Join(root, "shims")
	bin := filepath.Join(root, "ossprey")
	writeExec(t, bin, "#!/bin/sh\nexit 0\n")
	base := Options{
		Dir: shimDir, Binary: bin, Managers: []string{"npm"}, All: true,
		SkipProfiles: true, Home: root,
	}

	first := base
	first.Mode, first.MonitorID = ModeMonitor, testMonitorID
	if _, err := Install(first); err != nil {
		t.Fatalf("first install: %v", err)
	}
	cleared := base
	cleared.ClearMode = true
	if _, err := Install(cleared); err != nil {
		t.Fatalf("clearing install: %v", err)
	}

	mode, id := ShimMode(filepath.Join(shimDir, scriptName("npm")))
	if mode != ModeBlocking || id != "" {
		t.Errorf("--no-passive left mode %q / id %q", mode, id)
	}
}
