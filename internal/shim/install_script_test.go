package shim

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// installSh drives the repo's install.sh against a fake release: a stub curl
// serves files from a local directory, so nothing touches the network.
type installSh struct {
	t                         *testing.T
	release, fakeBin, install string
	shimDir, log              string
	asset                     string
}

func newInstallSh(t *testing.T) *installSh {
	t.Helper()
	requirePOSIX(t)
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("install.sh supports linux and darwin")
	}
	root := t.TempDir()
	s := &installSh{
		t:       t,
		release: filepath.Join(root, "release"),
		fakeBin: filepath.Join(root, "fakebin"),
		install: filepath.Join(root, "install"),
		shimDir: filepath.Join(root, "shims"),
		log:     filepath.Join(root, "ossprey.log"),
		asset:   "ossprey-" + runtime.GOOS + "-" + runtime.GOARCH,
	}
	mkdirs(t, s.release, s.fakeBin)
	// curl -fsSL -o OUT URL: serve basename(URL) from the release dir, or fail
	// like curl -f does on a 404.
	writeExec(t, filepath.Join(s.fakeBin, "curl"), `#!/bin/sh
out=$3; url=$4
src="$FAKE_RELEASE/${url##*/}"
[ -f "$src" ] || exit 22
cp "$src" "$out"
`)
	// The "released" ossprey records how it was called.
	s.publish(`#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$1" in
--version) echo "ossprey test" ;;
shim) [ "$2" = dir ] && echo "$OSSPREY_SHIM_DIR" ;;
esac
exit 0
`, true)
	return s
}

// publish writes the release asset and, if withSum, its sha256 sidecar.
func (s *installSh) publish(body string, withSum bool) {
	writeExec(s.t, filepath.Join(s.release, s.asset), body)
	sum := filepath.Join(s.release, s.asset+".sha256")
	_ = os.Remove(sum)
	if withSum {
		h := sha256.Sum256([]byte(body))
		if err := os.WriteFile(sum, []byte(hex.EncodeToString(h[:])+"  "+s.asset+"\n"), 0o644); err != nil {
			s.t.Fatal(err)
		}
	}
}

func (s *installSh) run(path string, env ...string) (string, error) {
	s.t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		s.t.Skip("no sh")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		s.t.Fatal(err)
	}
	cmd := exec.Command(sh, script)
	cmd.Env = append([]string{
		"PATH=" + path,
		"HOME=" + s.t.TempDir(),
		"FAKE_RELEASE=" + s.release,
		"FAKE_LOG=" + s.log,
		"OSSPREY_INSTALL_DIR=" + s.install,
		"OSSPREY_SHIM_DIR=" + s.shimDir,
	}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *installSh) systemPath() string { return s.fakeBin + ":" + os.Getenv("PATH") }

func (s *installSh) installed() bool {
	_, err := os.Stat(filepath.Join(s.install, "ossprey"))
	return err == nil
}

func TestInstallShVerifiesTheChecksum(t *testing.T) {
	s := newInstallSh(t)
	if out, err := s.run(s.systemPath()); err != nil || !s.installed() {
		t.Fatalf("a verified install failed: %v\n%s", err, out)
	}
}

// Every way of not verifying the binary refuses to install it, unless the
// operator opts out explicitly.
func TestInstallShFailsClosedWhenItCannotVerify(t *testing.T) {
	t.Run("sidecar missing", func(t *testing.T) {
		s := newInstallSh(t)
		s.publish("#!/bin/sh\nexit 0\n", false)
		out, err := s.run(s.systemPath())
		if err == nil || s.installed() {
			t.Fatalf("installed an unverified binary:\n%s", out)
		}
		if !strings.Contains(out, "OSSPREY_SKIP_CHECKSUM") {
			t.Fatalf("failure does not name the opt-out:\n%s", out)
		}

		out, err = s.run(s.systemPath(), "OSSPREY_SKIP_CHECKSUM=1")
		if err != nil || !s.installed() || !strings.Contains(out, "NOT verifying") {
			t.Fatalf("opt-out did not install with a warning: %v\n%s", err, out)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		s := newInstallSh(t)
		if err := os.WriteFile(filepath.Join(s.release, s.asset+".sha256"), []byte(strings.Repeat("0", 64)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := s.run(s.systemPath()); err == nil || s.installed() || !strings.Contains(out, "mismatch") {
			t.Fatalf("installed a binary with the wrong checksum: %v\n%s", err, out)
		}
	})

	t.Run("malformed sidecar", func(t *testing.T) {
		s := newInstallSh(t)
		if err := os.WriteFile(filepath.Join(s.release, s.asset+".sha256"), []byte("<html>not found</html>\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := s.run(s.systemPath()); err == nil || s.installed() {
			t.Fatalf("installed against a malformed checksum: %v\n%s", err, out)
		}
	})

	t.Run("no sha256 tool", func(t *testing.T) {
		s := newInstallSh(t)
		// A PATH holding only what the installer needs besides a hash tool.
		tools := filepath.Join(t.TempDir(), "tools")
		mkdirs(t, tools)
		for _, name := range []string{"sh", "awk", "uname", "mktemp", "rm", "chmod", "mv", "mkdir", "id", "cp", "tr", "grep", "basename"} {
			p, err := exec.LookPath(name)
			if err != nil {
				t.Skipf("no %s", name)
			}
			if err := os.Symlink(p, filepath.Join(tools, name)); err != nil {
				t.Fatal(err)
			}
		}
		out, err := s.run(s.fakeBin + ":" + tools)
		if err == nil || s.installed() || !strings.Contains(out, "no sha256 tool") {
			t.Fatalf("installed without a way to verify: %v\n%s", err, out)
		}
	})
}

// An upgrade with no shim flags re-points the shims already installed -- and
// only those, without touching profiles -- so they call the new binary.
func TestInstallShRepointsExistingShimsOnUpgrade(t *testing.T) {
	s := newInstallSh(t)
	if out, err := s.run(s.systemPath()); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if log, _ := os.ReadFile(s.log); strings.Contains(string(log), "shim install") {
		t.Fatalf("installed shims nobody asked for:\n%s", log)
	}

	mkdirs(t, s.shimDir)
	for _, m := range []string{"npm", "pip"} {
		writeExec(t, filepath.Join(s.shimDir, m), Script(ScriptOptions{Manager: m, Dir: s.shimDir, Binary: "/old/ossprey"}))
	}
	writeExec(t, filepath.Join(s.shimDir, "npm.tmp"), Script(ScriptOptions{Manager: "npm", Dir: s.shimDir, Binary: "/old/ossprey"}))
	writeExec(t, filepath.Join(s.shimDir, "yarn"), "#!/bin/sh\necho not ours\n")
	if err := os.Remove(s.log); err != nil {
		t.Fatal(err)
	}

	if out, err := s.run(s.systemPath()); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, out)
	}
	log, _ := os.ReadFile(s.log)
	if !strings.Contains(string(log), "shim install --no-path --managers npm,pip\n") {
		t.Fatalf("upgrade did not re-point exactly the existing shims:\n%s", log)
	}
}
