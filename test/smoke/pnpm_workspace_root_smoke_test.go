//go:build smoke

// Coverage for pnpm flag forms whose npm lookalikes take a value but which are
// boolean (or absent) in pnpm.
//
// These guard one failure mode: if pnpm's value-flag tables are ever aliased to
// npm's again (`valueFlags["pnpm"] = valueFlags["npm"]`, the shape of OSS-1577)
// or gain an npm-only entry, a flag consumes the package name that follows it
// and the install forwards with that package unchecked.
//
// Run with: go test -tags smoke -run TestPnpm -v ./test/smoke/...

package smoke

import (
	"strings"
	"testing"
)

// TestPnpmWorkspaceRootAddIsChecked covers `pnpm add -w <pkg>`, the standard way
// to add a dependency to a pnpm workspace root. pnpm's -w is boolean
// (--workspace-root); npm's -w (--workspace) takes a value.
func TestPnpmWorkspaceRootAddIsChecked(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmWorkspace(t)

	res := runForward(t, dir, api.URL, "pnpm", "add", "-w", "left-pad@1.3.0")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}

	_, purls := api.stats()
	found := false
	for _, p := range purls {
		if p == "pkg:npm/left-pad@1.3.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("`pnpm add -w left-pad@1.3.0` never checked left-pad; purls submitted: %v", purls)
	}
	if strings.Contains(res.stderr, "no packages named; scanning project manifest") {
		t.Error("-w was read as a value flag and swallowed the package name, " +
			"so the named package fell through to a manifest scan")
	}
}

// TestPnpmWorkspaceRootAddBlocksMalware is the security consequence: if -w
// swallows the package name, the malware verdict for it is never requested and
// the install proceeds.
func TestPnpmWorkspaceRootAddBlocksMalware(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "pkg:npm/left-pad@1.3.0")
	dir := pnpmWorkspace(t)

	res := runForward(t, dir, api.URL, "pnpm", "add", "-w", "left-pad@1.3.0")
	if res.exitCode == 0 {
		t.Errorf("`pnpm add -w <malware>` exited 0; expected the install to be blocked\nstderr: %s", res.stderr)
	}
	if installed(dir, "left-pad") {
		t.Error("malware was installed into the workspace root despite a malware verdict")
	}
}

// TestPnpmWorkspaceRootAddLongFormIsChecked pins the long form, which works
// today only because npm has no --workspace-root to inherit. It guards against
// someone "fixing" the short form by adding --workspace-root to the value table.
func TestPnpmWorkspaceRootAddLongFormIsChecked(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmWorkspace(t)

	res := runForward(t, dir, api.URL, "pnpm", "add", "--workspace-root", "left-pad@1.3.0")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}

	_, purls := api.stats()
	if len(purls) != 1 || purls[0] != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("`pnpm add --workspace-root left-pad@1.3.0` checked %v, want [pkg:npm/left-pad@1.3.0]", purls)
	}
}

// TestPnpmPostVerbFilterChecksOnlyTheRealPackage covers `--filter` after the
// verb, which pnpm accepts as readily as before it. If it is missing from pnpm's
// post-verb value-flag table its value is read as an install target, resolved
// against the real registry and checked — there is a package called `web`.
//
// Asserted as an exact set, so it fails both ways: a phantom `web` appearing,
// and left-pad going unchecked if the parse regresses and the install falls
// through.
func TestPnpmPostVerbFilterChecksOnlyTheRealPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("hits the npm registry")
	}
	pnpmBin(t)

	api := newFakeAPI(t, "")
	dir := pnpmWorkspace(t)

	res := runForward(t, dir, api.URL, "pnpm", "add", "--filter", "web", "left-pad@1.3.0")
	if res.exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout: %s\nstderr: %s", res.exitCode, res.stdout, res.stderr)
	}

	_, purls := api.stats()
	if len(purls) != 1 || purls[0] != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("checked %v, want exactly [pkg:npm/left-pad@1.3.0]; a pkg:npm/web@ entry means "+
			"--filter's value was read as a package", purls)
	}
}
