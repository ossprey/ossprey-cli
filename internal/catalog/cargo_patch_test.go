package catalog

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ossprey/ossprey-cli/internal/warn"
)

const patchRev = "0123456789abcdef0123456789abcdef01234567"

// r7 from the OSS-2099 sweep: a lockless crate patched to a fork.
const lockless7 = `[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.100"

[patch.crates-io]
serde = { git = "https://github.com/evil/serde" }
`

// cargoComponents spells each crate as name@version, its source qualifiers and where under root it was found.
func cargoComponents(t *testing.T, pkgs []Package, root string) []string {
	t.Helper()
	// Locations are root-relative on POSIX but absolute under the resolved root on Windows.
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range pkgs {
		if p.Type != "cargo" {
			continue
		}
		var locs []string
		for _, l := range p.Locations {
			locs = append(locs, rootRel(l, filepath.ToSlash(real)+"/"))
		}
		out = append(out, p.Name+"@"+p.Version+qualifierKey(p.Qualifiers)+" "+strings.Join(locs, ","))
	}
	slices.Sort(out)
	return out
}

// Without a Cargo.lock the git crate a [patch] or [replace] builds is sent marked beside the crates.io declaration (OSS-2099).
func TestCatalogCargoMarksLocklessPatchTargets(t *testing.T) {
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	t.Setenv("CARGO_HOME", t.TempDir())
	withResolveLatest(t, func(context.Context, string, string) (string, error) { return "9.9.9", nil })

	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"r7 lockless git patch", map[string]string{"Cargo.toml": lockless7}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		{"patch forms", map[string]string{"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1"
itoa = "1"
ryu = "1"

[patch.crates-io]
serde = { git = "https://github.com/evil/serde", rev = "` + strings.ToUpper(patchRev) + `" }
itoa = { git = "https://github.com/evil/itoa", rev = "0123abc" }
ryu = { git = "https://github.com/evil/ryu", branch = "main", version = "=1.0.20" }
json2 = { git = "https://github.com/evil/json", package = "serde_json" }

[patch."https://github.com/upstream/tool"]
tool = { git = "https://github.com/evil/tool" }
`}, []string{
			"itoa@9.9.9 Cargo.toml",
			// A short rev is not the commit Cargo.lock would record.
			"itoa@?vcs_url=git+https://github.com/evil/itoa Cargo.toml",
			"ryu@1.0.20?vcs_url=git+https://github.com/evil/ryu Cargo.toml",
			"ryu@9.9.9 Cargo.toml",
			"serde@9.9.9 Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.toml",
			"serde_json@?vcs_url=git+https://github.com/evil/json Cargo.toml",
			"tool@?vcs_url=git+https://github.com/evil/tool Cargo.toml",
		}},
		{"replace by name, by registry and by url", map[string]string{"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[dependencies]
itoa = "=1.0.15"
ryu = "=1.0.20"
semver = "1"

[replace]
"itoa:1.0.15" = { git = "https://git.example.com/acme/itoa", rev = "` + patchRev + `" }
"https://github.com/rust-lang/crates.io-index#ryu@1.0.20" = { git = "https://git.example.com/acme/ryu" }
"https://github.com/dtolnay/semver?branch=main#1.0.26" = { git = "https://git.example.com/acme/semver" }
`}, []string{
			"itoa@1.0.15 Cargo.toml",
			"itoa@1.0.15?vcs_url=git+https://git.example.com/acme/itoa@" + patchRev + " Cargo.toml",
			"ryu@1.0.20 Cargo.toml",
			"ryu@1.0.20?vcs_url=git+https://git.example.com/acme/ryu Cargo.toml",
			"semver@1.0.26?vcs_url=git+https://git.example.com/acme/semver Cargo.toml",
			"semver@9.9.9 Cargo.toml",
		}},
		// Cargo's parser refuses a core number past u64::MAX, so the spec names no version.
		{"replace spec past u64", map[string]string{"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[replace]
"itoa:18446744073709551616.0.0" = { git = "https://git.example.com/acme/itoa" }
`}, []string{
			"itoa@?vcs_url=git+https://git.example.com/acme/itoa Cargo.toml",
		}},
		{"credentials stay home", map[string]string{"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[patch.crates-io]
serde = { git = "https://deploy:s3cret@git.example.com/acme/serde?token=t0ken" }
`}, []string{
			"serde@?vcs_url=git+https://git.example.com/acme/serde Cargo.toml",
		}},
		{"path and registry patches are not git", map[string]string{"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.100"
itoa = "=1.0.15"

[patch.crates-io]
serde = { path = "../serde" }
itoa = { version = "=1.0.16", registry = "company" }

[replace]
"ryu:1.0.20" = { path = "../ryu" }
`}, []string{
			"itoa@1.0.15 Cargo.toml",
			"serde@1.0.100 Cargo.toml",
		}},
		{"workspace root patch", map[string]string{
			"Cargo.toml":            "[workspace]\nmembers = [\"crates/app\"]\n\n[patch.crates-io]\nserde = { git = \"https://github.com/evil/serde\" }\n",
			"crates/app/Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.100\"\n",
		}, []string{
			"serde@1.0.100 crates/app/Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		// Cargo ignores [patch] outside the workspace root, with a warning.
		{"member patch", map[string]string{
			"Cargo.toml":            "[workspace]\nmembers = [\"crates/app\"]\n",
			"crates/app/Cargo.toml": lockless7,
		}, []string{
			"serde@1.0.100 crates/app/Cargo.toml",
		}},
		{"locked patch", map[string]string{
			"Cargo.toml": lockless7,
			"Cargo.lock": `version = 4

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.100"
source = "git+https://github.com/evil/serde#` + patchRev + `"
`,
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, tc.files)
			got, err := Catalog(context.Background(), dir, Options{NoExec: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			want := slices.Sorted(slices.Values(tc.want))
			if gotC := cargoComponents(t, got, dir); !slices.Equal(gotC, want) {
				t.Errorf("crates:\n got  %s\n want %s", strings.Join(gotC, "\n      "), strings.Join(want, "\n      "))
			}
		})
	}
}

const mirrorConfig = "[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"sparse+https://crates.corp.example/index/\"\n"

// A cargo config that replaces crates.io gets one warning a scan, unless it names a vendor tree the filter proved (OSS-2099).
func TestCatalogWarnsWhenCargoReplacesCratesIo(t *testing.T) {
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	withResolveLatest(t, func(context.Context, string, string) (string, error) { return "9.9.9", nil })
	const project = "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n"

	for _, tc := range []struct {
		name  string
		files map[string]string
		// scan is the directory scanned under the fixture, and home is CARGO_HOME's config.
		scan, home string
		tree       func(t *testing.T) string
		want       int
	}{
		{name: "mirror registry", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": mirrorConfig}, want: 1},
		{name: "git source", files: map[string]string{"Cargo.toml": project, ".cargo/config": "[source.crates-io]\nreplace-with = \"fork\"\n\n[source.fork]\ngit = \"https://git.example.com/acme/crates\"\nbranch = \"main\"\n"}, want: 1},
		{name: "unproven directory", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": vendorConfig("vendor")}, want: 1},
		{name: "above the scan root", files: map[string]string{"proj/Cargo.toml": project, ".cargo/config.toml": mirrorConfig}, scan: "proj", want: 1},
		{name: "CARGO_HOME", files: map[string]string{"Cargo.toml": project}, home: mirrorConfig, want: 1},
		{name: "two configs", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": mirrorConfig, "tools/.cargo/config.toml": vendorConfig("vendor")}, want: 1},
		{name: "beside an unreadable config", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": mirrorConfig, "docs/.cargo/config.toml": "[source.crates-io\n"}, want: 1},
		{name: "proven vendor tree", tree: cargoVendorFixture, want: 0},
		{name: "mirror beside a vendor tree", tree: cargoVendorFixture, files: map[string]string{"tools/.cargo/config.toml": mirrorConfig}, want: 1},
		{name: "not replaced", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": "[net]\ngit-fetch-with-cli = true\n"}, want: 0},
		{name: "no crates", files: map[string]string{"package.json": `{"name":"web","dependencies":{"left-pad":"^1.3.0"}}`, ".cargo/config.toml": mirrorConfig}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("CARGO_HOME", home)
			if tc.home != "" {
				writeTree(t, home, map[string]string{"config.toml": tc.home})
			}
			dir := t.TempDir()
			if tc.tree != nil {
				dir = tc.tree(t)
			}
			writeTree(t, dir, tc.files)
			ctx := warn.NewContext(context.Background(), false)
			got, err := Catalog(ctx, filepath.Join(dir, tc.scan), Options{NoExec: true, ReportCargoReplacement: true})
			if err != nil {
				t.Fatalf("Catalog: %v", err)
			}
			out := warn.Drain(ctx)
			if n := strings.Count(out, "checked as their crates.io releases"); n != tc.want {
				t.Errorf("got %d replacement warnings, want %d:\n%s", n, tc.want, out)
			}
			// The crates themselves are still sent as crates.io releases.
			for _, p := range got {
				if p.Type == "cargo" && p.Version == "" {
					t.Errorf("%s left unversioned", p.Name)
				}
			}
		})
	}
}

// Only a scan reports a replacement, once and without a count, and the pre-commit hook's temp trees never do (OSS-2099).
func TestCatalogReportsCargoReplacementOnlyForAScan(t *testing.T) {
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	withResolveLatest(t, func(context.Context, string, string) (string, error) { return "9.9.9", nil })
	home := t.TempDir()
	t.Setenv("CARGO_HOME", home)
	writeTree(t, home, map[string]string{"config.toml": mirrorConfig})
	trees := []string{t.TempDir(), t.TempDir()}
	for _, dir := range trees {
		writeTree(t, dir, map[string]string{"Cargo.toml": "[package]\nname = \"app\"\n\n[dependencies]\nserde = \"=1.0.100\"\n"})
	}
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		// The hook catalogues its staged and HEAD trees offline, as precommit.Run does.
		{"pre-commit trees", Options{SkipVersionLookup: true, NoExec: true}, ""},
		{"a scan cataloguing twice", Options{NoExec: true, ReportCargoReplacement: true}, "ossprey: " + cargoReplacedEntry.One + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := warn.NewContext(context.Background(), false)
			for _, dir := range trees {
				if _, err := Catalog(ctx, dir, tc.opts); err != nil {
					t.Fatalf("Catalog: %v", err)
				}
			}
			if got := warn.Drain(ctx); got != tc.want {
				t.Errorf("warnings = %q, want %q", got, tc.want)
			}
		})
	}
}
