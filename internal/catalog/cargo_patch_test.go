package catalog

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
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

const otherRev = "89abcdef0123456789abcdef0123456789abcdef"

const registrySerde = "[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"

// unusedSerde records the evil fork's serde 1.0.200 as a patch the lock leaves unused.
const unusedSerde = "[[patch.unused]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"git+https://github.com/evil/serde#" + patchRev + "\"\n"

// gitSerde is a Cargo.lock entry for serde 1.0.100 from the evil fork, its source ending in suffix.
func gitSerde(suffix string) string {
	return "[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\nsource = \"git+https://github.com/evil/serde" + suffix + "\"\n"
}

// appLock is a Cargo.lock holding the app and entries.
func appLock(entries ...string) string {
	return "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n" + strings.Join(entries, "\n")
}

// itoaReplaceLock is the lock cargo 1.99 writes for replacedItoa("1.0.10"): the crates.io entry names the fork it is replaced by.
const itoaReplaceLock = `version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["itoa 1.0.10 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "itoa"
version = "1.0.10"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "itoa 1.0.10 (git+https://git.example.com/acme/itoa?branch=main)"

[[package]]
name = "itoa"
version = "1.0.10"
source = "git+https://git.example.com/acme/itoa?branch=main#` + patchRev + `"
`

// replacedItoa pins itoa at version and replaces that release with a fork's main branch.
func replacedItoa(version string) string {
	return "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nitoa = \"=" + version + "\"\n\n[replace]\n\"itoa:" + version + "\" = { git = \"https://git.example.com/acme/itoa\", branch = \"main\" }\n"
}

// patchedSerde is lockless7 with more keys on its serde patch.
func patchedSerde(keys string) string {
	return strings.Replace(lockless7, `git = "https://github.com/evil/serde" }`, `git = "https://github.com/evil/serde"`+keys+` }`, 1)
}

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
		// Cargo ignores a URL fragment, so it names no commit and does not hide rev.
		{"fragment in the git url", map[string]string{"Cargo.toml": `[package]
name = "app"
version = "0.1.0"

[patch.crates-io]
itoa = { git = "https://github.com/evil/itoa#cafebabe" }
serde = { git = "https://github.com/evil/serde#deadbeef12345", rev = "` + patchRev + `" }
`}, []string{
			"itoa@?vcs_url=git+https://github.com/evil/itoa Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.toml",
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
		// A crate the root excludes is its own workspace root, so cargo applies its [patch].
		{"excluded crate patch", map[string]string{
			"Cargo.toml":         "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"tools/x\"]\n",
			"tools/x/Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nryu = \"=1.0.20\"\n\n[patch.crates-io]\nryu = { git = \"https://github.com/evil/ryu\" }\n",
		}, []string{
			"ryu@1.0.20 tools/x/Cargo.toml",
			"ryu@?vcs_url=git+https://github.com/evil/ryu tools/x/Cargo.toml",
		}},
		// A member that names its root through package.workspace is not the root, so cargo ignores its [patch].
		{"package.workspace member patch", map[string]string{
			"ws/Cargo.toml":      "[workspace]\nmembers = [\"../outside\"]\n",
			"outside/Cargo.toml": "[package]\nname = \"outside\"\nversion = \"0.1.0\"\nworkspace = \"../ws\"\n\n[dependencies]\nlog = \"=0.4.22\"\n\n[patch.crates-io]\nlog = { git = \"https://github.com/evil/log\" }\n",
		}, []string{
			"log@0.4.22 outside/Cargo.toml",
		}},
		// Cargo ignores [patch] outside the workspace root, with a warning.
		{"member patch", map[string]string{
			"Cargo.toml":            "[workspace]\nmembers = [\"crates/app\"]\n",
			"crates/app/Cargo.toml": lockless7,
		}, []string{
			"serde@1.0.100 crates/app/Cargo.toml",
		}},
		// A crate whose root cannot be found counts as its own root, so its [patch] still goes out.
		{"patch under an ancestor that is no manifest", map[string]string{
			"Cargo.toml":     "[profile.release]\nopt-level = 3\n",
			"app/Cargo.toml": lockless7,
		}, []string{
			"serde@1.0.100 app/Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde app/Cargo.toml",
		}},
		// A package.workspace root that cannot be read governs nothing, so the member counts as its own root.
		{"patch under a pointed root that cannot be read", map[string]string{
			"Cargo.toml": strings.Replace(lockless7, "version = \"0.1.0\"\n", "version = \"0.1.0\"\nworkspace = \"../ws\"\n", 1),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
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
		// A lock the decoder cannot read in bounded memory records nothing, so the manifest's target goes out.
		{"lock refused for a long dotted key", map[string]string{
			"Cargo.toml": lockless7,
			"Cargo.lock": "version = 4\n" + strings.Repeat("a.", 2100) + "a = 1\n\n" + gitSerde("#"+patchRev),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		// A build without --locked rewrites a lock that predates the patch and fetches the fork, so the manifest's target still goes out.
		{"lock that predates the patch", map[string]string{
			"Cargo.toml": lockless7,
			"Cargo.lock": appLock(registrySerde),
		}, []string{
			"serde@1.0.100 Cargo.lock,Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		// An unused patch is not a package the lock sends, so it does not hide the manifest's target.
		{"lock recording the patch as unused", map[string]string{
			"Cargo.toml": lockless7,
			"Cargo.lock": appLock(registrySerde, unusedSerde),
		}, []string{
			"serde@1.0.100 Cargo.lock,Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		// cargo 1.99 builds the fork once a changed requirement activates the unused patch, so its target goes out.
		{"requirement activating an unused patch", map[string]string{
			"Cargo.toml": strings.Replace(lockless7, `"=1.0.100"`, `"=1.0.200"`, 1),
			"Cargo.lock": appLock(registrySerde, unusedSerde),
		}, []string{
			"serde@1.0.100 Cargo.lock",
			"serde@1.0.200 Cargo.toml",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		{"lock recording a branch patch", map[string]string{
			"Cargo.toml": patchedSerde(`, branch = "main"`),
			"Cargo.lock": appLock(gitSerde("?branch=main#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
		}},
		// Cargo fetches the branch afresh for a patch version the locked release does not meet, so the manifest's target goes out.
		{"lock below the patch's version", map[string]string{
			"Cargo.toml": strings.Replace(patchedSerde(`, branch = "main", version = "=1.0.200"`), `"=1.0.100"`, `"=1.0.200"`, 1),
			"Cargo.lock": appLock(gitSerde("?branch=main#" + patchRev)),
		}, []string{
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@1.0.200 Cargo.toml",
			"serde@1.0.200?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		{"lock meeting the patch's version", map[string]string{
			"Cargo.toml": patchedSerde(`, branch = "main", version = "1.0"`),
			"Cargo.lock": appLock(gitSerde("?branch=main#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
		}},
		// cargo 1.99 fetches afresh when the [replace] spec names another version than the locked replacement.
		{"lock below the replaced version", map[string]string{
			"Cargo.toml": replacedItoa("1.0.11"),
			"Cargo.lock": itoaReplaceLock,
		}, []string{
			"itoa@1.0.10 Cargo.lock",
			"itoa@1.0.10?vcs_url=git+https://git.example.com/acme/itoa@" + patchRev + " Cargo.lock",
			"itoa@1.0.11 Cargo.toml",
			"itoa@1.0.11?vcs_url=git+https://git.example.com/acme/itoa Cargo.toml",
		}},
		// cargo 1.99 reads a [replace] version padded with a space, which we cannot, so the lock does not hide it.
		{"replaced version padded with a space", map[string]string{
			"Cargo.toml": strings.Replace(replacedItoa("1.0.11"), `"itoa:1.0.11"`, `"itoa: 1.0.11"`, 1),
			"Cargo.lock": itoaReplaceLock,
		}, []string{
			"itoa@1.0.10 Cargo.lock",
			"itoa@1.0.10?vcs_url=git+https://git.example.com/acme/itoa@" + patchRev + " Cargo.lock",
			"itoa@1.0.11 Cargo.toml",
			"itoa@?vcs_url=git+https://git.example.com/acme/itoa Cargo.toml",
		}},
		{"lock holding the replaced version", map[string]string{
			"Cargo.toml": replacedItoa("1.0.10"),
			"Cargo.lock": itoaReplaceLock,
		}, []string{
			"itoa@1.0.10 Cargo.lock,Cargo.toml",
			"itoa@1.0.10?vcs_url=git+https://git.example.com/acme/itoa@" + patchRev + " Cargo.lock",
		}},
		{"lock at another commit than rev", map[string]string{
			"Cargo.toml": patchedSerde(`, rev = "` + patchRev + `"`),
			"Cargo.lock": appLock(gitSerde("?rev=" + otherRev + "#" + otherRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + otherRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.toml",
		}},
		// Cargo matches a lock entry only on the same branch, tag or rev as written, so a changed one is fetched afresh.
		{"lock recording another branch", map[string]string{
			"Cargo.toml": patchedSerde(`, branch = "main"`),
			"Cargo.lock": appLock(gitSerde("?branch=develop#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		{"lock recording the default branch", map[string]string{
			"Cargo.toml": patchedSerde(`, branch = "main"`),
			"Cargo.lock": appLock(gitSerde("#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		{"lock recording another tag", map[string]string{
			"Cargo.toml": patchedSerde(`, tag = "v2"`),
			"Cargo.lock": appLock(gitSerde("?tag=v1#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		{"lock recording another rev", map[string]string{
			"Cargo.toml": patchedSerde(`, rev = "89abcde"`),
			"Cargo.lock": appLock(gitSerde("?rev=0123456#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		// cargo 1.99 rewrites the lock for a longer prefix of the same commit, so it is not the locked rev.
		{"lock recording a shorter prefix of the rev", map[string]string{
			"Cargo.toml": patchedSerde(`, rev = "0123456789ab"`),
			"Cargo.lock": appLock(gitSerde("?rev=0123456#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		{"lock recording a tag patch", map[string]string{
			"Cargo.toml": patchedSerde(`, tag = "v1"`),
			"Cargo.lock": appLock(gitSerde("?tag=v1#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
		}},
		{"lock recording a short rev patch", map[string]string{
			"Cargo.toml": patchedSerde(`, rev = "0123456"`),
			"Cargo.lock": appLock(gitSerde("?rev=0123456#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
		}},
		// Version 4 form-encodes the branch and version 3 writes it as is, and Cargo decodes both.
		{"version 4 lock encoding the branch", map[string]string{
			"Cargo.toml": patchedSerde(`, branch = "feat/a+b"`),
			"Cargo.lock": appLock(gitSerde("?branch=feat%2Fa%2Bb#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
		}},
		{"version 3 lock writing the branch as is", map[string]string{
			"Cargo.toml": patchedSerde(`, branch = "feat/a+b"`),
			"Cargo.lock": strings.Replace(appLock(gitSerde("?branch=feat/a+b#"+patchRev)), "version = 4", "version = 3", 1),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
		}},
		// cargo 1.99 takes a lock as current for a git URL with a query even after its branch changed, so no lock records it.
		{"lock recording a git url with a query", map[string]string{
			"Cargo.toml": strings.Replace(patchedSerde(`, branch = "main"`), "evil/serde\"", "evil/serde?x=1\"", 1),
			"Cargo.lock": appLock(gitSerde("?x=1?branch=main#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
		}},
		// A version 4 lock's '+' is a space, so it records another branch.
		{"version 4 lock with a raw plus", map[string]string{
			"Cargo.toml": patchedSerde(`, branch = "a+b"`),
			"Cargo.lock": appLock(gitSerde("?branch=a+b#" + patchRev)),
		}, []string{
			"serde@1.0.100 Cargo.toml",
			"serde@1.0.100?vcs_url=git+https://github.com/evil/serde@" + patchRev + " Cargo.lock",
			"serde@?vcs_url=git+https://github.com/evil/serde Cargo.toml",
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
		// Cargo opens .cargo/config.toml as Config.toml on a case-insensitive filesystem.
		{name: "config named in another case", files: map[string]string{"Cargo.toml": project, "tools/.cargo/Config.toml": mirrorConfig}, want: 1},
		{name: "config in a .cargo named in another case", files: map[string]string{"Cargo.toml": project, "tools/.Cargo/config.toml": mirrorConfig}, want: 1},
		// Cargo reads a config through a linked .cargo directory, whose real path is not a .cargo.
		{name: "config in a linked .cargo", tree: func(t *testing.T) string {
			if runtime.GOOS == "windows" {
				t.Skip("symlinks need privileges on Windows")
			}
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"Cargo.toml": project, "cargo-config/config.toml": mirrorConfig})
			if err := os.Symlink(filepath.Join(dir, "cargo-config"), filepath.Join(dir, ".cargo")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			return dir
		}, want: 1},
		{name: "above the scan root", files: map[string]string{"proj/Cargo.toml": project, ".cargo/config.toml": mirrorConfig}, scan: "proj", want: 1},
		{name: "CARGO_HOME", files: map[string]string{"Cargo.toml": project}, home: mirrorConfig, want: 1},
		{name: "two configs", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": mirrorConfig, "tools/.cargo/config.toml": vendorConfig("vendor")}, want: 1},
		{name: "beside an unreadable config", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": mirrorConfig, "docs/.cargo/config.toml": "[source.crates-io\n"}, want: 1},
		{name: "above a manifest that cannot be parsed", files: map[string]string{"Cargo.toml": "this is [not toml", "proj/Cargo.toml": project}, scan: "proj", home: mirrorConfig, want: 1},
		{name: "beside a manifest that cannot be parsed", files: map[string]string{"Cargo.toml": "this is [not toml", ".cargo/config.toml": mirrorConfig, "proj/Cargo.toml": project}, scan: "proj", want: 1},
		{name: "proven vendor tree", tree: cargoVendorFixture, want: 0},
		{name: "mirror beside a vendor tree", tree: cargoVendorFixture, files: map[string]string{"tools/.cargo/config.toml": mirrorConfig}, want: 1},
		// The root's replace-with still holds in tools, where the vendored source now names an unproven directory.
		{name: "vendored source redirected below the root", tree: cargoVendorFixture, files: map[string]string{"tools/.cargo/config.toml": "[source.vendored-sources]\ndirectory = \"../mirror-vendor\"\n"}, want: 1},
		// Every cargo run in the project takes the project's proven vendor tree, so CARGO_HOME's mirror is never in effect.
		{name: "CARGO_HOME mirror under a proven vendor tree", tree: cargoVendorFixture, home: mirrorConfig, want: 0},
		// A scan root holding no Cargo.toml or config is not judged, so CARGO_HOME's mirror is judged only where the subdirectory's vendor tree overrides it.
		{name: "CARGO_HOME mirror over a subdirectory's proven vendor tree", tree: func(t *testing.T) string {
			mono := t.TempDir()
			if err := os.Rename(cargoVendorFixture(t), filepath.Join(mono, "rust")); err != nil {
				t.Fatal(err)
			}
			return mono
		}, files: map[string]string{"web/package.json": `{"name":"web","dependencies":{"left-pad":"^1.3.0"}}`}, home: mirrorConfig, want: 0},
		{name: "CARGO_HOME mirror over a subdirectory", files: map[string]string{"rust/Cargo.toml": project, "web/package.json": `{"name":"web"}`}, home: mirrorConfig, want: 1},
		{name: "mirror at a root holding no manifest", files: map[string]string{"rust/Cargo.toml": project, ".cargo/config.toml": mirrorConfig}, want: 1},
		{name: "not replaced", files: map[string]string{"Cargo.toml": project, ".cargo/config.toml": "[net]\ngit-fetch-with-cli = true\n"}, want: 0},
		{name: "no crates", files: map[string]string{"package.json": `{"name":"web","dependencies":{"left-pad":"^1.3.0"}}`, ".cargo/config.toml": mirrorConfig}, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A user's CARGO_HOME, whose parent is not above the scan.
			home := filepath.Join(t.TempDir(), "user", ".cargo")
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

// globLog records the globs a resolver is asked for.
type globLog struct {
	file.Resolver
	globs []string
}

func (g *globLog) FilesByGlob(patterns ...string) ([]file.Location, error) {
	g.globs = append(g.globs, patterns...)
	return g.Resolver.FilesByGlob(patterns...)
}

// The replacement check runs on every scan with a crate, so it may only ask for names syft looks up in its index, never a glob that walks every file (OSS-2099).
func TestCargoSourceReplacedLooksUpConfigsByName(t *testing.T) {
	t.Setenv("CARGO_HOME", filepath.Join(t.TempDir(), "user", ".cargo"))
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"Cargo.toml": "[package]\nname = \"app\"\n", "tools/.cargo/config.toml": mirrorConfig, "web/.cache/index.js": ""})
	src, err := newDirectorySource(dir)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	t.Cleanup(func() { src.Close() })
	r, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	log := &globLog{Resolver: r}
	if !cargoSourceReplaced(log, dir) {
		t.Fatal("mirror in tools/.cargo not reported")
	}
	for _, g := range log.globs {
		// A literal name, or every file in a literally named directory, is answered from syft's index.
		dir, base := path.Split(g)
		if strings.ContainsAny(base, "*?[]{}") && (base != "*" || strings.ContainsAny(path.Base(dir), "*?[]{}")) {
			t.Errorf("asked for %q, which syft answers by walking every file", g)
		}
	}
}

// Only a scan reports a replacement, once and without a count, and the pre-commit hook's temp trees never do (OSS-2099).
func TestCatalogReportsCargoReplacementOnlyForAScan(t *testing.T) {
	t.Setenv("OSSPREY_RESOLVE_LATEST", "")
	withResolveLatest(t, func(context.Context, string, string) (string, error) { return "9.9.9", nil })
	home := filepath.Join(t.TempDir(), "user", ".cargo")
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

// Windows resolves a CARGO_HOME rooted without a drive, or relative to another drive, on that drive, as cargo's join leaves it (OSS-2553).
func TestCargoHomeKeepsAWindowsRootedHomeOnItsDrive(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only Windows has rooted and drive-relative paths")
	}
	for _, home := range []string{`\cargo`, `D:cargo`} {
		t.Setenv("CARGO_HOME", home)
		want, err := filepath.Abs(home)
		if err != nil {
			t.Fatal(err)
		}
		if got := CargoHome(`C:\elsewhere`); got != want {
			t.Errorf("CARGO_HOME=%s: %s, want %s", home, got, want)
		}
	}
}

// IsCratesIoIndex reads an --index URL as cargo 1.99.1 does: sparse+ in any case after trimming, and a backslash as a separator only in a special scheme such as https (OSS-2553).
func TestIsCratesIoIndexReadsTheURLAsCargoDoes(t *testing.T) {
	for _, tc := range []struct {
		index string
		want  bool
	}{
		{"sparse+https://index.crates.io/", true},
		{"https://github.com/rust-lang/crates.io-index", true},
		// cargo downloads crates.io's itoa from each of these.
		{`https://github.com\rust-lang\crates.io-index`, true},
		{`https://github.com\@mirror.example/../rust-lang/crates.io-index`, true},
		{"SPARSE+https://index.crates.io/", true},
		{" sparse+https://index.crates.io/", true},
		{"Sparse+HTTPS://index.crates.io/", true},
		{"spa\trse+https://index.crates.io/", true},
		// cargo fetches these from mirror.example, the backslash being userinfo.
		{`sparse+https://index.crates.io\@mirror.example/../`, false},
		{`ssh://git@github.com\@mirror.example/../rust-lang/crates.io-index`, false},
		// cargo reads this as another registry, which finds no crates.io crate.
		{`sparse+https://index.crates.io/\/`, false},
		{"sparse+https://crates.corp.example/", false},
	} {
		if got := IsCratesIoIndex(tc.index); got != tc.want {
			t.Errorf("IsCratesIoIndex(%q) = %v, want %v", tc.index, got, tc.want)
		}
	}
}
