# Cargo cataloguing

Source marks, range folding, `[patch]` targets, the `cargo vendor` filter and source replacement. The `CargoTomlCataloger` itself is described in [catalog.md](catalog.md). [Back to the internals index](README.md).

A `Cargo.lock` crate from git or a non-crates.io registry is **sent, marked** (`cargoSourceMarks`, OSS-2484) as `vcs_url=git+<url>@<commit>` or `repository_url=<origin>/`, never with userinfo, query, fragment or a registry path, any of which can hold a token; a source Go cannot parse or the API cannot fit falls back to its origin, then its scheme, so a crate Cargo builds is never dropped or sent bare. `isCratesIo` folds at least what Cargo's WHATWG parser and `CanonicalUrl` fold (padding, case, a default port, `./`, escapes, backslashes, `http://`, a trailing `/` or `.git`, each checked for `registry+` with a real `cargo metadata --locked`); `sparse+` spellings fold further than Cargo, which reads them as another source, but one on crates.io's own host. A non-ASCII path stays foreign, tested before `ToLower`, which maps `İ` to `i`; a non-ASCII `registry+` host goes out marked **and** bare, because Cargo's IDNA step maps `ｇithub.com` or a soft hyphen to github.com but `gİthub.com` elsewhere. A marked crate is its own component: never version-resolved, never folded, never absorbing a sighting. The pre-commit hook keys its diff on the mark too, so a crate moved from git to crates.io at the same version reads as new, and it never sends a marked crate, whose bare purl `/malware/check` would match against the crates.io advisory of that name; `-v` counts the ones it leaves out. The hook also writes each unstaged ancestor `Cargo.toml` that declares `[workspace]` into both temp trees (`cargoAncestors`), because a member's `dep = { workspace = true }` takes its pin from that root, and without it every commit touching only a member warned that the root could not be read and dropped the member's inherited crates. In those trees the cataloguer picks a member's root as `workspacePool` does everywhere ([catalog.md](catalog.md)): the root the member's `package.workspace` names, else the first ancestor `[workspace]` that does not exclude the member. The trees differ from a checkout, though. Only an ancestor that declares `[workspace]` is written, so a non-root ancestor whose own `package.workspace` names a root, which cargo follows, is climbed past; when a `[workspace]` further up then takes the member, a pin there under the same alias is looked up in place of cargo's, a range there is skipped like any range, and an alias it does not declare drops with the warning. A pointed root outside the member's parent directories is not written at all; writing it needs a pointer read through symlinks and case as cargo opens it, and a crafted one must not cost the rest of the commit its check. Index paths are named `:0:<path>` (`indexSpec`), since git reads `:0:../x` as stage 0 of a path outside the repo and fails the whole call, and a root whose path holds a newline is resolved by a git of its own before sizing, since `cat-file` reads one name per line. A staged root is diffed on its own pool instead (`workspacePinChanges`): `catalog.CargoWorkspacePins` reads `[workspace.dependencies]` from the index and from HEAD as an inheriting member reads each entry, so path, git and private-registry entries and ranges add nothing, and each exact crates.io pin HEAD lacked goes out attributed to the root. A virtual root emits nothing itself and the members the commit leaves alone are not in the trees, so without it a pin bumped only in the pool reached no lookup. Both reads stop at `CargoManifestLimit`, as the vendor proofs' reads do. An ancestor root is sized with one `git cat-file --batch-check` and read through `blobReader`, and a root git cannot size fails the hook as a staged read does, since dropping its members' inherited pins would go unseen; the pool diff stats a root's tree copies before reading them, so a root over the bound is skipped as an unreadable one is. Writing the members into the trees was tried and dropped: listing them from `workspace.members` missed those Cargo adds on its own (path dependencies under the root, a root whose `[workspace]` is empty), wrote a symlinked member as its link text, and capped the index and HEAD lists apart, so an unchanged crate could read as new. Two accepted over-reports: a pool pin new at the root's path is looked up even when no member inherits it (a changed pin, or every pin of a root that is added, moved or in the first commit), and a crate `[patch.crates-io]` redirects to git also goes out as its `Cargo.toml` declaration, so one unused crates.io crate gets checked; folding it meant guessing which lock owns a manifest, and each guess let a forged or nearby lock hide a declared crates.io dependency.

A versionless crate folds per manifest, and only into a release the `Cargo.lock` at that manifest's workspace root locks (`workspacePool` returns the root, which travels with the manifest's requirements as the range's `cargoRange` metadata to `foldCargoRanges`) and that meets a requirement the manifest declares for it (`registry.CargoSatisfies`, which reads core numbers as the u64 Cargo does and refuses a version Cargo's parser rejects; a requirement it cannot read, such as one past u64, is not met). Folding on the name alone let one member's `=` pin swallow another member's range, a dev-dependency's pin replace the runtime range, and a decoy lock anywhere in the tree set a lockless crate's version, so none of those ranges reached the registry (OSS-2099). Any lock above the manifest is not enough either: a scan-root `Cargo.lock` says nothing about a nested crate with no `[workspace]` over it, and a stale or forged root lock holding only a release outside the range says nothing about what the range builds. The cost is an over-report: any range that no governing `Cargo.lock` locks goes out at its latest release, including one Cargo would unify with an `=` pin elsewhere in the workspace or in the same manifest, and a path dependency outside any workspace whose parent's lock covers it.

**A git `[patch]` or `[replace]` target the root's `Cargo.lock` does not record is read from the manifest** (`cargoGitTargets`, OSS-2099). Cargo honours both tables only in the workspace root, so a member's are skipped (a manifest whose `workspacePool` root is not its own directory; one whose root cannot be found counts as a root, so its targets go out), and a target the lock beside the root records as a package, from the same repository with the same `branch`, `tag` or `rev`, at the manifest's full `rev` when it names one and at a version the target's own requirement accepts (a `[patch]` entry's `version`, or the full version a `[replace]` spec must name, which matches nothing when we cannot read it) (`lockRecords`), adds nothing, since syft reads the same git source from the lock. Cargo matches the selector exactly as written once both sides are read back (`cargoGitRef`: the query form-decoded, the last key winning, `ref` meaning `branch`), so the manifest's selector is spelled as cargo would write it for the lock's version (form-encoded from version 4, as written before) and read back the same way; cargo 1.99 rewrites the lock when the branch, tag or rev changes, from the default branch too, and even to a longer prefix of the locked commit (verified), so each of those targets goes out. It fetches the branch afresh too when that requirement no longer accepts the locked version, and builds the new commit (verified), while a dependency requirement moved past the locked fork leaves the patch unused and builds the crates.io release (verified), which the manifest's own declaration sends. A git URL with a query, two selectors or one that is not a string is never recorded, since cargo 1.99 takes a stale lock as current for a queried URL while it builds the new branch (verified). The lock is read only as a regular file within the caps `withBoundedLocks` applies (`maxLockBytes`, `maxLockDepth`, via `readRegularFile`) and decoded through `decodeTOML`, so a FIFO or a link to a device named `Cargo.lock` can neither block the scan nor read without end, and a lock the scan hides or this read refuses records nothing. The mere presence of a lock used to hide it, but a lock can predate the patch: cargo 1.99 without `--locked` rewrites such a lock and builds a fork published at the locked version, and records one at another version as unused until `cargo update` (verified), so the target goes out in both cases. An unused patch records nothing, since the lockfile cataloguer sends nothing for it and cargo 1.99 builds the fork at the commit `[[patch.unused]]` holds once a changed requirement reaches its version (verified). The accepted over-report: a member directory scanned on its own has no root above it inside the scan, so it counts as its own root and its git targets are sent, although cargo run from the full checkout ignores them. Each target is carried as a `pkg.RustCargoLockEntry` whose source is spelled as the lock would spell it without the query, `git+<url>` plus `#<rev>` only for a full 40 or 64 hex commit (a short rev is not what a lock records), so `cargoSourceMarks` strips credentials and falls back exactly as it does for a lock. `catalogByGlob` keys its dedup on that source too, or a versionless git target and its versionless crates.io twin collapse into one. A `path` target is the project's own code and is not sent; the crates.io twin stays, as above. Two more behaviours are kept by decision: an exact `Cargo.toml` pin that disagrees with `Cargo.lock` goes out at both versions, since cargo rebuilds to the pin unless run `--locked`, which fails instead, so neither file alone says what builds; and an exact pin keeps its build metadata as written (`=1.0.0+abc`), since the service fetches the `.crate` by that exact string and a crate published with metadata carries it in its file name.

**`cargo vendor` crates are hidden by marker, not by name** (`withoutCargoVendor`,
OSS-2561). Every crate it writes holds a `.cargo-checksum.json`, and the vendor
directory's name is configurable, so a `vendor` sink would miss
`third_party/rust` and drop a path dependency kept under `vendor/`. A published
crate ships its own `Cargo.lock` (anyhow 1.0.100's names 59 crates, its dev
tree), which syft's `**/Cargo.lock` glob read as the project's. An exclusion glob
cannot say "a directory holding this file", so the filter wraps the resolver
every cataloger reads instead of the index. A crate at the scan root is exempt,
since that scan asked for it.

**The marker is repository content, so it proves nothing alone.** Review broke
two earlier rules. Hiding every file under a marked directory let a marker
beside a `package-lock.json` hide it, and accepting any lockfile as proof let a
decoy `Cargo.lock` naming a standalone project hide that project's own lock. So
the proof is now what cargo itself would do. The vendoring project is a strict
ancestor whose `Cargo.lock` (beside its `Cargo.toml`) locks the crate's
name@version from a registry with the marker's checksum, has no path entry of
that name@version, and holds a release meeting every normal and build
dependency the crate's manifest turns on, non-optional or enabled by its default
features (so an edited vendored manifest stays visible). The nearest cargo
config for that project replaces `crates-io` with a `directory` source equal to
the crate's parent, and that source is not replaced again. cargo reads config
from where it runs, and an alias or `--manifest-path` reaches any crate from any
directory, so every committed config level in the scan must also resolve
`crates-io` to some directory source.
Under that replacement cargo can take a crates.io dependency only from the
vendor tree, so a hidden manifest cannot pull one from the network. A crate any
manifest or config builds by path is never hidden (`path`, `workspace`,
`members` and `paths` keys, read from every file in the scan, every ancestor of
the scan root and `CARGO_HOME`), nor is one whose manifest has `[workspace]`,
which `cargo publish` strips. References are resolved from both the path a file
was reached by and its real path, through symlinks, with case and Unicode
folded, both backslash readings, and a suffix match for one that leaves the
root; member globs are expanded on disk against a literal base, and a config
counts at the directory cargo reads it from, symlink or not. An alias's `--manifest-path`
counts as a reference. Anything it cannot place (a member glob with `[` or `**`
or outside the root, a `path-bases` `base`, a config `include`, an alias running
`cargo vendor`, which ignores source replacement, or passing `--config`, two
configs or one named in
another case at a level, a file reached through a symlink out of the root, an
unreadable, over-limit or too deeply nested manifest or config) turns the filter
off, a refused `Cargo.lock` only proves nothing, and a hidden file reached
through a symlink stays visible. Out of reach: `--config`, `CARGO_*` environment
overrides and CI steps, which no manifest scan sees, and configs and `path`
dependencies inside package sinks, which the index never holds and which only a
command run from inside a build or install directory would use.
`TestCatalogDoesNotLetACargoMarkerHideOtherFiles`,
`TestCatalogReadsAProjectCrateThatLooksVendored`,
`TestCatalogReadsACrateAProjectAboveTheScanBuilds`,
`TestCatalogHidesNothingWhenAPathCannotBePlaced` and
`TestCatalogRefusesCargoFilesNestedTooDeepForTheFilter` pin one case per guard;
each of the 38 fails with its guard removed.

The pre-commit hook's temp trees hold no marker, so the filter never runs
there; `withoutVendoredLocks` instead drops a staged `Cargo.lock` beside a
marker only when a strict ancestor's staged `Cargo.lock`, beside its own
`Cargo.toml` in a directory with no marker as in `projectLocks`, pins that
crate's name@version at the marker's checksum (`CargoLock.Vendors`, the
filter's own lock check) and the staged `.cargo/config` or `.cargo/config.toml`
at or above that ancestor replaces crates.io with a `directory` source that is
the crate's parent (`CargoVendorSource`: nearest config wins per key, a path is
relative to the directory holding `.cargo`, and no config, an unclear one or a
mismatch skips nothing). `CargoVendorSource` places no directory with `..`
after a named directory, because cargo resolves `..` after following symlinks
and a lexical join can name another directory. A crate whose `Cargo.toml`
declares `[workspace]` is never a vendored copy, as in the filter, since
`cargo publish` strips the table and that crate's own lock is what pins its
range dependencies. Every proof file comes from one
`git ls-files -s` listing and is read by its blob only when its entry is a
regular file: a symlink's blob is its target text, which cargo never reads as
the file. One `git cat-file --batch-check` then sizes every listed blob, and a
blob over the bound its parser enforces (`CargoProofLimit` for a lock or
marker, `CargoManifestLimit` for a manifest or config) proves nothing and is
never read, since the parsers refused it only after the hook had buffered all
of it. Every blob, the staged manifests included, is read through one
`git cat-file --batch` (`blobReader`), since a git per file took 1.1s and
1,509 processes for a commit adding 500 vendored crates on Linux, where
processes start fastest; a blob the batch finds over its limit ends that
process, and a name holding a newline gets a git of its own (`readBlob`,
which also stops git at the bound). That leaves a vendored crate's own lock out of the lookup,
never skips a `Cargo.toml`, and still checks in full a `vendor/` change staged
without its `Cargo.lock`. `ParseCargoLock`, `ParseCargoConfig` and
`CargoPackageID` run `proofTOMLError` before decoding. It refuses a file nested
more than `maxProofNesting` deep outside its strings and comments, with each dot
of a key counted as a level, since the TOML decoder recurses once per level (a
few million overflow the stack) and its memory grows with the square of one
key's parts. It also refuses a line over `maxProofLine` bytes, and six quotes
in a row, where the decoder can close a multi-line string later than the
nesting scan does. Real files reach 7 levels (hyper's
`[[package.metadata.capi.install.include.asset]]`), so the bound is 16.

**Source replacement is warned about, not marked** (`cargoSourceReplaced`,
OSS-2099). A `[source.crates-io] replace-with` in a cargo config leaves
crates.io in `Cargo.lock` while cargo builds whatever the replacement serves (a
mirror, a git repository, a directory), so the scan checks crates.io releases
that may not be the code built. Nothing in the scan records what the replacement
served, so there is nothing to mark, and dropping the crates would only check
less; one warning a scan says so, which is the decision for now. Only `scan.Run`
asks for it (`Options.ReportCargoReplacement`): the pre-commit hook catalogues
temp trees that hold no repository config, so all it could report is the
developer's own `CARGO_HOME` mirror, on every commit, against a hook whose clean
output is nothing. The entry has no `Many`, which `warn.Drain` renders as `One`
however often it is added, so a caller cataloguing twice still prints one
accurate line. It finds
configs in the scan through syft's index of names (`cargoConfigGlobs`:
`**/config`, `**/config.toml`, and `**/.cargo/*` for a config named in another
case, which cargo opens on a case-insensitive filesystem; `isCargoConfig` folds
the directory's case too, so only a config whose `.cargo` directory and file name
are both in another case, such as `.Cargo/Config.toml`, is missed in the scan,
while above it both are read in any case), not with the vendor filter's `**/.*/*`,
which walks every file and added about 40% to a large scan's catalogue time
when it ran for every crate. It files them with the vendor filter's own
`cargoConfigLevels`, and reads `cargoFilesAbove` without manifests and
through symlinks, as the vendor filter does (every ancestor and `CARGO_HOME`); when the filter proved a tree it reuses the levels the proof read (`cargoVendored.levels`), which cover the same configs, all readable. Otherwise configs in the scan are read one at a time, so one
that cannot be parsed does not hide another's replacement. Above the scan only
configs are read, so an ancestor `Cargo.toml` that cannot be parsed hides
nothing, while a config there that cannot be parsed hides the others, as cargo
stops on it too; the vendor filter still reads the manifests and proves
nothing when one fails. It judges the replacement in effect where cargo
would run, at each directory in the scan holding a `Cargo.toml` or a config, so
at the scan root only when it holds one of them
(`cratesIoReplacement`: the nearest level that sets `replace-with`, as
`vendorDir` walks, then `CARGO_HOME`'s, which cargo reads last), and stays
quiet only where that is a vendor directory the filter proved
(`cargoVendored.vendors`), whose crates the lock pins to crates.io checksums,
though the files cargo checks against `.cargo-checksum.json` are not compared
with the release. Judging each config at its own directory missed a nested
config that redirects the vendored source without restating `replace-with`,
and warned about a `CARGO_HOME` mirror that the project's own vendor config
overrides everywhere in the project; judging a scan root holding neither file
warned about that mirror in a monorepo whose Rust project, in a subdirectory,
builds from a proven vendor tree. It runs only when a
crate goes out unmarked, so a scan with no Rust never mentions cargo.
